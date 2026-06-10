"""
core/attack_graph.py
─────────────────────
The engagement as a property graph (workstream 2A).

Every host, service, vulnerability, credential and foothold the agents discover
is mirrored — through a KnowledgeBase sink — into a graph, so the planner can ask
*path* questions ("is there a credential path from my foothold to a domain
admin?") instead of re-reading a flat JSON blob.

Backends (graceful degradation, MCPBridge-style):
  • networkx  — the in-process computation engine, and what the tests run against.
  • neo4j     — OPTIONAL write mirror. If `settings.neo4j_uri` is set and the
                driver connects, every write is ALSO MERGE'd into Neo4j so the
                operator gets a live BloodHound-style browser. Reads always come
                from the in-process networkx graph. If neo4j is missing or
                unreachable we log once and carry on with networkx only.
  • disabled  — if networkx itself is not installed the graph disables itself:
                writes are no-ops, reads return empty. The engagement is
                unaffected (same philosophy as the MCP layer).

Node id scheme (stable, so writes are idempotent / MERGE-like):
    host:<ip>   svc:<ip>:<port>   vuln:<ip>:<cve>
    cred:<user>@<source_ip>   session:<ip>   domain:<name>   goal:<name>
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

from config.settings import settings

log = logging.getLogger(__name__)

try:
    import networkx as nx
    _NX = nx
except ImportError:  # graceful degradation — no networkx, graph disables itself
    _NX = None


def _networkx_available() -> bool:
    return _NX is not None


# ── Optional Neo4j mirror ──────────────────────────────────────────────────────

class _Neo4jMirror:
    """Best-effort write mirror into Neo4j. Every failure is swallowed + logged —
    the mirror must NEVER break the engagement."""

    def __init__(self, driver) -> None:
        self._driver = driver

    def run(self, cypher: str, **params) -> None:
        try:
            with self._driver.session() as session:
                session.run(cypher, **params)
        except Exception as e:  # noqa: BLE001 — best effort
            log.warning("[GRAPH] neo4j write failed: %s", e)

    def close(self) -> None:
        try:
            self._driver.close()
        except Exception:  # noqa: BLE001
            pass


def _try_neo4j(uri: str, user: str, password: str) -> Optional[_Neo4jMirror]:
    try:
        from neo4j import GraphDatabase
    except ImportError:
        log.warning("[GRAPH] neo4j_uri set but the `neo4j` driver isn't installed "
                    "(pip install neo4j) — using in-process graph only")
        return None
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password) if user else None)
        driver.verify_connectivity()
        return _Neo4jMirror(driver)
    except Exception as e:  # noqa: BLE001 — unreachable server, bad creds, etc.
        log.warning("[GRAPH] neo4j unreachable at %s (%s) — using in-process graph only",
                    uri, e)
        return None


# ── Attack graph ───────────────────────────────────────────────────────────────

class AttackGraph:
    """A property graph of the engagement, fed by the KnowledgeBase sink."""

    def __init__(self, backend: str = "auto") -> None:
        self._lock = threading.RLock()
        self._mirror: Optional[_Neo4jMirror] = None

        if _NX is None:
            self._disabled = True
            self._g = None
            self.backend = "disabled"
            log.warning("[GRAPH] networkx not installed — attack graph disabled "
                        "(writes no-op, reads empty). pip install networkx")
            return

        self._disabled = False
        self._g = _NX.DiGraph()
        self.backend = "networkx"

        if backend in ("auto", "neo4j") and settings.neo4j_uri:
            self._mirror = _try_neo4j(
                settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password
            )
            if self._mirror:
                log.info("[GRAPH] neo4j mirror connected at %s", settings.neo4j_uri)

    # ── internal graph + mirror helpers ────────────────────────────────────────

    def _merge_node(self, node: str, *, _label: str = "Node", **attrs) -> None:
        """Idempotent node upsert; mirrors to neo4j when configured."""
        clean = {k: v for k, v in attrs.items() if v is not None}
        if node in self._g:
            self._g.nodes[node].update(clean)
        else:
            self._g.add_node(node, **clean)
        self._mirror_node(_label, node, clean)

    def _add_edge(self, src: str, dst: str, rel: str, **attrs) -> None:
        self._g.add_edge(src, dst, rel=rel, **{k: v for k, v in attrs.items() if v is not None})
        self._mirror_rel(src, dst, rel)

    def _mirror_node(self, label: str, node_id: str, props: dict) -> None:
        if self._mirror is None:
            return
        # Neo4j properties must be primitives — drop nested structures.
        primitive = {k: v for k, v in props.items()
                     if isinstance(v, (str, int, float, bool))}
        sets = "".join(f", n.{k} = ${k}" for k in primitive)
        cypher = f"MERGE (n:{label} {{id: $__id}}) SET n.id = $__id{sets}"
        self._mirror.run(cypher, __id=node_id, **primitive)

    def _mirror_rel(self, src_id: str, dst_id: str, rel: str) -> None:
        if self._mirror is None:
            return
        cypher = ("MERGE (a {id: $src}) MERGE (b {id: $dst}) "
                  f"MERGE (a)-[:{rel}]->(b)")
        self._mirror.run(cypher, src=src_id, dst=dst_id)

    def _neighbors_of_kind(self, node: str, kind: str) -> list[str]:
        if node not in self._g:
            return []
        ug = self._g.to_undirected(as_view=True)
        return [m for m in ug.neighbors(node) if self._g.nodes[m].get("kind") == kind]

    def _host_has_session(self, ip: str) -> bool:
        return f"session:{ip}" in self._g

    # ── write side (called by the KB sink) ─────────────────────────────────────

    def upsert_host(self, ip: str, **props) -> None:
        if self._disabled or not ip:
            return
        with self._lock:
            self._merge_node(f"host:{ip}", _label="Host", kind="host", ip=ip, **props)

    def upsert_service(self, ip: str, port, **props) -> None:
        if self._disabled or not ip:
            return
        with self._lock:
            self._merge_node(f"host:{ip}", _label="Host", kind="host", ip=ip)
            svc = f"svc:{ip}:{port}"
            self._merge_node(svc, _label="Service", kind="service", ip=ip, port=port, **props)
            self._add_edge(f"host:{ip}", svc, "RUNS")

    def add_vuln(self, ip: str, cve: str, cvss=None, port=None, **props) -> None:
        if self._disabled or not ip:
            return
        with self._lock:
            self._merge_node(f"host:{ip}", _label="Host", kind="host", ip=ip)
            vnode = f"vuln:{ip}:{cve}"
            self._merge_node(vnode, _label="Vulnerability", kind="vuln",
                             ip=ip, cve=cve, cvss=cvss, **props)
            if port is not None:
                svc = f"svc:{ip}:{port}"
                self._merge_node(svc, _label="Service", kind="service", ip=ip, port=port)
                self._add_edge(svc, vnode, "HAS_VULN")
            else:
                self._add_edge(f"host:{ip}", vnode, "HAS_VULN")

    def add_credential(self, cred: dict, source_ip: str) -> None:
        if self._disabled:
            return
        cred = cred or {}
        username = cred.get("username") or cred.get("user") or "unknown"
        is_domain_admin = bool(cred.get("domain_admin") or cred.get("admin"))
        with self._lock:
            cnode = f"cred:{username}@{source_ip}"
            self._merge_node(cnode, _label="Credential", kind="cred", username=username,
                             source_ip=source_ip, service=cred.get("service"),
                             domain_admin=is_domain_admin)
            if source_ip:
                self._merge_node(f"host:{source_ip}", _label="Host", kind="host", ip=source_ip)
                self._add_edge(f"host:{source_ip}", cnode, "HAS_CRED")
            if is_domain_admin:
                self._merge_node("goal:domain_admin", _label="Goal", kind="goal",
                                 name="domain_admin")
                self._add_edge(cnode, "goal:domain_admin", "GRANTS")

    def add_session(self, ip: str, **props) -> None:
        if self._disabled or not ip:
            return
        with self._lock:
            self._merge_node(f"host:{ip}", _label="Host", kind="host", ip=ip)
            snode = f"session:{ip}"
            self._merge_node(snode, _label="Session", kind="session", ip=ip, **props)
            self._add_edge(f"host:{ip}", snode, "HAS_SESSION")

    def link_pivot(self, src_ip: str, dst_ip: str, via=None) -> None:
        if self._disabled or not src_ip or not dst_ip:
            return
        with self._lock:
            self._merge_node(f"host:{src_ip}", _label="Host", kind="host", ip=src_ip)
            self._merge_node(f"host:{dst_ip}", _label="Host", kind="host", ip=dst_ip)
            self._add_edge(f"host:{src_ip}", f"host:{dst_ip}", "PIVOTS_TO", via=via)

    # ── KB sink entry point ─────────────────────────────────────────────────────

    def on_kb_event(self, event: str, payload: dict) -> None:
        """Translate a KnowledgeBase mutation into graph writes. Never raises."""
        if self._disabled:
            return
        try:
            ip = payload.get("ip")
            if event == "port_added":
                self.upsert_host(ip)
                self.upsert_service(ip, payload.get("port"),
                                    protocol=payload.get("protocol"),
                                    state=payload.get("state"))
            elif event == "service_added":
                self.upsert_service(ip, payload.get("port"), **(payload.get("info") or {}))
            elif event == "vuln_added":
                v = payload.get("vuln") or {}
                self.add_vuln(ip, v.get("cve", "unknown"), v.get("cvss"),
                              port=v.get("port"), severity=v.get("severity"))
            elif event == "credential_added":
                self.add_credential(payload.get("cred") or {}, ip)
            elif event == "shell_added":
                self.add_session(ip, **(payload.get("info") or {}))
            elif event == "hostname_added":
                self.upsert_host(ip, hostname=payload.get("hostname"))
        except Exception as e:  # noqa: BLE001 — a sink must never break a KB write
            log.warning("[GRAPH] failed to handle '%s': %s", event, e)

    # ── read side (called by planner tools in 2B) ───────────────────────────────

    def high_value_unexploited(self) -> list[dict]:
        """Services on un-owned hosts that carry a vulnerability, ranked by CVSS —
        the crown-jewel targets the planner hasn't cracked yet."""
        if self._disabled:
            return []
        with self._lock:
            out: list[dict] = []
            for node, data in self._g.nodes(data=True):
                if data.get("kind") != "service":
                    continue
                ip, port = data.get("ip"), data.get("port")
                if self._host_has_session(ip):
                    continue
                vulns = (self._neighbors_of_kind(node, "vuln")
                         + self._neighbors_of_kind(f"host:{ip}", "vuln"))
                if not vulns:
                    continue
                cvss_vals = [self._g.nodes[v].get("cvss") or 0 for v in vulns]
                out.append({
                    "ip": ip,
                    "port": port,
                    "service": data.get("product") or data.get("name"),
                    "max_cvss": max(cvss_vals) if cvss_vals else 0,
                    "vuln_count": len(set(vulns)),
                })
            out.sort(key=lambda r: r["max_cvss"], reverse=True)
            return out

    def reachable_unowned_hosts(self) -> list[str]:
        """Hosts we've seen but don't yet have a session on."""
        if self._disabled:
            return []
        with self._lock:
            return sorted(
                data["ip"] for _, data in self._g.nodes(data=True)
                if data.get("kind") == "host" and not self._host_has_session(data.get("ip"))
            )

    def shortest_path_to(self, goal: str = "domain_admin") -> Optional[list[str]]:
        """Shortest path (list of node ids) from any current foothold/session to the
        goal node, over the undirected projection. None if unreachable."""
        if self._disabled:
            return None
        with self._lock:
            goal_node = f"goal:{goal}"
            if goal_node not in self._g:
                return None
            sessions = [n for n, d in self._g.nodes(data=True) if d.get("kind") == "session"]
            if not sessions:
                return None
            ug = self._g.to_undirected(as_view=True)
            best: Optional[list[str]] = None
            for s in sessions:
                if _NX.has_path(ug, s, goal_node):
                    path = _NX.shortest_path(ug, s, goal_node)
                    if best is None or len(path) < len(best):
                        best = path
            return best

    def query(self, named: str):
        """Run a named canned query (networkx backend exposes named queries only)."""
        if named == "high_value_unexploited":
            return self.high_value_unexploited()
        if named == "reachable_unowned_hosts":
            return self.reachable_unowned_hosts()
        if named == "shortest_path_to_domain_admin":
            return self.shortest_path_to("domain_admin")
        raise ValueError(
            f"Unknown named query: {named!r}. Valid: high_value_unexploited, "
            f"reachable_unowned_hosts, shortest_path_to_domain_admin"
        )

    # ── housekeeping ────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        if self._disabled:
            return {"backend": "disabled", "nodes": 0, "edges": 0}
        with self._lock:
            by_kind: dict[str, int] = {}
            for _, data in self._g.nodes(data=True):
                k = data.get("kind", "?")
                by_kind[k] = by_kind.get(k, 0) + 1
            return {
                "backend": self.backend,
                "neo4j_mirror": self._mirror is not None,
                "nodes": self._g.number_of_nodes(),
                "edges": self._g.number_of_edges(),
                "by_kind": by_kind,
            }

    def export(self) -> dict:
        """A serialisable node/edge dump — used by checkpoints (5B)."""
        if self._disabled:
            return {"nodes": [], "edges": []}
        with self._lock:
            nodes = [{"id": n, **dict(d)} for n, d in self._g.nodes(data=True)]
            edges = [{"src": u, "dst": v, "rel": d.get("rel")}
                     for u, v, d in self._g.edges(data=True)]
            return {"nodes": nodes, "edges": edges}

    def reset(self) -> None:
        with self._lock:
            if not self._disabled:
                self._g.clear()

    def close(self) -> None:
        if self._mirror is not None:
            self._mirror.close()


# Module-level singleton — mirrors kb / telemetry / guardrails.
graph = AttackGraph()
