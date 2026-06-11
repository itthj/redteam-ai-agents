import React, { useCallback, useEffect, useState } from 'react';
import { API_BASE, eventSource, getJSON, post } from './api.js';

const SEV = { critical: 'sev-crit', high: 'sev-high', medium: 'sev-med', low: 'sev-low', info: 'sev-info' };
const STATE = { candidate: 'st-cand', confirmed: 'st-conf', approved: 'st-appr', rejected: 'st-rej' };

function Kpi({ label, value, sub }) {
  return (
    <div className="card">
      <div className="k">{label}</div>
      <div className="v">{value}</div>
      {sub && <div className="sub">{sub}</div>}
    </div>
  );
}

export default function App() {
  const [live, setLive] = useState(null);
  const [engagement, setEngagement] = useState(null);
  const [findings, setFindings] = useState([]);
  const [queue, setQueue] = useState([]);
  const [err, setErr] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const [eng, f, q] = await Promise.all([
        getJSON('/engagements'),
        getJSON('/findings'),
        getJSON('/findings/queue'),
      ]);
      setEngagement(eng.engagements[0]);
      setFindings(f.findings || []);
      setQueue(q.queue || []);
      setErr(null);
    } catch (e) {
      setErr(String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
    const es = eventSource();
    es.onmessage = (e) => setLive(JSON.parse(e.data));
    const t = setInterval(refresh, 5000);
    return () => { es.close(); clearInterval(t); };
  }, [refresh]);

  const act = async (sig, action) => {
    await post(`/findings/${sig}/${action}`, action === 'approve' ? {} : { reason: 'rejected from dashboard' });
    refresh();
  };
  const runEngagement = async () => {
    if (engagement) { await post(`/engagements/${engagement.id}/run`, { mode: 'autonomous' }); refresh(); }
  };
  const stopEngagement = async () => {
    if (engagement) { await post(`/engagements/${engagement.id}/stop`, {}); refresh(); }
  };

  const total = (live && live.telemetry && live.telemetry.total) || {};
  const states = (live && live.finding_states && live.finding_states.by_state)
    || (engagement && engagement.findings && engagement.findings.by_state) || {};
  const runStatus = (live && live.run && live.run.status) || (engagement && engagement.run && engagement.run.status) || 'idle';

  return (
    <div className="wrap">
      <header>
        <h1>RED TEAM <span className="dim">Client Dashboard</span></h1>
        <div className={`pill ${runStatus === 'running' ? 'live' : ''}`}>{runStatus}</div>
      </header>

      {err && <div className="err">API error: {err} — is the backend running at {API_BASE}?</div>}

      <section className="grid">
        <Kpi label="Phase" value={(live && live.phase) || '—'} />
        <Kpi label="Cost (USD)" value={'$' + (total.cost_usd || 0).toFixed(4)} sub={`${total.api_calls || 0} API calls`} />
        <Kpi label="Cache hit" value={Math.round((total.cache_hit_rate || 0) * 100) + '%'} />
        <Kpi label="Approved" value={states.approved || 0}
             sub={`${states.confirmed || 0} confirmed · ${states.candidate || 0} candidate`} />
        <Kpi label="Targets" value={engagement ? engagement.targets : '—'} />
      </section>

      <div className="cols">
        <section className="panel">
          <div className="phead">
            <h2>Engagement</h2>
            <div>
              <button onClick={runEngagement} disabled={runStatus === 'running'}>Start</button>
              <button onClick={stopEngagement} disabled={runStatus !== 'running'} className="ghost">Stop</button>
            </div>
          </div>
          {engagement && (
            <table className="kv"><tbody>
              <tr><td>ID</td><td>{engagement.id}</td></tr>
              <tr><td>Name</td><td>{engagement.name}</td></tr>
              <tr><td>Operator</td><td>{engagement.operator}</td></tr>
              <tr><td>Scope</td><td>{(engagement.scope && engagement.scope.authorized_targets || []).join(', ') || '—'}</td></tr>
              <tr><td>Expiry</td><td>{engagement.scope && engagement.scope.expiry}</td></tr>
            </tbody></table>
          )}

          <h2>Approval queue ({queue.length})</h2>
          {queue.length === 0 && <p className="dim">No findings awaiting approval.</p>}
          {queue.map((f) => (
            <div className="qrow" key={f.signature}>
              <div><span className={`badge ${SEV[f.severity] || ''}`}>{f.severity}</span> {f.title}</div>
              <div className="dim small">{f.target} · CVSS {f.cvss != null ? f.cvss : '—'}</div>
              <div className="actions">
                <button onClick={() => act(f.signature, 'approve')}>Approve</button>
                <button className="ghost" onClick={() => act(f.signature, 'reject')}>Reject</button>
              </div>
            </div>
          ))}
        </section>

        <section className="panel">
          <h2>Findings ({findings.length})</h2>
          <table className="findings">
            <thead><tr><th>State</th><th>Sev</th><th>Target</th><th>Title</th></tr></thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.signature}>
                  <td><span className={`badge ${STATE[f.state] || ''}`}>{f.state}</span></td>
                  <td><span className={`badge ${SEV[f.severity] || ''}`}>{f.severity}</span></td>
                  <td className="small">{f.target}</td>
                  <td className="small">{f.title}</td>
                </tr>
              ))}
              {findings.length === 0 && <tr><td colSpan="4" className="dim">No findings yet.</td></tr>}
            </tbody>
          </table>

          <h2>Live activity</h2>
          <ul className="activity">
            {(live && live.activity ? live.activity.slice().reverse() : []).map((a, i) => (
              <li key={i}><span className="dim small">{a.topic}</span> <span className="small">{a.source}</span></li>
            ))}
            {(!live || !(live.activity && live.activity.length)) && <li className="dim">No activity yet.</li>}
          </ul>
        </section>
      </div>

      <footer className="dim small">Live via SSE · {API_BASE} · authorized engagements only</footer>
    </div>
  );
}
