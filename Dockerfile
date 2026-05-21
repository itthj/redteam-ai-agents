FROM kalilinux/kali-rolling

# ── System tools the agents shell out to ──────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    nmap \
    whois \
    dnsutils \
    exploitdb \
    nodejs npm \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Python dependencies ───────────────────────────────────────────────────────
COPY requirements.txt .
# --break-system-packages: Kali enforces PEP 668; this container is dedicated.
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# ── Application ────────────────────────────────────────────────────────────────
COPY . .

EXPOSE 8000

# Default: REST API. Override with `docker run ... python main.py mission ...`
CMD ["uvicorn", "api.server:app", "--host", "0.0.0.0", "--port", "8000"]
