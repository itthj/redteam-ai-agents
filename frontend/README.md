# Red Team — Client Dashboard (C4)

A React (Vite) frontend for the `redteam-ai-agents` platform: KPI overview,
engagement detail, findings table with the candidate / confirmed / approved
lifecycle, the human-approval queue, live agent activity, and live token/USD cost.

It is a thin client over the FastAPI backend (`api/server.py`) — KPIs and activity
stream live over SSE (`/events`); findings and the approval queue are read over REST
and acted on with `POST /findings/{sig}/approve|reject`.

## Run

1. Start the backend (from the repo root):

   ```bash
   uvicorn api.server:app --reload --port 8000
   ```

2. Start the dashboard:

   ```bash
   cd frontend
   npm install
   npm run dev          # http://localhost:5173
   ```

## Configuration

Set these as Vite env vars (e.g. in `frontend/.env.local`):

| Var | Default | Notes |
|-----|---------|-------|
| `VITE_API_BASE` | `http://localhost:8000` | Backend base URL |
| `VITE_API_KEY`  | _(empty)_ | Required only if the backend sets `API_SECRET_KEY`. The `/events` SSE stream is always open. |

The backend's CORS allow-list (`API_CORS_ORIGINS`, default `*`) must permit the
dashboard origin. Authentication / RBAC and multi-tenant engagement selection arrive
with the SaaS backend (C7); today the dashboard shows the single configured engagement
and is intended for localhost / trusted-network use.

> Authorized engagements only. The dashboard surfaces live offensive activity — run it
> on a trusted network.
