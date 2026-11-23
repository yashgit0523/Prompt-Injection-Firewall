# Deployment: Render (backend) + Vercel (frontend)

PromptGuard is one FastAPI app: it serves the JSON API (`/api/*`) **and** the
server-rendered UI (Jinja templates + `/static`). To deploy it without changing
any application code:

- **Render** runs the FastAPI app (API + UI) -> `render.yaml`
- **Vercel** is the public frontend URL. It proxies every request to Render
  -> `deploy/vercel/vercel.json`

The browser only talks to the Vercel domain. The UI's `fetch("/api/...")` calls
stay same-origin, so there's no CORS to configure.

```
Browser ──> your-app.vercel.app ──(rewrite/proxy)──> promptguard-api.onrender.com (FastAPI)
```

---

## 1. Deploy the backend on Render

1. Push this repo to GitHub.
2. In Render, go to **New + -> Blueprint** and pick the repository. Render reads `render.yaml`.
3. Click **Apply**. Render installs `requirements.txt` and starts:
   `uvicorn app.main:app --host 0.0.0.0 --port $PORT --proxy-headers`
4. When it's live, open `https://<your-service>.onrender.com/api/health`. You should see
   `{"status":"ok", ...}`.
5. **Copy the service URL.** If the name `promptguard-api` was already taken, Render
   gives you a different URL, such as `promptguard-api-xyz1.onrender.com`.

Environment variables (already set in `render.yaml`; change them in the Render dashboard):

| Variable | Default | Notes |
|---|---|---|
| `PROMPTGUARD_MODE` | `ENFORCE` | `LEARNING` / `MONITOR` / `ENFORCE` |
| `PROMPTGUARD_LLM_PROVIDER` | `mock` | `openai` / `anthropic` also need the package added to `requirements.txt` and the API key set |
| `PROMPTGUARD_DB_PATH` | `/tmp/promptguard/promptguard.db` | SQLite event log |
| `FORWARDED_ALLOW_IPS` | `*` | Trusts Render's proxy headers so generated links use https |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | (empty) | Set them in the dashboard only, never in git |

> **Note:** Render's free plan has an ephemeral disk, so the security event log
> resets on every redeploy or restart. Free services also sleep after about 15
> minutes idle, so the first request after that takes around 30–60 seconds. For
> persistent logs, use a paid plan with a Render Disk mounted at, for example,
> `/var/data` and set `PROMPTGUARD_DB_PATH=/var/data/promptguard.db`.

## 2. Deploy the frontend on Vercel

1. If your Render URL is not `https://promptguard-api.onrender.com`, edit
   `deploy/vercel/vercel.json` and replace the `destination` host with your URL.
   Commit and push.
2. In Vercel, go to **Add New -> Project** and import the same repository.
3. Under **Root Directory**, click *Edit* and choose **`deploy/vercel`**. This step is required.
4. Set **Framework Preset** to **Other**. Leave the build and output settings empty.
5. Click **Deploy**.
6. Open `https://<your-project>.vercel.app`. You should see the dashboard, and the status chip should show
   **FIREWALL ONLINE**.

All routes work through Vercel: `/`, `/scanner`, `/documents`, `/demo`,
`/events`, `/about`, `/docs` (Swagger) and `/api/*`.

## Troubleshooting

- **Vercel shows 502/504 on first load:** the Render free instance is waking up. Wait about 1 minute and refresh.
- **"FIREWALL OFFLINE":** check `/api/health` on the Render URL directly, then check that the
  `destination` in `deploy/vercel/vercel.json` matches it exactly.
- **Vercel tries to build Python:** Root Directory is not set to `deploy/vercel`.
