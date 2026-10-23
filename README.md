# GA5 incident agent — Cloudflare Workers

Static URL: `https://ga5-incident-agent.<your-subdomain>.workers.dev`

- `src/index.js` — Worker (routing/validation) + `IncidentRun` Durable Object (one per runId)
- `wrangler.jsonc` — config; model settings in `vars`
- Secret `LLM_API_KEY` — set in the Cloudflare dashboard, never commit it
- `test_local.py` — end-to-end check: `python test_local.py https://<your-url>`

Local dev: put `LLM_API_KEY=...` in `.dev.vars`, then `npm install && npx wrangler dev`.
