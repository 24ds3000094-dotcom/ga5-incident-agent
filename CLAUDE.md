# GA5 incident agent (Cloudflare Workers)

Graded assignment: a public HTTPS incident agent, profile `ga5-incident-agent/v2`.
The full problem statement is in `SPEC.md`. Treat it as the source of truth.

## Layout
- `src/index.js`: the Worker does routing and validation. The `IncidentRun` Durable Object (one per runId)
  holds the planner, the receipt state machine and the OTLP builder.
- `wrangler.jsonc`: config. `LLM_API_KEY` is a Cloudflare Secret. Never write it into any file.
- `test_local.py`: end-to-end test. Run it with `python test_local.py <base-url>`.
- Deployed by GitHub → Cloudflare on every push to `main`.
  URL: https://ga5-incident-agent.<subdomain>.workers.dev

## Commands
- Local dev: `npm install`, then `npx wrangler dev`. The key goes in `.dev.vars` as `LLM_API_KEY=...`, which is gitignored.
- Local test: `python test_local.py http://localhost:8787`
- Deploy: commit and `git push`. Do not run `wrangler deploy` by hand unless asked.

## Invariants (do not break)
- Exactly one model call, only in `create`. Receipts, retries, GET, replay and OTLP must never call a model.
- Store state before responding. An identical replay returns the stored JSON byte-for-byte.
  Changed content with the same runId or receiptId returns 409. An invalid request returns 400/422 and stores nothing.
- Never send the `sensitive` object to the model. Never export sensitive values, transcripts, prompts,
  tool arguments or tool results in spans or error responses.
- 503 gets exactly one retry. A timeout fails the diagnostic, and its effect is suppressed, never dispatched.
- Destructive effects (`approvalRequiredFor`) are only dispatched after the approval receipt arrives,
  with `approvalId` and `approvalNonce` set.
- Each dispatch's traceparent span ID equals its CLIENT span ID. Every span carries `ga5.run.id` and `ga5.public.marker`.
- Responses are JSON, under 768 KiB, under 18 s, and never redirect.

## Working rules
- Grader Checks are limited (10 per 24h). Run `test_local.py` against the deployed URL before suggesting a Check.
- When given Check feedback, identify the failing layer (diagnosis, actions, receipts, trace,
  correlation, replay, redaction) and make the smallest fix.
- Keep `src/index.js` as a single file with no runtime dependencies.
