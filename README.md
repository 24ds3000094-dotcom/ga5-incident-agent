# ga5-incident-agent (Cloudflare Worker + Durable Object)

## Deploy
1. Replace the repo contents with these files (delete any old `wrangler.jsonc` / `wrangler.json`
   and old `src/` files so only this `wrangler.toml` remains).
2. Dashboard > ga5-incident-agent > Settings > Variables and Secrets > add **Secret**
   `LLM_API_KEY` = your AI Pipe token (or OpenAI/OpenRouter key; then edit LLM_BASE_URL/LLM_MODEL).
   No secret set => it falls back to free Workers AI (Llama 3.3 70B), which is weaker at diagnosis.
3. `git push` to main (your build runs `npx wrangler deploy`).
4. Submit the base URL only: `https://ga5-incident-agent.<your-subdomain>.workers.dev`

## Test locally (no Checks used)
    MOCK_LLM=1 node test/local-server.mjs
    BASE=http://127.0.0.1:8787 python3 test/test_local.py
