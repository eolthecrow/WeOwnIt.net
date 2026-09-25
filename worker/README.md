# Network & Security Assistant — Cloudflare Workers AI

This folder contains the free-first backend for the website chatbot.

## What it uses

- Cloudflare Worker
- Cloudflare Workers AI binding
- Model: `@cf/zai-org/glm-4.7-flash`
- No OpenAI API key is required.

The website currently keeps its local fallback until a deployed Worker URL is configured.

## Deploy

From the repository root:

```bash
cd worker
npm install
npx wrangler login
npm run deploy
```

Wrangler will return a URL similar to:

```text
https://network-security-assistant.<your-subdomain>.workers.dev
```

Test it:

```bash
curl https://network-security-assistant.<your-subdomain>.workers.dev/health
```

Then test chat:

```bash
curl -X POST \
  https://network-security-assistant.<your-subdomain>.workers.dev/chat \
  -H "Content-Type: application/json" \
  -d '{"message":"Explain network segmentation simply.","language":"en","history":[]}'
```

## Connect the website

The existing `assets/chatbox.js` already reads:

```js
window.NETWORK_SECURITY_CHAT_ENDPOINT
```

After deployment, set it before loading `assets/chatbox.js`:

```html
<script>
window.NETWORK_SECURITY_CHAT_ENDPOINT =
  "https://network-security-assistant.<your-subdomain>.workers.dev/chat";
</script>
```

Once the real Workers URL is known, update the website pages that load the chatbot.

## Current safeguards

- CORS restricted to `https://eolthecrow.github.io`
- localhost allowed for development
- max user message: 4,000 characters
- max retained history: 8 messages
- history character cap
- output cap: 700 completion tokens
- paid toolkit content is not treated as part of the model's knowledge

## Recommended next safeguards

Before substantial public traffic, add:

- Cloudflare Turnstile
- per-user/IP rate limiting
- analytics for errors and usage
- optional AI Gateway observability
- a graceful message when the daily Workers AI free allocation is exhausted
