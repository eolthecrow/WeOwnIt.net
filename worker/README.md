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

- CORS allows `https://weownit.net`, `https://www.weownit.net`, and the legacy GitHub Pages origin during migration
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


## Direct contact form

The same Worker now exposes:

```text
POST /contact
```

The website sends contact-form submissions directly to this endpoint. The Worker validates the request and sends it to the fixed destination configured in `wrangler.jsonc` using Cloudflare Email Service. The submitted email address is set as `replyTo`, so replying from the inbox goes directly to the visitor.

### One-time Cloudflare email setup

1. In Cloudflare, open **Compute > Email Service** and onboard a domain that uses Cloudflare DNS.
2. Under **Email Routing > Destination Addresses**, add and verify:
   `vladimir.arjoca@outlook.com`
3. Use the configured sender address:
   `contact@weownit.net`
   The address is already set in `wrangler.jsonc` as `CONTACT_FROM_EMAIL` and restricted by the email binding.
4. Deploy the Worker:
   ```bash
   npm run deploy
   ```
5. Test the contact endpoint from the website or with a POST request from an allowed origin.

The `send_email` binding is restricted to the verified Outlook destination in `wrangler.jsonc`.

### Contact-form safeguards

- CORS restricted to the website origin and localhost development.
- Required-field and email-format validation.
- 5,000-character message limit.
- Consent required.
- Hidden honeypot field.
- Lightweight submission-timing check.
- No contact submission is intentionally written to a website database.
- If direct delivery is unavailable, the frontend presents an email fallback instead of discarding the visitor's message.

For broader public traffic, add Cloudflare Turnstile and/or rate limiting.


## Custom-domain production setup

The website canonical domain is `https://weownit.net`. The repository root contains a `CNAME` file for GitHub Pages.

Cloudflare DNS should point the apex domain to GitHub Pages and `www` to `eolthecrow.github.io`. Keep the legacy GitHub Pages origin in Worker CORS only during the migration period; remove it after the custom domain is confirmed stable.
