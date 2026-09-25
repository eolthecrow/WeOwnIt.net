# WeOwnIt.net
Practical cybersecurity resources shaped by real-world network operations — assessments, incident response, hardening, troubleshooting, and automation made usable.
https://eolthecrow.github.io/WeOwnIt.net/


## Language and production maintenance

- Shared language state/navigation/metadata: `assets/i18n.js`. Page copy remains next to the page markup.
- Links use explicit `?lang=en`, `?lang=ro`, or `?lang=fr`; URL selection takes precedence over the remembered preference. Storage failures do not block translation.
- Language changes emit `site:languagechange`. The chat updates its controls, greeting and suggestions while retaining conversation messages in their original language.
- EN metadata is included in source HTML; RO/FR metadata and canonical are updated by JavaScript. `hreflang` and the sitemap identify all language query variants. Crawlers/social preview clients that do not execute JavaScript will still see English metadata. Static language-specific HTML is a separate future step if localized link previews are required.
- Privacy describes the current email hand-off, GitHub Pages hosting, Cal.com embed, browser language preference and local demo assistant. Revisit this notice before enabling an AI endpoint, analytics or payments.
- Before enabling sales: supply verified per-product Lemon Squeezy URLs; configure and test price/tax/invoice, delivery, success/cancellation paths and refunds; publish the applicable seller identity, purchase/license and refund terms. No checkout is enabled by this change.

### Verification — 25 September 2026

DOM execution checks cover all seven main pages in EN/RO/FR, selector clicks, language links, metadata, chat labels/suggestions, keyboard Escape/focus return, disabled checkout and storage-denied operation. Script syntax and internal paths/anchors are checked separately. DOM tests do not validate rendered mobile layout, contrast, Cal.com availability, email delivery, actual payment processing or JavaScript-free social previews.
