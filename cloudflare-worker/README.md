# D&C Dispatch Security Test

This is a draft security test only. It is not deployed and does not change the live site.

## Files
- \`src/index.js\`: Cloudflare Worker login and signed-token verification.
- \`wrangler.jsonc\`: Worker configuration, including the \`RATE_LIMITER\` binding.
- \`../admin-security-test.html\`: isolated test copy of the existing admin page.

## Before deploying
1. Confirm the GitHub Pages origin in \`ALLOWED_ORIGIN\` exactly matches the site address bar origin (scheme and host only; no \`/dctrucking/\` path).
2. The current config assumes \`https://dctruckingjamaica.github.io\`; verify this is the actual host before deployment.
3. Choose a new PIN. Do not reuse the old PIN because it was exposed in public source code.
4. Keep \`PIN_SECRET\` and \`TOKEN_SECRET\` out of GitHub. Set them as Worker secrets:
   - \`npx wrangler secret put PIN_SECRET\`
   - \`npx wrangler secret put TOKEN_SECRET\`
5. Use a random \`TOKEN_SECRET\` with at least 32 characters.
6. The sample \`RATE_LIMITER\` allows 10 login attempts per 60 seconds per client IP. Rate limiting is approximate and local to each Cloudflare location; users on the same mobile carrier may share an IP.
7. Deploy only as a test Worker. Then replace \`WORKER_BASE_URL\` in \`admin-security-test.html\` with the deployed Worker origin.

## Session behaviour
- Signed tokens expire after two hours.
- The admin page automatically locks after three minutes of inactivity.
- Logout clears the token from this browser session. It does not revoke a copied token on the server; a copied token can remain valid until its two-hour expiry.
- No business records are sent to the Worker. Jobs, invoices, crew profiles, receipts, documents and other business records remain in browser localStorage.

## Security limitation
This is a server-verified gate for opening the dispatch panel. Because business records remain in browser localStorage, it does not make them tamper-proof against someone who can use developer tools or execute code in that same browser profile. A true server-side data permission system would require storing protected records server-side, which this project intentionally does not do.
