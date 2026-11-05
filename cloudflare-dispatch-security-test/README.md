# DC Trucking dispatch security test

This is an isolated Cloudflare Worker test. It is not connected to the live website and does not read, store, or move job, receipt, photo, or other business records.

## Endpoints
- POST /auth with JSON {"pin":"six digits"} returns a short-lived signed token when the PIN is correct.
- POST /verify with JSON {"token":"..."} validates that token.
- Browser requests are restricted to the GitHub Pages origin https://dctrucking-jamaica.github.io.

## Required Worker secrets
Configure these as encrypted Worker secrets; never put their values in this repository:
- DISPATCH_PIN: the existing six-digit dispatch PIN (do not send it in chat or commit it).
- TOKEN_SECRET: a separate long random secret used to sign short-lived access tokens.

## Rate limiting
The LOGIN_LIMITER binding allows 5 attempts per IP per 60 seconds. It is configured in wrangler.toml.

## Important limitations
This test Worker is not yet integrated into admin.html. Until a separate, reviewed integration is made and explicitly approved, the existing website login remains unchanged. The token lasts five minutes. This protects the login check from being hard-coded in the public page, but it does not make the public HTML/JavaScript private or encrypt device-local records.
