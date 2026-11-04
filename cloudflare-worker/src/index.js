function jsonResponse(data, status, corsHeaders) {
  return new Response(JSON.stringify(data), {
    status: status,
    headers: Object.assign(
      { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
      corsHeaders || {}
    )
  });
}

function base64UrlEncodeBytes(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlEncodeText(value) {
  return base64UrlEncodeBytes(new TextEncoder().encode(value));
}

function base64UrlDecodeBytes(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Invalid base64url.");
  }
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64UrlDecodeText(value) {
  return new TextDecoder("utf-8", { fatal: true }).decode(base64UrlDecodeBytes(value));
}

function constantTimeTextEqual(a, b) {
  const left = new TextEncoder().encode(a);
  const right = new TextEncoder().encode(b);
  let diff = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i++) diff |= (left[i] || 0) ^ (right[i] || 0);
  return diff === 0;
}

async function importHmacKey(secret, usage) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    [usage]
  );
}

async function signPayload(payloadText, secret) {
  const key = await importHmacKey(secret, "sign");
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payloadText)
  );
  return base64UrlEncodeBytes(new Uint8Array(signature));
}

async function verifyPayloadSignature(payloadText, signature, secret) {
  const signatureBytes = base64UrlDecodeBytes(signature);
  if (signatureBytes.length !== 32) return false;
  const key = await importHmacKey(secret, "verify");
  return crypto.subtle.verify(
    "HMAC",
    key,
    signatureBytes,
    new TextEncoder().encode(payloadText)
  );
}

export default {
  async fetch(request, env) {
    const configuredOrigin = env.ALLOWED_ORIGIN;
    const requestOrigin = request.headers.get("Origin");

    if (!configuredOrigin || requestOrigin !== configuredOrigin) {
      return jsonResponse({ success: false, error: "Forbidden origin." }, 403);
    }

    const cors = {
      "Access-Control-Allow-Origin": configuredOrigin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "600",
      "Vary": "Origin"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }
    if (request.method !== "POST") {
      return jsonResponse({ success: false, error: "Method not allowed." }, 405, cors);
    }

    if (!env.PIN_SECRET || !env.TOKEN_SECRET || !env.RATE_LIMITER) {
      return jsonResponse({ success: false, error: "Server security configuration is incomplete." }, 500, cors);
    }
    if (String(env.TOKEN_SECRET).length < 32) {
      return jsonResponse({ success: false, error: "Token signing secret is not strong enough." }, 500, cors);
    }

    try {
      const url = new URL(request.url);
      if (url.pathname !== "/api/login" && url.pathname !== "/api/verify-token") {
        return jsonResponse({ success: false, error: "Endpoint not found." }, 404, cors);
      }

      const contentType = request.headers.get("Content-Type") || "";
      if (!contentType.toLowerCase().includes("application/json")) {
        return jsonResponse({ success: false, error: "Content-Type must be application/json." }, 415, cors);
      }

      const rawBody = await request.text();
      if (rawBody.length > 2048) {
        return jsonResponse({ success: false, error: "Request is too large." }, 413, cors);
      }

      let body;
      try {
        body = JSON.parse(rawBody);
      } catch (_) {
        return jsonResponse({ success: false, error: "Malformed JSON request." }, 400, cors);
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return jsonResponse({ success: false, error: "Invalid request body." }, 400, cors);
      }

      if (url.pathname === "/api/login") {
        // One manager account: use one shared key so attempts from multiple IPs cannot each get a fresh allowance.
        const rate = await env.RATE_LIMITER.limit({ key: "dispatch-manager-login" });
        if (!rate || rate.success !== true) {
          return jsonResponse({ success: false, error: "Too many login attempts. Please wait before trying again." }, 429, cors);
        }

        if (typeof body.pin !== "string" || body.pin.length < 6 || body.pin.length > 32) {
          return jsonResponse({ success: false, error: "Enter the dispatch PIN." }, 401, cors);
        }
        if (!constantTimeTextEqual(body.pin, String(env.PIN_SECRET))) {
          return jsonResponse({ success: false, error: "Incorrect PIN." }, 401, cors);
        }

        const now = Date.now();
        const payload = {
          v: 1,
          iat: now,
          exp: now + (2 * 60 * 60 * 1000),
          jti: crypto.randomUUID()
        };
        const payloadText = JSON.stringify(payload);
        const payloadPart = base64UrlEncodeText(payloadText);
        const signaturePart = await signPayload(payloadText, String(env.TOKEN_SECRET));

        return jsonResponse(
          { success: true, token: payloadPart + "." + signaturePart },
          200,
          cors
        );
      }

      const token = body.token;
      if (typeof token !== "string" || token.length > 2048) {
        return jsonResponse({ valid: false }, 401, cors);
      }
      const parts = token.split(".");
      if (parts.length !== 2 || !parts[0] || !parts[1]) {
        return jsonResponse({ valid: false }, 401, cors);
      }

      let payloadText;
      let payload;
      try {
        payloadText = base64UrlDecodeText(parts[0]);
        payload = JSON.parse(payloadText);
      } catch (_) {
        return jsonResponse({ valid: false }, 401, cors);
      }

      if (!payload || typeof payload !== "object" || Array.isArray(payload) ||
          payload.v !== 1 || !Number.isSafeInteger(payload.iat) ||
          !Number.isSafeInteger(payload.exp) || typeof payload.jti !== "string" ||
          payload.jti.length < 16 || payload.jti.length > 80) {
        return jsonResponse({ valid: false }, 401, cors);
      }

      const now = Date.now();
      const maxLifetime = 2 * 60 * 60 * 1000;
      if (payload.iat > now + 30000 || payload.exp <= now ||
          payload.exp <= payload.iat || payload.exp - payload.iat > maxLifetime) {
        return jsonResponse({ valid: false }, 401, cors);
      }

      let signatureValid = false;
      try {
        signatureValid = await verifyPayloadSignature(
          payloadText,
          parts[1],
          String(env.TOKEN_SECRET)
        );
      } catch (_) {
        signatureValid = false;
      }
      if (!signatureValid) return jsonResponse({ valid: false }, 401, cors);

      return jsonResponse({ valid: true }, 200, cors);
    } catch (error) {
      // Never return stack traces or secret values to the browser.
      return jsonResponse({ success: false, error: "Internal server error." }, 500, cors);
    }
  }
};