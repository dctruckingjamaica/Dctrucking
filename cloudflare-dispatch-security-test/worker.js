const ALLOWED_ORIGIN = "https://dctrucking-jamaica.github.io";
const TOKEN_LIFETIME_SECONDS = 300;

function cors(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

function json(data, status, headers) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...headers, "Content-Type": "application/json", "Cache-Control": "no-store" }
  });
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function fromBase64Url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function importSigningKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function issueToken(secret) {
  const payload = {
    purpose: "dispatch-access",
    exp: Math.floor(Date.now() / 1000) + TOKEN_LIFETIME_SECONDS
  };
  const encoded = toBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const key = await importSigningKey(secret);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(encoded));
  return encoded + "." + toBase64Url(new Uint8Array(signature));
}

async function validToken(secret, token) {
  if (typeof token !== "string" || token.length > 2048) return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  try {
    const key = await importSigningKey(secret);
    const signatureOK = await crypto.subtle.verify(
      "HMAC", key, fromBase64Url(parts[1]), new TextEncoder().encode(parts[0])
    );
    if (!signatureOK) return false;
    const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[0])));
    return payload.purpose === "dispatch-access" &&
      Number.isInteger(payload.exp) &&
      payload.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

async function pinMatches(entered, expected) {
  const encoder = new TextEncoder();
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(entered)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected))
  ]);
  const x = new Uint8Array(a);
  const y = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    if (origin !== ALLOWED_ORIGIN) return new Response("Forbidden", { status: 403 });

    const headers = cors(ALLOWED_ORIGIN);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });

    const url = new URL(request.url);
    if (request.method !== "POST" || !["/auth", "/verify"].includes(url.pathname)) {
      return json({ success: false, error: "Not found" }, 404, headers);
    }

    if (!env.DISPATCH_PIN || !/^\d{6}$/.test(env.DISPATCH_PIN) || !env.TOKEN_SECRET) {
      return json({ success: false, error: "Worker secrets are not configured" }, 503, headers);
    }

    if (url.pathname === "/auth") {
      if (!env.LOGIN_LIMITER) {
        return json({ success: false, error: "Login rate limiter is not configured" }, 503, headers);
      }
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const limit = await env.LOGIN_LIMITER.limit({ key: ip });
      if (!limit.success) return json({ success: false, error: "Too many attempts. Try again shortly." }, 429, headers);

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ success: false }, 400, headers);
      }
      const pin = String(body?.pin ?? "");
      if (!/^\d{6}$/.test(pin) || !(await pinMatches(pin, env.DISPATCH_PIN))) {
        return json({ success: false }, 401, headers);
      }
      const token = await issueToken(env.TOKEN_SECRET);
      return json({ success: true, token, expiresIn: TOKEN_LIFETIME_SECONDS }, 200, headers);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ success: false }, 400, headers);
    }
    const ok = await validToken(env.TOKEN_SECRET, body?.token);
    return json({ success: ok }, ok ? 200 : 401, headers);
  }
};
