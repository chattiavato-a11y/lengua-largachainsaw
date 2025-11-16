// src/worker.js  — Integrity Gateway (withered-mouse-9aee…workers.dev)
// Endpoints:  POST /auth/issue   |  GET /health, /health/origin
// Verifies X-Integrity headers, mints detached HMAC-SHA512 signatures, strict CORS.

const BASE_ALLOWED_ORIGINS = [
  "https://chattiavato-a11y.github.io"
];

const DEFAULT_INTEGRITY_GATEWAY   = "https://withered-mouse-9aee.grabem-holdem-nuts-right.workers.dev";
const DEFAULT_INTEGRITY_PROTOCOLS = "CORS,CSP,OPS-CySec-Core,CISA,NIST,PCI-DSS,SHA-384,SHA-512";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const m   = request.method.toUpperCase();

    if ((url.pathname.startsWith("/auth/") || url.pathname.startsWith("/health/") || url.pathname.startsWith("/fallback/")) && m === "OPTIONS") {
      return applySecurityHeaders(new Response(null, { status: 204 }), request, env);
    }

    if (url.pathname === "/health" || url.pathname === "/health/ok") {
      return applySecurityHeaders(json({ ok: true }), request, env);
    }

    if (url.pathname === "/health/origin") {
      const origin = request.headers.get("Origin") || "";
      const allowed = getAllowedOrigin(origin, env);
      return applySecurityHeaders(json({ reqOrigin: origin, allowedNow: Boolean(allowed) }), request, env);
    }

    if (url.pathname === "/auth/issue") {
      if (m !== "POST") {
        return applySecurityHeaders(json({ error: "method_not_allowed" }, 405), request, env);
      }

      const gate = enforceIntegrityHeadersOnly(request, env);
      if (gate) return applySecurityHeaders(gate, request, env);

      if (!env.SHARED_KEY) {
        return applySecurityHeaders(json({ error: "Signature service unavailable" }, 500), request, env);
      }

      let payload;
      try { payload = await request.json(); }
      catch { return applySecurityHeaders(json({ error: "Invalid JSON" }, 400), request, env); }

      const tsRaw     = payload?.ts ?? payload?.timestamp;
      const nonceRaw  = payload?.nonce;
      const methodRaw = payload?.method;
      const pathRaw   = payload?.path;
      const bodyShaRaw= payload?.body_sha256 ?? payload?.bodySha256;

      const ts  = Number(tsRaw);
      const now = Math.floor(Date.now()/1000);
      const ttl = getSignatureTtl(env);

      if (!Number.isFinite(ts))                              return applySecurityHeaders(json({ error: "Invalid timestamp" }, 400), request, env);
      if (ts > now + 5 || now - ts > ttl)                    return applySecurityHeaders(json({ error: "Timestamp out of range" }, 400), request, env);
      const nonce = (typeof nonceRaw === "string" ? nonceRaw.trim().toLowerCase() : "");
      if (!/^[a-f0-9]{32}$/.test(nonce))                     return applySecurityHeaders(json({ error: "Invalid nonce" }, 400), request, env);
      const method = (typeof methodRaw === "string" ? methodRaw.trim().toUpperCase() : "");
      if (method !== "POST")                                 return applySecurityHeaders(json({ error: "Unsupported method" }, 400), request, env);
      const path   = (typeof pathRaw === "string" ? pathRaw.trim() : "");
      if (!path.startsWith("/api/"))                         return applySecurityHeaders(json({ error: "Invalid path" }, 400), request, env);
      const bodySha= (typeof bodyShaRaw === "string" ? bodyShaRaw.trim().toLowerCase() : "");
      if (!/^[a-f0-9]{64}$/.test(bodySha))                   return applySecurityHeaders(json({ error: "Invalid body digest" }, 400), request, env);

      if (env.OPS_NONCE_KV) {
        const mintKey = `mint:${nonce}:${ts}`;
        const exists  = await env.OPS_NONCE_KV.get(mintKey);
        if (exists)                                        return applySecurityHeaders(json({ error: "Nonce reuse detected" }, 409), request, env);
        await env.OPS_NONCE_KV.put(mintKey, "1", { expirationTtl: ttl });
      }

      const canonical = `${ts}.${nonce}.${method}.${path}.${bodySha}`;
      const signature = await hmacSha512B64(env.SHARED_KEY, canonical);
      const remaining = Math.max(0, ttl - Math.max(0, now - ts));

      return applySecurityHeaders(json({ signature, expires_in: remaining }, 200, {
        "cache-control": "no-store",
        "x-signature-ttl": String(ttl)
      }), request, env);
    }

    if (url.pathname === "/fallback/escalate") {
      if (m !== "POST") {
        return applySecurityHeaders(json({ error: "method_not_allowed" }, 405), request, env);
      }

      const gate = enforceIntegrityHeadersOnly(request, env);
      if (gate) return applySecurityHeaders(gate, request, env);

      let payload = {};
      try { payload = await request.json(); }
      catch { return applySecurityHeaders(json({ error: "Invalid JSON" }, 400), request, env); }

      const reason = typeof payload.reason === "string" && payload.reason.trim() ? payload.reason.trim() : "unspecified";
      const confidence = typeof payload.confidence === "number" ? payload.confidence : null;
      const meta = {
        reason,
        confidence,
        lang: typeof payload.lang === "string" ? payload.lang : undefined,
        userText: typeof payload.userText === "string" ? payload.userText : undefined,
        fallback: typeof payload.fallback === "string" ? payload.fallback : undefined,
        timestamp: payload.timestamp || new Date().toISOString(),
        conversationTail: Array.isArray(payload.conversationTail) ? payload.conversationTail : undefined
      };

      forwardEscalation(meta, env).catch(()=>{});

      return applySecurityHeaders(json({ escalated: true, reason, confidence }), request, env);
    }

    return applySecurityHeaders(json({ error: "not_found" }, 404), request, env);
  }
};

/* -------------------- Integrity & CORS -------------------- */

function enforceIntegrityHeadersOnly(request, env) {
  if (env.INTEGRITY_REQUIRED !== "true") return null;

  const provided = (request.headers.get("x-integrity") || "").toLowerCase();
  const gateway  = request.headers.get("x-integrity-gateway");
  const expected = resolveIntegrityGateway(env);
  const allow    = buildAllowedOrigins(env);

  if (!provided || !allow.includes(provided)) return json({ error: "Integrity validation failed" }, 403);
  if (gateway !== expected)                   return json({ error: "Integrity gateway mismatch" }, 412);
  return null;
}

function applySecurityHeaders(res, request, env) {
  const h = new Headers(res.headers);
  const origin = request.headers.get("Origin");
  const allowedOrigin = getAllowedOrigin(origin, env);
  if (allowedOrigin) {
    h.set("Access-Control-Allow-Origin", allowedOrigin);
    h.set("Access-Control-Allow-Credentials", "true");
    h.set("Vary", mergeVary(h.get("Vary"), "Origin"));
  }

  h.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  h.set("Access-Control-Allow-Headers",
    "Content-Type, X-Integrity, X-Integrity-Gateway, X-Integrity-Protocols");
  h.set("Access-Control-Max-Age", "600");

  h.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none';");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("X-Frame-Options", "DENY");
  h.set("Referrer-Policy", "same-origin");
  h.set("Permissions-Policy", "microphone=(),camera=(),geolocation=()");
  h.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");

  const gw  = resolveIntegrityGateway(env);
  const pr  = resolveIntegrityProtocols(env);
  h.set("X-OPS-CYSEC-CORE", "active");
  h.set("X-Compliance-Frameworks", pr);
  h.set("Integrity", gw);
  h.set("X-Integrity-Gateway", gw);
  h.set("X-Integrity-Protocols", pr);

  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}

function resolveIntegrityGateway(env){
  const c = (env.INTEGRITY_GATEWAY||"").trim();
  return c || DEFAULT_INTEGRITY_GATEWAY;
}
function resolveIntegrityProtocols(env){
  const c = (env.INTEGRITY_PROTOCOLS||"").trim();
  return c || DEFAULT_INTEGRITY_PROTOCOLS;
}

function getAllowedOrigin(origin, env){
  if (!origin) return null;
  const norm = origin.trim().toLowerCase();
  if (!norm) return null;

  const allowWorkers = env.ALLOW_WORKERS_DEV === "true";
  const allowDash    = env.ALLOW_DASH === "true";
  const allow        = buildAllowedOrigins(env);

  if (allow.includes(norm)) return allow[allow.indexOf(norm)];
  if (allowWorkers && isWorkersDev(norm)) return origin;
  if (allowDash && isDash(norm))          return origin;
  return null;
}

function buildAllowedOrigins(env) {
  const set = new Set(BASE_ALLOWED_ORIGINS.map(s => s.toLowerCase()));
  const extra = (env.UI_ORIGINS || "").split(/[\,\s]+/).map(s => s.trim()).filter(Boolean);
  for (const e of extra) set.add(e.toLowerCase());
  return Array.from(set);
}

function isWorkersDev(o) { try { return new URL(o).hostname.endsWith(".workers.dev"); } catch { return false; } }
function isDash(o)       { try { return new URL(o).hostname.endsWith(".dash.cloudflare.com"); } catch { return false; } }
function mergeVary(exist, v) {
  if (!exist) return v;
  const parts = new Set(exist.split(",").map(p => p.trim()).filter(Boolean));
  parts.add(v);
  return Array.from(parts).join(", ");
}

async function hmacSha512B64(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-512" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return b64(sig);
}
function b64(buf) {
  const u8 = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer || buf);
  let bin = ""; for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}
function json(obj, status = 200, extra) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=UTF-8", ...(extra || {}) }
  });
}
function getSignatureTtl(env) {
  const fallback = 300;
  const n = Number(env.SIG_TTL_SECONDS || "");
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.max(60, Math.min(900, Math.floor(n)));
}

async function forwardEscalation(payload, env) {
  const hook = (env.ESCALATION_WEBHOOK || "").trim();
  if (!hook) return;
  try {
    await fetch(hook, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...payload, gateway: "withered-mouse-9aee" })
    });
  } catch (err) {
    console.error("escalation_forward_failed", err);
  }
}
