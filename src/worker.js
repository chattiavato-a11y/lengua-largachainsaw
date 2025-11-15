/**
 * OPS Chattia API — Chat + STT + Integrity Envelope
 * Updated to your spec: SHA-512 HMAC, Integrity headers, protocol/gateway headers, strict CORS/CSP.
 */

const MODEL_ID = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
const DEFAULT_INTEGRITY_GATEWAY = "https://withered-mouse-9aee.grabem-holdem-nuts-right.workers.dev";
const BASE_ALLOWED_ORIGINS = ["https://chattiavato-a11y.github.io"]; // baseline allow-list (UI)
const DEFAULT_INTEGRITY_PROTOCOLS = "CORS,CSP,OPS-CySec-Core,CISA,NIST,PCI-DSS,SHA-384,SHA-512";
const DEFAULT_HONEYPOT_FIELDS = [
  "hp_email",
  "hp_name",
  "hp_field",
  "honeypot",
  "hp_text",
  "botcheck",
  "bot_field",
  "trap_field"
];
const HONEYPOT_BLOCK_TTL_SECONDS = 86400; // 24h default block window

const DEFAULT_BM25_THRESHOLD = 1.15;

const STOP_WORDS = {
  en: new Set([
    "a","about","an","and","are","as","at","be","by","for","from","how",
    "in","is","it","of","on","or","our","that","the","their","to","we","what","when"
  ]),
  es: new Set([
    "a","al","como","con","de","del","el","ella","ellas","ellos","en","es","esta","este",
    "las","los","para","por","que","se","son","su","sus","un","una","y"
  ])
};

const WEBSITE_KB = buildWebsiteKnowledgeBase();
const AVG_DOC_LENGTH =
  WEBSITE_KB.reduce((acc, doc) => acc + doc.length, 0) / (WEBSITE_KB.length || 1);

const SYSTEM_PROMPT =
  "You are Chattia, an empathetic, security-aware assistant that communicates with clarity and inclusive language. " +
  "Deliver responses that are concise, actionable, and aligned with Cyber-Security Core Governance. Provide step-by-step support " +
  "when helpful, highlight important cautions, and remain compliant with accessibility and privacy expectations.";

const WARNING_MESSAGE =
  "Apologies, but I cannot execute that request, do you have any questions about our website?";
const TERMINATE_MESSAGE =
  "Apologies, but I must not continue with this chat and I must end this session.";

const MALICIOUS_PATTERNS = [
  /<[^>]*>/i,
  /script/i,
  /malicious/i,
  /attack/i,
  /ignore/i,
  /prompt/i,
  /hack/i,
  /drop\s+table/i
];

const WEBSITE_KEYWORDS = [
  "website","site","chattia","product","service","support","order","account","pricing","contact","help"
];

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    const activeBlock = await checkHoneypotBan(request, env);
    if (activeBlock?.blocked) {
      const res = honeypotBlockedResponse(activeBlock.reason, activeBlock.until);
      return applySecurityHeaders(res, request, env);
    }

    // Preflight CORS
    if (url.pathname.startsWith("/api/") && method === "OPTIONS") {
      const pre = new Response(null, { status: 204 });
      return applySecurityHeaders(pre, request, env);
    }

    // Static assets (if ASSETS bound) or pass through
    if (url.pathname === "/" || !url.pathname.startsWith("/api/")) {
      if (env.ASSETS && env.ASSETS.fetch) {
        const assetRes = await env.ASSETS.fetch(request);
        return applySecurityHeaders(assetRes, request, env);
      }
      return applySecurityHeaders(new Response("OK", { status: 200 }), request, env);
    }

    // -------- AUTH: mint detached signature for this exact request --------
    if (url.pathname === "/auth/issue") {
      if (method !== "POST") {
        return applySecurityHeaders(new Response("Method not allowed", { status: 405 }), request, env);
      }
      const out = await handleAuthIssue(request, env);
      return applySecurityHeaders(out, request, env);
    }

    // -------- CHAT --------
    if (url.pathname === "/api/chat") {
      if (method !== "POST") {
        return applySecurityHeaders(new Response(JSON.stringify({ error: "method_not_allowed" }), {
          status: 405, headers: { "content-type": "application/json; charset=UTF-8" }
        }), request, env);
      }
      const out = await handleChatRequest(request, env);
      return applySecurityHeaders(out, request, env);
    }

    // -------- STT --------
    if (url.pathname === "/api/stt") {
      if (method !== "POST") {
        return applySecurityHeaders(new Response(JSON.stringify({ error: "method_not_allowed" }), {
          status: 405, headers: { "content-type": "application/json; charset=UTF-8" }
        }), request, env);
      }
      const out = await handleSttRequest(request, env);
      return applySecurityHeaders(out, request, env);
    }

    return applySecurityHeaders(new Response(JSON.stringify({ error: "not_found" }), {
      status: 404, headers: { "content-type": "application/json; charset=UTF-8" }
    }), request, env);
  }
};

/* =============================== ROUTES =============================== */

async function handleAuthIssue(request, env) {
  // Header-level integrity (origin allowlist + gateway header)
  const gate = enforceIntegrityHeadersOnly(request, env);
  if (gate) return gate;

  if (!env.SHARED_KEY) {
    return json({ error: "Signature service unavailable" }, 500);
  }

  let payload;
  try {
    payload = await request.json();
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  const tsRaw     = payload?.ts ?? payload?.timestamp;
  const nonceRaw  = payload?.nonce;
  const methodRaw = payload?.method;
  const pathRaw   = payload?.path;
  const bodyShaRaw= payload?.body_sha256 ?? payload?.bodySha256;

  const timestamp = Number(tsRaw);
  const now = Math.floor(Date.now() / 1000);
  const ttl = getSignatureTtl(env);

  if (!Number.isFinite(timestamp)) return json({ error: "Invalid timestamp" }, 400);
  if (timestamp > now + 5 || now - timestamp > ttl) return json({ error: "Timestamp out of range" }, 400);

  const nonce = typeof nonceRaw === "string" ? nonceRaw.trim().toLowerCase() : "";
  if (!/^[a-f0-9]{32}$/.test(nonce)) return json({ error: "Invalid nonce" }, 400);

  const method = typeof methodRaw === "string" ? methodRaw.trim().toUpperCase() : "";
  if (method !== "POST") return json({ error: "Unsupported method" }, 400);

  const path = typeof pathRaw === "string" ? pathRaw.trim() : "";
  if (!path.startsWith("/api/")) return json({ error: "Invalid path" }, 400);

  const bodySha = typeof bodyShaRaw === "string" ? bodyShaRaw.trim().toLowerCase() : "";
  if (!/^[a-f0-9]{64}$/.test(bodySha)) return json({ error: "Invalid body digest" }, 400);

  // Pre-mark nonce at mint time (prevent re-issuing the same nonce quickly)
  if (env.OPS_NONCE_KV) {
    const mintKey = `mint:${nonce}:${timestamp}`;
    const exists = await env.OPS_NONCE_KV.get(mintKey);
    if (exists) return json({ error: "Nonce reuse detected" }, 409);
    await env.OPS_NONCE_KV.put(mintKey, "1", { expirationTtl: ttl });
  }

  const canonical = `${timestamp}.${nonce}.${method}.${path}.${bodySha}`;
  const signature = await hmacSha512B64(env.SHARED_KEY, canonical);
  const remaining = Math.max(0, ttl - Math.max(0, now - timestamp));

  return new Response(JSON.stringify({ signature, expires_in: remaining }), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store",
      "x-signature-ttl": String(ttl)
    }
  });
}

async function handleChatRequest(request, env) {
  // Full integrity: headers + detached signature verification + replay defense
  const gate = await enforceIntegrity(request, env, "/api/chat");
  if (gate) return gate;

  try {
    const body = await request.json();

    const honeypotHit = detectHoneypotInObject(body, env);
    if (honeypotHit) {
      await registerHoneypotBan(request, env, honeypotHit);
      return honeypotBlockedResponse(honeypotHit.reason);
    }

    const turnstileToken = extractTurnstileToken(body);
    const turnstileGate = await enforceTurnstile(turnstileToken, request, env);
    if (turnstileGate) return turnstileGate;

    const { messages = [], metadata } = body;

    const normalized = Array.isArray(messages)
      ? messages.filter(m => m && typeof m.content === "string" && m.content.trim())
      : [];

    // Policy guard
    const pol = evaluatePolicy(normalized);
    if (pol.blocked) return buildGuardedResponse(pol.reply, env);

    // Sanitize user content; keep roles
    const sanitizedMessages = normalized.map(m =>
      m.role === "user" ? { ...m, content: sanitizeText(m.content) } : m
    );

    const lastUserMessage = [...sanitizedMessages]
      .reverse()
      .find(m => m.role === "user");

    const defaultFlow = routeWebsiteDefaultFlow(lastUserMessage?.content || "");
    if (defaultFlow?.type === "kb") {
      return buildKnowledgeResponse(defaultFlow, env);
    }

    // Ensure system prompt present
    if (!sanitizedMessages.some(m => m.role === "system")) {
      sanitizedMessages.unshift({ role: "system", content: SYSTEM_PROMPT });
    }

    // Model selection (supports metadata.tier = "big" | "premium")
    const chatModel = selectChatModel(env, metadata);

    const aiResponse = await env.AI.run(chatModel, {
      messages: sanitizedMessages,
      max_tokens: getMaxTokens(env),
      temperature: 0.3,
      metadata
    });

    const reply =
      (typeof aiResponse === "string" && aiResponse) ||
      aiResponse?.response ||
      aiResponse?.result ||
      aiResponse?.output_text ||
      "I’m unable to respond right now.";

    const trimmed = String(reply).trim();
    const replyDigest = await sha512B64(trimmed);
    const integGateway = resolveIntegrityGateway(env);
    const integProtocols = resolveIntegrityProtocols(env);

    return new Response(JSON.stringify({
      reply: trimmed,
      model: chatModel,
      usage: aiResponse?.usage ?? null
    }), {
      status: 200,
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "cache-control": "no-store",
        "x-model": chatModel,
        "x-reply-digest-sha512": replyDigest,
        "x-integrity-gateway": integGateway,
        "x-integrity-protocols": integProtocols
      }
    });

  } catch (err) {
    return json({ error: "Failed to process request" }, 500);
  }
}

async function handleSttRequest(request, env) {
  // Full integrity (same as chat)
  const gate = await enforceIntegrity(request, env, "/api/stt");
  if (gate) return gate;

  try {
    const ct = request.headers.get("content-type") || "";
    if (!ct.toLowerCase().includes("multipart/form-data")) {
      return json({ error: "Expected multipart/form-data" }, 400);
    }

    const form = await request.formData();
    const honeypotHit = detectHoneypotInForm(form, env);
    if (honeypotHit) {
      await registerHoneypotBan(request, env, honeypotHit);
      return honeypotBlockedResponse(honeypotHit.reason);
    }

    const turnstileToken = extractTurnstileToken(form);
    const turnstileGate = await enforceTurnstile(turnstileToken, request, env);
    if (turnstileGate) return turnstileGate;

    const audio = form.get("audio");
    if (!(audio instanceof File)) return json({ error: "Audio blob missing" }, 400);

    const maxBytes = clampInt(env.MAX_AUDIO_BYTES, 8000000);
    if (audio.size > maxBytes) return json({ error: "Audio payload exceeds limit" }, 413);

    const buf = await audio.arrayBuffer();
    // Prefer raw bytes for Workers AI STT
    const bytes = new Uint8Array(buf);

    const locale = sanitizeLocale(String(form.get("lang") || ""));
    const prefer = String(form.get("prefer") || "").trim().toLowerCase();
    const model = selectSttModel(env, prefer);

    const aiResponse = await env.AI.run(model, {
      audio: [...bytes],
      language: locale
    });

    const transcript = extractTranscript(aiResponse);
    const clean = sanitizeText(transcript);
    const transcriptDigest = await sha512B64(clean);
    const integGateway = resolveIntegrityGateway(env);
    const integProtocols = resolveIntegrityProtocols(env);

    return new Response(JSON.stringify({ text: clean }), {
      status: 200,
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "cache-control": "no-store",
        "x-tier": aiResponse?.tier || "?",
        "x-model": model,
        "x-transcript-digest-sha512": transcriptDigest,
        "x-integrity-gateway": integGateway,
        "x-integrity-protocols": integProtocols
      }
    });

  } catch (err) {
    return json({ error: "Failed to transcribe audio" }, 500);
  }
}

/* ============================ INTEGRITY & CORS ============================ */

// Strict header checks (X-Integrity origin + gateway). Does NOT verify HMAC.
function enforceIntegrityHeadersOnly(request, env) {
  const allowedOrigins = buildAllowedOrigins(env);
  const provided = request.headers.get("x-integrity");
  const gateway  = request.headers.get("x-integrity-gateway");
  const expectedGateway = resolveIntegrityGateway(env);

  if (env.INTEGRITY_REQUIRED !== "true") return null;

  if (!provided || !allowedOrigins.includes(provided)) {
    return json({ error: "Integrity validation failed" }, 403);
  }
  if (gateway !== expectedGateway) {
    return json({ error: "Integrity gateway mismatch" }, 412);
  }
  return null;
}

// Full integrity: headers + detached signature verification + replay defense
async function enforceIntegrity(request, env, expectedPath) {
  // First the header allow-list & gateway
  const headerGate = enforceIntegrityHeadersOnly(request, env);
  if (headerGate) return headerGate;

  if (env.INTEGRITY_REQUIRED !== "true") return null;

  // Accept either X-Request-* or legacy X-OPS-* header names
  const sig   = request.headers.get("x-request-signature") || request.headers.get("x-ops-signature");
  const tsH   = request.headers.get("x-request-timestamp") || request.headers.get("x-ops-timestamp");
  const nonce = request.headers.get("x-request-nonce")      || request.headers.get("x-ops-nonce");

  if (!sig || !tsH || !nonce) return json({ error: "missing_sig_headers" }, 400);

  const ts = Number(tsH);
  const ttl = getSignatureTtl(env);
  const now = Math.floor(Date.now()/1000);
  if (!Number.isFinite(ts)) return json({ error: "bad_timestamp" }, 400);
  if (ts > now + 5 || now - ts > ttl) return json({ error: "expired" }, 400);

  // Replay defense: mark used at verification time
  if (env.OPS_NONCE_KV) {
    const usedKey = `used:${nonce}:${ts}`;
    const seen = await env.OPS_NONCE_KV.get(usedKey);
    if (seen) return json({ error: "replay" }, 409);
    await env.OPS_NONCE_KV.put(usedKey, "1", { expirationTtl: ttl });
  }

  // Compute body SHA-256 hex
  const bodyHex = await sha256HexOfRequest(request);
  const canonical = `${ts}.${nonce}.POST.${expectedPath}.${bodyHex}`;
  const expectedSig = await hmacSha512B64(env.SHARED_KEY, canonical);

  if (expectedSig !== sig) return json({ error: "bad_signature" }, 403);

  return null;
}

/* ================================ HELPERS ================================ */

function sanitizeText(input) {
  if (!input) return "";
  return String(input)
    .replace(/[^\x09\x0A\x0D\x20-\x7E\u00A0-\uFFFF]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function sanitizeLocale(input) {
  if (!input) return "en";
  const s = String(input).trim().toLowerCase();
  return /^[a-z]{2}(-[a-z]{2})?$/.test(s) ? s : "en";
}

function evaluatePolicy(messages) {
  if (!Array.isArray(messages) || messages.length === 0) return { blocked: false };

  const users = messages.filter(m => m.role === "user");
  if (!users.length) return { blocked: false };

  const lastUser = sanitizeText(users[users.length - 1].content);
  if (!lastUser) return { blocked: false };

  const lower = lastUser.toLowerCase();
  const looksBad = MALICIOUS_PATTERNS.some(re => re.test(lower));
  const onTopic  = WEBSITE_KEYWORDS.some(k => lower.includes(k));

  if (!looksBad && onTopic) return { blocked: false };

  const guardCount = messages.filter(m =>
    m.role === "assistant" &&
    (m.content.includes(WARNING_MESSAGE) || m.content.includes(TERMINATE_MESSAGE))
  ).length;

  if (guardCount >= 1) return { blocked: true, reply: TERMINATE_MESSAGE };
  return { blocked: true, reply: WARNING_MESSAGE };
}

async function buildGuardedResponse(reply, env) {
  const sanitized = (reply || WARNING_MESSAGE).trim();
  const digest = await sha512B64(sanitized);
  const gw = resolveIntegrityGateway(env);
  const protos = resolveIntegrityProtocols(env);
  return new Response(JSON.stringify({
    reply: sanitized,
    model: MODEL_ID,
    usage: null
  }), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store",
      "x-model": MODEL_ID,
      "x-reply-digest-sha512": digest,
      "x-integrity-gateway": gw,
      "x-integrity-protocols": protos
    }
  });
}

function routeWebsiteDefaultFlow(userMessage) {
  const query = sanitizeText(userMessage || "");
  if (!query) return null;

  const language = detectLanguage(query);
  const tokens = tokenize(query).filter(t => !STOP_WORDS[language]?.has(t));
  if (!tokens.length) return null;

  const candidates = WEBSITE_KB.filter(doc => doc.lang === language);
  if (!candidates.length) return null;

  let best = null;
  for (const doc of candidates) {
    const score = scoreDocumentBm25(doc, tokens);
    if (!best || score > best.score) {
      best = { doc, score };
    }
  }

  if (!best || best.score < DEFAULT_BM25_THRESHOLD) return null;

  const reply = buildWebsiteReply(best.doc, language);

  return {
    type: "kb",
    reply,
    docId: best.doc.id,
    title: best.doc.title,
    language,
    score: best.score
  };
}

async function buildKnowledgeResponse(flow, env) {
  const trimmed = String(flow.reply || "").trim();
  const digest = await sha512B64(trimmed);
  const integGateway = resolveIntegrityGateway(env);
  const integProtocols = resolveIntegrityProtocols(env);

  const usage = {
    source: flow.docId,
    title: flow.title,
    language: flow.language,
    confidence: Number(flow.score.toFixed(4))
  };

  return new Response(JSON.stringify({
    reply: trimmed,
    model: "bm25-website-default",
    usage
  }), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store",
      "x-model": "bm25-website-default",
      "x-reply-digest-sha512": digest,
      "x-integrity-gateway": integGateway,
      "x-integrity-protocols": integProtocols,
      "x-knowledge-source": flow.docId
    }
  });
}

function selectChatModel(env, metadata) {
  const tier = typeof metadata?.tier === "string" ? metadata.tier.toLowerCase() : "";
  if (tier === "big" && env.AI_LLM_BIG) return env.AI_LLM_BIG;
  if (tier === "premium" && env.AI_LLM_PREMIUM) return env.AI_LLM_PREMIUM;
  return env.AI_LLM_DEFAULT || MODEL_ID;
}

function scoreDocumentBm25(doc, queryTerms) {
  const k1 = 1.2;
  const b = 0.75;
  let score = 0;
  for (const term of queryTerms) {
    const freq = doc.termFreq.get(term);
    if (!freq) continue;
    const idf = computeIdf(term);
    const numerator = freq * (k1 + 1);
    const denominator = freq + k1 * (1 - b + b * (doc.length / (AVG_DOC_LENGTH || 1)));
    score += idf * (numerator / denominator);
  }
  return score;
}

function buildWebsiteReply(doc, language) {
  if (language === "es" && doc.summaryEs) return doc.summaryEs;
  if (language === "en" && doc.summaryEn) return doc.summaryEn;
  return doc.summary || doc.content;
}

function selectSttModel(env, prefer) {
  const fallback =
    env.AI_STT_TURBO ||
    env.AI_STT_BASE  ||
    env.AI_STT_TINY  ||
    env.AI_STT_VENDOR||
    "@cf/openai/whisper";

  switch (prefer) {
    case "tiny":   return env.AI_STT_TINY   || fallback;
    case "base":   return env.AI_STT_BASE   || fallback;
    case "turbo":  return env.AI_STT_TURBO  || fallback;
    case "vendor": return env.AI_STT_VENDOR || fallback;
    default:       return fallback;
  }
}

function getSignatureTtl(env) {
  const fallback = 300;
  const v = env.SIG_TTL_SECONDS ? Number(env.SIG_TTL_SECONDS) : NaN;
  if (!Number.isFinite(v) || v <= 0) return fallback;
  return Math.max(60, Math.min(900, Math.floor(v)));
}

function getMaxTokens(env) {
  const v = env.LLM_MAX_TOKENS ? Number(env.LLM_MAX_TOKENS) : NaN;
  if (!Number.isFinite(v) || v <= 0) return 768;
  return Math.min(1024, v);
}

/* ---------------------------- Security Headers --------------------------- */

function applySecurityHeaders(response, request, env) {
  const headers = new Headers(response.headers);

  const origin = request.headers.get("Origin");
  const allowedOrigin = getAllowedOrigin(origin, env);
  if (allowedOrigin) {
    headers.set("Access-Control-Allow-Origin", allowedOrigin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", mergeVary(headers.get("Vary"), "Origin"));
  }

  headers.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type, X-Integrity, X-Integrity-Gateway, X-Integrity-Protocols, X-Request-Signature, X-Request-Timestamp, X-Request-Nonce, X-OPS-Signature, X-OPS-Timestamp, X-OPS-Nonce"
  );
  headers.set("Access-Control-Max-Age", "600");

  // Tight baseline
  headers.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none';");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "same-origin");
  headers.set("Permissions-Policy", "microphone=(),camera=(),geolocation=()");
  headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");

  // Integrity headers echo
  const gw = resolveIntegrityGateway(env);
  const protos = resolveIntegrityProtocols(env);
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("X-OPS-CYSEC-CORE", "active");
  headers.set("X-Compliance-Frameworks", protos);
  headers.set("Integrity", gw);
  headers.set("X-Integrity-Gateway", gw);
  headers.set("X-Integrity-Protocols", protos);

  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function resolveIntegrityGateway(env) {
  const c = (env.INTEGRITY_GATEWAY || "").trim();
  return c || DEFAULT_INTEGRITY_GATEWAY;
}
function resolveIntegrityProtocols(env) {
  const c = (env.INTEGRITY_PROTOCOLS || "").trim();
  return c || DEFAULT_INTEGRITY_PROTOCOLS;
}

function getAllowedOrigin(origin, env) {
  if (!origin) return null;
  const normalized = origin.trim().toLowerCase();
  if (!normalized) return null;

  const allowWorkers = env.ALLOW_WORKERS_DEV === "true";
  const allowDash    = env.ALLOW_DASH === "true";

  const allow = buildAllowedOrigins(env);
  if (allow.includes(normalized)) return allow[allow.indexOf(normalized)];

  if (allowWorkers && isWorkersDevOrigin(normalized)) return origin;
  if (allowDash && isDashOrigin(normalized)) return origin;
  return null;
}

function buildAllowedOrigins(env) {
  const gw = resolveIntegrityGateway(env);
  const configured = (env.INTEGRITY_GATEWAY || "").trim();
  const set = new Set(BASE_ALLOWED_ORIGINS.map(s => s.toLowerCase()));
  set.add(gw.toLowerCase());
  if (configured) set.add(configured.toLowerCase());
  return Array.from(set);
}

function isWorkersDevOrigin(o) {
  try { return new URL(o).hostname.endsWith(".workers.dev"); }
  catch { return false; }
}
function isDashOrigin(o) {
  try { return new URL(o).hostname.endsWith(".dash.cloudflare.com"); }
  catch { return false; }
}
function mergeVary(existing, value) {
  if (!existing) return value;
  const parts = new Set(existing.split(",").map(p => p.trim()).filter(Boolean));
  parts.add(value);
  return Array.from(parts).join(", ");
}

/* ------------------------------- Crypto ---------------------------------- */

async function sha256HexOfRequest(request) {
  const buf = await request.arrayBuffer();
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function sha512B64(input) {
  const enc = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-512", enc);
  return b64(hash);
}

async function hmacSha512B64(secret, message) {
  if (!secret) throw new Error("missing_shared_key");
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-512" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return b64(sig);
}

function b64(bufferLike) {
  const u8 = bufferLike instanceof ArrayBuffer ? new Uint8Array(bufferLike) : new Uint8Array(bufferLike.buffer || bufferLike);
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}

/* ------------------------------- JSON util -------------------------------- */

function json(obj, status = 200, extra) {
  const h = { "content-type": "application/json; charset=UTF-8", ...(extra || {}) };
  return new Response(JSON.stringify(obj), { status, headers: h });
}

/* --------------------------- Transcript helpers --------------------------- */

function extractTranscript(res) {
  if (!res) return "";
  if (typeof res === "string") return res;
  if (typeof res.text === "string") return res.text;
  if (Array.isArray(res.results) && res.results[0]?.text) return res.results[0].text;
  if (typeof res.output_text === "string") return res.output_text;
  return "";
}

/* ------------------------------- Misc ------------------------------------- */

function clampInt(v, def) {
  const n = Number(v);
  return Number.isFinite(n) ? n : def;
}

/* ----------------------------- Honeypot guard ---------------------------- */

async function checkHoneypotBan(request, env) {
  const kv = getHoneypotKv(env);
  if (!kv) return null;

  const ip = getClientIp(request);
  if (!ip) return null;

  const key = `honeypot:block:${ip}`;
  const stored = await kv.get(key);
  if (!stored) return null;

  let parsed;
  try {
    parsed = JSON.parse(stored);
  } catch {
    parsed = { reason: String(stored || "honeypot"), expiresAt: null };
  }

  return {
    blocked: true,
    reason: parsed?.reason || "honeypot",
    until: parsed?.expiresAt || null
  };
}

async function registerHoneypotBan(request, env, detail) {
  const kv = getHoneypotKv(env);
  const ip = getClientIp(request);
  const ttl = getHoneypotBlockTtl(env);
  const reason = detail?.reason || `honeypot:${detail?.field || "unknown"}`;

  if (kv && ip) {
    const key = `honeypot:block:${ip}`;
    const now = Date.now();
    const expiresAt = now + ttl * 1000;
    const payload = JSON.stringify({
      reason,
      createdAt: now,
      expiresAt,
      field: detail?.field || null,
      snippet: detail?.snippet || null
    });
    await kv.put(key, payload, { expirationTtl: ttl });
  }

  return reason;
}

function honeypotBlockedResponse(reason, until) {
  const payload = {
    error: "access_denied",
    reason: reason || "honeypot"
  };
  if (until) payload.blocked_until = until;

  return json(payload, 403, {
    "cache-control": "no-store",
    "x-honeypot": "blocked",
    "x-block-reason": reason || "honeypot"
  });
}

function detectHoneypotInObject(obj, env) {
  if (!obj || typeof obj !== "object") return null;

  const fields = getHoneypotFieldNames(env);
  const stack = [obj];
  const seen = new Set();

  while (stack.length) {
    const current = stack.pop();
    if (!current || typeof current !== "object") continue;
    if (seen.has(current)) continue;
    seen.add(current);

    const entries = Array.isArray(current)
      ? current.entries()
      : Object.entries(current);

    for (const [keyRaw, value] of entries) {
      const key = typeof keyRaw === "string" ? keyRaw : String(keyRaw);
      const keyLower = key.toLowerCase();

      if (isHoneypotFieldName(keyLower, fields)) {
        if (isFilledHoneypotValue(value)) {
          return createHoneypotDetail(key, value);
        }
      }

      if (shouldTraverse(value)) {
        stack.push(value);
      }
    }
  }

  return null;
}

function detectHoneypotInForm(form, env) {
  if (!form || typeof form.get !== "function" || typeof form.getAll !== "function") {
    return null;
  }

  const fields = getHoneypotFieldNames(env);
  for (const name of form.keys()) {
    const fieldName = String(name);
    const lower = fieldName.toLowerCase();
    if (!isHoneypotFieldName(lower, fields)) continue;

    const all = form.getAll(name) || [];
    for (const entry of all) {
      if (typeof entry === "string" && entry.trim()) {
        return createHoneypotDetail(fieldName, entry);
      }
    }
  }

  return null;
}

function createHoneypotDetail(field, value) {
  const snippet = typeof value === "string"
    ? value.trim().slice(0, 64)
    : Array.isArray(value)
      ? value.map(v => String(v)).join(", ").slice(0, 64)
      : typeof value === "object"
        ? JSON.stringify(value).slice(0, 64)
        : String(value);

  return {
    field,
    reason: `honeypot:${field.toLowerCase()}`,
    snippet
  };
}

function isFilledHoneypotValue(value) {
  if (typeof value === "string") return value.trim().length > 0;
  if (typeof value === "number") return !Number.isNaN(value) && value !== 0;
  if (Array.isArray(value)) return value.some(v => isFilledHoneypotValue(v));
  if (shouldTraverse(value)) {
    return Object.values(value).some(v => isFilledHoneypotValue(v));
  }
  return false;
}

function getHoneypotFieldNames(env) {
  const fromEnv = (env?.HONEYPOT_FIELDS || "")
    .split(",")
    .map(s => s.trim().toLowerCase())
    .filter(Boolean);
  const merged = new Set([...DEFAULT_HONEYPOT_FIELDS, ...fromEnv]);
  return Array.from(merged);
}

function isHoneypotFieldName(name, allowlist) {
  if (!name) return false;
  if (allowlist.includes(name)) return true;
  if (name.includes("honeypot")) return true;
  if (name.includes("bot")) return true;
  if (name.includes("trap")) return true;
  return false;
}

function shouldTraverse(value) {
  if (!value) return false;
  if (Array.isArray(value)) return true;
  if (typeof value !== "object") return false;
  if (typeof File !== "undefined" && value instanceof File) return false;
  if (typeof Blob !== "undefined" && value instanceof Blob) return false;
  if (value instanceof ArrayBuffer) return false;
  if (ArrayBuffer.isView && ArrayBuffer.isView(value)) return false;
  if (typeof Response !== "undefined" && value instanceof Response) return false;
  if (typeof Request !== "undefined" && value instanceof Request) return false;
  if (typeof FormData !== "undefined" && value instanceof FormData) return false;
  if (typeof URLSearchParams !== "undefined" && value instanceof URLSearchParams) return false;

  const tag = Object.prototype.toString.call(value);
  return tag === "[object Object]" || tag === "[object Array]";
}

function getHoneypotKv(env) {
  return env?.OPS_BANLIST_KV || env?.HONEYPOT_KV || env?.OPS_NONCE_KV || null;
}

function getHoneypotBlockTtl(env) {
  const raw = env?.HONEYPOT_BLOCK_TTL;
  const num = Number(raw);
  if (!Number.isFinite(num) || num <= 0) return HONEYPOT_BLOCK_TTL_SECONDS;
  return Math.max(300, Math.min(604800, Math.floor(num))); // clamp between 5 min and 7 days
}

function getClientIp(request) {
  const headers = request.headers;
  const direct = headers.get("cf-connecting-ip");
  if (direct) return direct.trim();

  const forwarded = headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",").map(p => p.trim()).find(Boolean);
    if (first) return first;
  }

  const realIp = headers.get("x-real-ip");
  if (realIp) return realIp.trim();

  return null;
}

/* --------------------------- Turnstile validation ------------------------ */

function extractTurnstileToken(source) {
  const keys = [
    "cf-turnstile-response",
    "turnstile_response",
    "turnstile-token",
    "turnstile_token",
    "turnstileResponse",
    "turnstileToken",
    "turnstile"
  ];

  if (!source) return null;

  if (typeof FormData !== "undefined" && source instanceof FormData) {
    for (const key of keys) {
      const value = source.get(key);
      if (typeof value === "string" && value.trim()) return value.trim();
    }
    return null;
  }

  if (typeof source === "object") {
    for (const key of keys) {
      const value = source[key];
      if (typeof value === "string" && value.trim()) return value.trim();
    }

    if (source.metadata && typeof source.metadata === "object") {
      return extractTurnstileToken(source.metadata);
    }
  }

  return null;
}

async function enforceTurnstile(token, request, env) {
  const secret = (env?.TURNSTILE_SECRET || "").trim();
  if (!secret) return null;

  let resolved = typeof token === "string" ? token.trim() : "";
  if (!resolved) {
    const headerToken = request.headers.get("cf-turnstile-response") || request.headers.get("x-turnstile-token");
    if (headerToken) resolved = headerToken.trim();
  }

  if (!resolved) {
    return json({ error: "turnstile_required" }, 403, {
      "cache-control": "no-store",
      "x-turnstile": "missing"
    });
  }

  const params = new URLSearchParams();
  params.set("secret", secret);
  params.set("response", resolved);
  const ip = getClientIp(request);
  if (ip) params.set("remoteip", ip);

  let result;
  try {
    const verify = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: params,
      headers: { "content-type": "application/x-www-form-urlencoded" }
    });

    if (!verify.ok) {
      return json({ error: "turnstile_unreachable" }, 502, {
        "cache-control": "no-store",
        "x-turnstile": String(verify.status)
      });
    }

    result = await verify.json();
  } catch (err) {
    return json({ error: "turnstile_error" }, 500, {
      "cache-control": "no-store",
      "x-turnstile": "exception"
    });
  }

  if (!result?.success) {
    const codes = Array.isArray(result?.["error-codes"]) ? result["error-codes"].join(",") : "failed";
    return json({ error: "turnstile_failed", code: codes }, 403, {
      "cache-control": "no-store",
      "x-turnstile": codes || "failed"
    });
  }

  return null;
}
