const MODEL_ID = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
const DEFAULT_INTEGRITY_GATEWAY =
  "https://withered-mouse-9aee.grabem-holdem-nuts-right.workers.dev";
const BASE_ALLOWED_ORIGINS = ["https://chattiavato-a11y.github.io"];
const DEFAULT_INTEGRITY_PROTOCOLS =
  "CORS,CSP,OPS-CySec-Core,CISA,NIST,PCI-DSS,SHA-384,SHA-512";
const SYSTEM_PROMPT = `You are Chattia, an empathetic, security-aware assistant that
communicates with clarity and inclusive language. Deliver responses that are concise,
actionable, and aligned with human-computer interaction (HCI) best practices. Provide
step-by-step support when helpful, highlight important cautions, and remain compliant
with accessibility and privacy expectations.`;

const WARNING_MESSAGE =
  "Apologies, but I cannot execute that request, do you have any questions about our website?";
const TERMINATE_MESSAGE =
  "Apologies, but I must not continue with this chat and I must end this session.";

const MALICIOUS_PATTERNS: RegExp[] = [
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
  "website",
  "site",
  "chattia",
  "product",
  "service",
  "support",
  "order",
  "account",
  "pricing",
  "contact",
  "help"
];

interface Env {
  AI: {
    run<T = unknown>(
      model: string,
      body: Record<string, unknown>,
      options?: Record<string, unknown>
    ): Promise<T>;
  };
  ASSETS: {
    fetch(request: Request): Promise<Response>;
  };
  INTEGRITY_REQUIRED?: string;
  MAX_AUDIO_BYTES?: string;
  LLM_MAX_TOKENS?: string;
  AI_LLM_DEFAULT?: string;
  AI_LLM_BIG?: string;
  AI_LLM_PREMIUM?: string;
  AI_STT_TINY?: string;
  AI_STT_BASE?: string;
  AI_STT_TURBO?: string;
  AI_STT_VENDOR?: string;
  UI_ORIGIN_PRIMARY_SECRET?: string;
  UI_ORIGIN_SECONDARY_SECRET?: string;
  ALLOW_WORKERS_DEV?: string;
  ALLOW_DASH?: string;
  INTEGRITY_GATEWAY?: string;
  INTEGRITY_PROTOCOLS?: string;
  OPS_NONCE_KV?: KVNamespace;
  SIG_TTL_SECONDS?: string;
  SHARED_KEY?: string;
}

type Message = {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
};

interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
}

export default {
  /**
   * Main request handler for the Worker
   */
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/") && request.method === "OPTIONS") {
      const preflight = new Response(null, { status: 204 });
      return applySecurityHeaders(preflight, request, env);
    }

    if (url.pathname === "/" || !url.pathname.startsWith("/api/")) {
      const assetResponse = await env.ASSETS.fetch(request);
      return applySecurityHeaders(assetResponse, request, env);
    }

    if (url.pathname === "/auth/issue") {
      if (request.method === "POST") {
        const authResponse = await handleAuthIssue(request, env);
        return applySecurityHeaders(authResponse, request, env);
      }
      return applySecurityHeaders(
        new Response("Method not allowed", { status: 405 }),
        request,
        env
      );
    }

    if (url.pathname === "/api/chat") {
      if (request.method === "POST") {
        const chatResponse = await handleChatRequest(request, env);
        return applySecurityHeaders(chatResponse, request, env);
      }
      return applySecurityHeaders(
        new Response("Method not allowed", { status: 405 }),
        request,
        env
      );
    }

    if (url.pathname === "/api/stt") {
      if (request.method === "POST") {
        const sttResponse = await handleSttRequest(request, env);
        return applySecurityHeaders(sttResponse, request, env);
      }
      return applySecurityHeaders(
        new Response("Method not allowed", { status: 405 }),
        request,
        env
      );
    }

    return applySecurityHeaders(
      new Response("Not found", { status: 404 }),
      request,
      env
    );
  },
};

async function handleAuthIssue(request: Request, env: Env): Promise<Response> {
  const integrityFailure = enforceIntegrity(request, env);
  if (integrityFailure) {
    return integrityFailure;
  }

  if (!env.SHARED_KEY) {
    return new Response(
      JSON.stringify({ error: "Signature service unavailable" }),
      {
        status: 500,
        headers: { "content-type": "application/json; charset=UTF-8" },
      }
    );
  }

  let payload: any;
  try {
    payload = await request.json();
  } catch (error) {
    console.warn("Invalid JSON for auth issue request", error);
    return new Response(JSON.stringify({ error: "Invalid JSON" }), {
      status: 400,
      headers: { "content-type": "application/json; charset=UTF-8" },
    });
  }

  const tsRaw = payload?.ts ?? payload?.timestamp;
  const nonceRaw = payload?.nonce;
  const methodRaw = payload?.method;
  const pathRaw = payload?.path;
  const bodyShaRaw = payload?.body_sha256 ?? payload?.bodySha256;

  const timestamp = Number(tsRaw);
  const now = Math.floor(Date.now() / 1000);
  const ttl = getSignatureTtl(env);

  if (!Number.isFinite(timestamp)) {
    return new Response(JSON.stringify({ error: "Invalid timestamp" }), {
      status: 400,
      headers: { "content-type": "application/json; charset=UTF-8" },
    });
  }

  if (timestamp > now + 5 || now - timestamp > ttl) {
    return new Response(JSON.stringify({ error: "Timestamp out of range" }), {
      status: 400,
      headers: { "content-type": "application/json; charset=UTF-8" },
    });
  }

  const nonce = typeof nonceRaw === "string" ? nonceRaw.trim().toLowerCase() : "";
  if (!/^[a-f0-9]{32}$/.test(nonce)) {
    return new Response(JSON.stringify({ error: "Invalid nonce" }), {
      status: 400,
      headers: { "content-type": "application/json; charset=UTF-8" },
    });
  }

  const method = typeof methodRaw === "string" ? methodRaw.trim().toUpperCase() : "";
  if (!method || method !== "POST") {
    return new Response(JSON.stringify({ error: "Unsupported method" }), {
      status: 400,
      headers: { "content-type": "application/json; charset=UTF-8" },
    });
  }

  const path = typeof pathRaw === "string" ? pathRaw.trim() : "";
  if (!path.startsWith("/api/")) {
    return new Response(JSON.stringify({ error: "Invalid path" }), {
      status: 400,
      headers: { "content-type": "application/json; charset=UTF-8" },
    });
  }

  const bodySha =
    typeof bodyShaRaw === "string" ? bodyShaRaw.trim().toLowerCase() : "";
  if (!/^[a-f0-9]{64}$/.test(bodySha)) {
    return new Response(JSON.stringify({ error: "Invalid body digest" }), {
      status: 400,
      headers: { "content-type": "application/json; charset=UTF-8" },
    });
  }

  const kv = env.OPS_NONCE_KV;
  if (kv) {
    const nonceKey = `${nonce}:${timestamp}`;
    try {
      const existing = await kv.get(nonceKey);
      if (existing) {
        return new Response(JSON.stringify({ error: "Nonce reuse detected" }), {
          status: 409,
          headers: { "content-type": "application/json; charset=UTF-8" },
        });
      }
      await kv.put(nonceKey, "1", { expirationTtl: ttl });
    } catch (error) {
      console.error("KV error enforcing nonce integrity", error);
      return new Response(
        JSON.stringify({ error: "Nonce integrity unavailable" }),
        {
          status: 500,
          headers: { "content-type": "application/json; charset=UTF-8" },
        }
      );
    }
  }

  const canonical = `${timestamp}.${nonce}.${method}.${path}.${bodySha}`;
  const signature = await createHmacSha512Base64(env.SHARED_KEY, canonical);
  const remaining = Math.max(0, ttl - Math.max(0, now - timestamp));

  return new Response(JSON.stringify({ signature, expires_in: remaining }), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store",
      "x-signature-ttl": String(ttl),
    },
  });
}

async function handleChatRequest(request: Request, env: Env): Promise<Response> {
  const integrityFailure = enforceIntegrity(request, env);
  if (integrityFailure) {
    return integrityFailure;
  }

  try {
    const { messages = [], metadata } = await request.json<{
      messages?: Message[];
      metadata?: Record<string, unknown>;
    }>();

    const normalizedMessages: Message[] = Array.isArray(messages)
      ? messages.filter((msg): msg is Message =>
          Boolean(msg && typeof msg.content === "string" && msg.content.trim())
        )
      : [];

    const policyCheck = evaluatePolicy(normalizedMessages);
    if (policyCheck.blocked) {
      return buildGuardedResponse(policyCheck.reply, env);
    }

    const sanitizedMessages = normalizedMessages.map((msg) =>
      msg.role === "user"
        ? { ...msg, content: sanitizeText(msg.content) }
        : msg
    );

    if (!normalizedMessages.some((msg) => msg.role === "system")) {
      sanitizedMessages.unshift({ role: "system", content: SYSTEM_PROMPT });
    }

    const chatModel = selectChatModel(env, metadata);

    const aiResponse: any = await env.AI.run(chatModel, {
      messages: sanitizedMessages,
      max_tokens: getMaxTokens(env),
      temperature: 0.3,
      metadata,
    });

    const reply =
      (typeof aiResponse === "string" && aiResponse) ||
      aiResponse?.response ||
      aiResponse?.result ||
      aiResponse?.output_text ||
      "I’m unable to respond right now.";

    const trimmedReply = reply.trim();
    const replyDigest = await digestSha512Base64(trimmedReply);
    const integrityGateway = resolveIntegrityGateway(env);
    const integrityProtocols = resolveIntegrityProtocols(env);
    const body = JSON.stringify({
      reply: trimmedReply,
      model: chatModel,
      usage: aiResponse?.usage ?? null,
    });

    return new Response(body, {
      status: 200,
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "cache-control": "no-store",
        "x-model": chatModel,
        "x-reply-digest-sha512": replyDigest,
        "x-integrity-gateway": integrityGateway,
        "x-integrity-protocols": integrityProtocols,
      },
    });
  } catch (error) {
    console.error("Error processing chat request:", error);
    return new Response(
      JSON.stringify({ error: "Failed to process request" }),
      {
        status: 500,
        headers: { "content-type": "application/json" },
      }
    );
  }
}

function sanitizeText(input: string): string {
  if (!input) return "";
  return String(input)
    .replace(/[^\x09\x0A\x0D\x20-\x7E\u00A0-\uFFFF]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function sanitizeLocale(input: string | null | undefined): string {
  if (!input) return "en";
  const trimmed = input.trim().toLowerCase();
  return /^[a-z]{2}(-[a-z]{2})?$/.test(trimmed) ? trimmed : "en";
}

function evaluatePolicy(messages: Message[]): { blocked: boolean; reply?: string } {
  if (!messages.length) {
    return { blocked: false };
  }

  const userMessages = messages.filter((msg) => msg.role === "user");
  if (!userMessages.length) {
    return { blocked: false };
  }

  const lastUser = sanitizeText(userMessages[userMessages.length - 1].content);
  if (!lastUser) {
    return { blocked: false };
  }

  const lower = lastUser.toLowerCase();
  const looksMalicious = MALICIOUS_PATTERNS.some((pattern) => pattern.test(lower));
  const onTopic = WEBSITE_KEYWORDS.some((keyword) => lower.includes(keyword));

  if (!looksMalicious && onTopic) {
    return { blocked: false };
  }

  const guardCount = messages.filter(
    (msg) =>
      msg.role === "assistant" &&
      (msg.content.includes(WARNING_MESSAGE) ||
        msg.content.includes(TERMINATE_MESSAGE))
  ).length;

  if (guardCount >= 1) {
    return { blocked: true, reply: TERMINATE_MESSAGE };
  }

  return { blocked: true, reply: WARNING_MESSAGE };
}

async function buildGuardedResponse(
  reply = WARNING_MESSAGE,
  env: Env
): Promise<Response> {
  const sanitizedReply = reply.trim() || WARNING_MESSAGE;
  const replyDigest = await digestSha512Base64(sanitizedReply);
  const integrityGateway = resolveIntegrityGateway(env);
  const integrityProtocols = resolveIntegrityProtocols(env);
  const body = JSON.stringify({
    reply: sanitizedReply,
    model: MODEL_ID,
    usage: null,
  });

  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store",
      "x-model": MODEL_ID,
      "x-reply-digest-sha512": replyDigest,
      "x-integrity-gateway": integrityGateway,
      "x-integrity-protocols": integrityProtocols,
    },
  });
}

function enforceIntegrity(request: Request, env: Env): Response | null {
  if (env.INTEGRITY_REQUIRED !== "true") {
    return null;
  }

  const headerName = "x-integrity";
  const provided = request.headers.get(headerName);
  const gateway = request.headers.get("x-integrity-gateway");
  const expectedGateway = resolveIntegrityGateway(env);
  const allowed = [
    env.UI_ORIGIN_PRIMARY_SECRET,
    env.UI_ORIGIN_SECONDARY_SECRET,
  ].filter((value): value is string => Boolean(value));

  if (!allowed.length) {
    return new Response(
      JSON.stringify({ error: "Integrity enforcement misconfigured" }),
      {
        status: 500,
        headers: { "content-type": "application/json; charset=UTF-8" },
      }
    );
  }

  if (gateway !== expectedGateway) {
    return new Response(
      JSON.stringify({ error: "Integrity gateway mismatch" }),
      {
        status: 412,
        headers: { "content-type": "application/json; charset=UTF-8" },
      }
    );
  }

  if (!provided || !allowed.includes(provided)) {
    return new Response(
      JSON.stringify({ error: "Integrity validation failed" }),
      {
        status: 403,
        headers: { "content-type": "application/json; charset=UTF-8" },
      }
    );
  }

  return null;
}

function getSignatureTtl(env: Env): number {
  const fallback = 300;
  const configured = env.SIG_TTL_SECONDS ? Number(env.SIG_TTL_SECONDS) : NaN;
  if (!Number.isFinite(configured) || configured <= 0) {
    return fallback;
  }
  return Math.max(60, Math.min(900, Math.floor(configured)));
}

function getMaxTokens(env: Env): number {
  const configured = env.LLM_MAX_TOKENS ? Number(env.LLM_MAX_TOKENS) : NaN;
  if (!Number.isFinite(configured) || configured <= 0) {
    return 768;
  }
  return Math.min(1024, configured);
}

function selectChatModel(
  env: Env,
  metadata: Record<string, unknown> | undefined
): string {
  const requested =
    typeof metadata?.tier === "string" ? metadata.tier.toLowerCase() : "";

  if (requested === "big" && env.AI_LLM_BIG) {
    return env.AI_LLM_BIG;
  }

  if (requested === "premium" && env.AI_LLM_PREMIUM) {
    return env.AI_LLM_PREMIUM;
  }

  return env.AI_LLM_DEFAULT || MODEL_ID;
}

async function handleSttRequest(request: Request, env: Env): Promise<Response> {
  const integrityFailure = enforceIntegrity(request, env);
  if (integrityFailure) {
    return integrityFailure;
  }

  try {
    const contentType = request.headers.get("content-type") || "";
    if (!contentType.toLowerCase().includes("multipart/form-data")) {
      return new Response(
        JSON.stringify({ error: "Expected multipart/form-data" }),
        {
          status: 400,
          headers: { "content-type": "application/json; charset=UTF-8" },
        }
      );
    }

    const formData = await request.formData();
    const audio = formData.get("audio");
    if (!(audio instanceof File)) {
      return new Response(
        JSON.stringify({ error: "Audio blob missing" }),
        {
          status: 400,
          headers: { "content-type": "application/json; charset=UTF-8" },
        }
      );
    }

    const maxBytes = env.MAX_AUDIO_BYTES ? Number(env.MAX_AUDIO_BYTES) : 8_000_000;
    if (audio.size > maxBytes) {
      return new Response(
        JSON.stringify({ error: "Audio payload exceeds limit" }),
        {
          status: 413,
          headers: { "content-type": "application/json; charset=UTF-8" },
        }
      );
    }

    const arrayBuffer = await audio.arrayBuffer();
    const base64Audio = arrayBufferToBase64(arrayBuffer);
    const locale = sanitizeLocale(String(formData.get("lang") || ""));
    const prefer = String(formData.get("prefer") || "").trim().toLowerCase();
    const model = selectSttModel(env, prefer);

    const aiResponse: any = await env.AI.run(model, {
      audio: [
        {
          data: base64Audio,
          type: audio.type || "audio/webm",
        },
      ],
      language: locale,
    });

    const transcript = extractTranscript(aiResponse);
    const sanitized = sanitizeText(transcript);
    const transcriptDigest = await digestSha512Base64(sanitized);
    const integrityGateway = resolveIntegrityGateway(env);
    const integrityProtocols = resolveIntegrityProtocols(env);

    return new Response(JSON.stringify({ text: sanitized }), {
      status: 200,
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "cache-control": "no-store",
        "x-tier": aiResponse?.tier || "?",
        "x-model": model,
        "x-transcript-digest-sha512": transcriptDigest,
        "x-integrity-gateway": integrityGateway,
        "x-integrity-protocols": integrityProtocols,
      },
    });
  } catch (error) {
    console.error("Error processing STT request:", error);
    return new Response(
      JSON.stringify({ error: "Failed to transcribe audio" }),
      {
        status: 500,
        headers: { "content-type": "application/json; charset=UTF-8" },
      }
    );
  }
}

function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return bufferToBase64(buffer);
}

function selectSttModel(env: Env, prefer: string): string {
  const fallback =
    env.AI_STT_TURBO ||
    env.AI_STT_BASE ||
    env.AI_STT_TINY ||
    env.AI_STT_VENDOR ||
    "@cf/openai/whisper";

  switch (prefer) {
    case "tiny":
      return env.AI_STT_TINY || fallback;
    case "base":
      return env.AI_STT_BASE || fallback;
    case "turbo":
      return env.AI_STT_TURBO || fallback;
    case "vendor":
      return env.AI_STT_VENDOR || fallback;
    default:
      return fallback;
  }
}

function extractTranscript(aiResponse: any): string {
  if (!aiResponse) {
    return "";
  }

  if (typeof aiResponse === "string") {
    return aiResponse;
  }

  if (typeof aiResponse.text === "string") {
    return aiResponse.text;
  }

  if (Array.isArray(aiResponse.results) && aiResponse.results[0]?.text) {
    return aiResponse.results[0].text;
  }

  if (typeof aiResponse.output_text === "string") {
    return aiResponse.output_text;
  }

  return "";
}

async function createHmacSha512Base64(
  secret: string,
  message: string
): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign"]
  );
  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    encoder.encode(message)
  );
  return bufferToBase64(signatureBuffer);
}

async function digestSha512Base64(input: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest("SHA-512", data);
  return bufferToBase64(hashBuffer);
}

function getAllowedOrigin(origin: string | null, env: Env): string | null {
  if (!origin) {
    return null;
  }

  const trimmed = origin.trim();
  if (!trimmed) {
    return null;
  }

  const normalized = trimmed.toLowerCase();
  const allowWorkersDev = env.ALLOW_WORKERS_DEV === "true";
  const allowDash = env.ALLOW_DASH === "true";

  const allowedOrigins = buildAllowedOrigins(env);
  const match = allowedOrigins.find(
    (allowedOrigin) => allowedOrigin.toLowerCase() === normalized
  );
  if (match) {
    return match;
  }

  if (allowWorkersDev && isWorkersDevOrigin(normalized)) {
    return origin;
  }

  if (allowDash && isDashOrigin(normalized)) {
    return origin;
  }

  return null;
}

function buildAllowedOrigins(env: Env): string[] {
  const integrityGateway = resolveIntegrityGateway(env);
  const configured = env.INTEGRITY_GATEWAY?.trim();
  const origins = new Set<string>(BASE_ALLOWED_ORIGINS);
  origins.add(DEFAULT_INTEGRITY_GATEWAY);
  origins.add(integrityGateway);
  if (configured) {
    origins.add(configured);
  }
  return Array.from(origins);
}

function isWorkersDevOrigin(origin: string): boolean {
  try {
    const url = new URL(origin);
    return url.hostname.endsWith(".workers.dev");
  } catch (error) {
    console.warn("Unable to parse origin", origin, error);
    return false;
  }
}

function isDashOrigin(origin: string): boolean {
  try {
    const url = new URL(origin);
    return url.hostname.endsWith(".dash.cloudflare.com");
  } catch (error) {
    console.warn("Unable to parse dash origin", origin, error);
    return false;
  }
}

function mergeVary(existing: string | null, value: string): string {
  if (!existing) {
    return value;
  }

  const parts = new Set(
    existing
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean)
  );
  parts.add(value);
  return Array.from(parts).join(", ");
}

function applySecurityHeaders(
  response: Response,
  request: Request,
  env: Env
): Response {
  const headers = new Headers(response.headers);

  const origin = request.headers.get("Origin");
  const allowedOrigin = getAllowedOrigin(origin, env);
  if (allowedOrigin) {
    headers.set("Access-Control-Allow-Origin", allowedOrigin);
    headers.set(
      "Vary",
      mergeVary(headers.get("Vary"), "Origin")
    );
    headers.set("Access-Control-Allow-Credentials", "true");
  }

  headers.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type, X-Integrity, X-Integrity-Gateway, X-Integrity-Protocols"
  );
  headers.set("Access-Control-Max-Age", "600");
  headers.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none';");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "same-origin");
  headers.set("Permissions-Policy", "microphone=(),camera=(),geolocation=()");
  headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  const integrityGateway = resolveIntegrityGateway(env);
  const integrityProtocols = resolveIntegrityProtocols(env);
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("X-OPS-CYSEC-CORE", "active");
  headers.set("X-Compliance-Frameworks", integrityProtocols);
  headers.set("Integrity", integrityGateway);
  headers.set("X-Integrity-Gateway", integrityGateway);
  headers.set("X-Integrity-Protocols", integrityProtocols);

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function resolveIntegrityGateway(env: Env): string {
  const configured = env.INTEGRITY_GATEWAY?.trim();
  if (configured) {
    return configured;
  }
  return DEFAULT_INTEGRITY_GATEWAY;
}

function resolveIntegrityProtocols(env: Env): string {
  const configured = env.INTEGRITY_PROTOCOLS?.trim();
  if (configured) {
    return configured;
  }
  return DEFAULT_INTEGRITY_PROTOCOLS;
}
