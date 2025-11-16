// src/worker.js — Integrity Gateway + Chat + STT + Escalation (single Worker)
import { SERVICE_DIRECTORY, SERVICE_DIRECTORY_PROMPT } from "../services/directory.js";

/* ---------- Config ---------- */
const MODEL_ID = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
const DEFAULT_INTEGRITY_VALUE = "https://chattiavato-a11y.github.io";
const DEFAULT_INTEGRITY_GATEWAY = "https://withered-mouse-9aee.grabem-holdem-nuts-right.workers.dev";
const DEFAULT_HIGH_CONFIDENCE_URL = "https://ops-chattia-api.grabem-holdem-nuts-right.workers.dev/";
const BASE_ALLOWED_ORIGINS = ["https://chattiavato-a11y.github.io"];
const DEFAULT_INTEGRITY_PROTOCOLS = "CORS,CSP,OPS-CySec-Core,CISA,NIST,PCI-DSS,SHA-384,SHA-512";
const DEFAULT_HONEYPOT_FIELDS = ["hp_email","hp_name","hp_field","honeypot","hp_text","botcheck","bot_field","trap_field","company"];
const HONEYPOT_BLOCK_TTL_SECONDS = 86400; // 24h

/* ---------- Governance ---------- */
const SYSTEM_PROMPT =
  "You are Chattia, an empathetic, security-aware assistant that communicates with clarity and inclusive language. " +
  "Deliver concise, actionable answers aligned with OPS Core CyberSec governance. Provide step-by-step help when useful, " +
  "call out safety cautions, respect accessibility and privacy expectations, and tie every insight back to the OPS Remote " +
  "Professional Network service directory pillars or solutions when relevant.";

const WARNING_MESSAGE   = "Apologies, but I cannot execute that request, do you have any questions about our website?";
const TERMINATE_MESSAGE = "Apologies, but I must not continue with this chat and I must end this session.";
const MALICIOUS_PATTERNS = [/<[^>]*>/i,/script/i,/malicious/i,/attack/i,/ignore/i,/prompt/i,/hack/i,/drop\s+table/i];
const SECURITY_THREAT_PATTERNS = [
  /<script/i,
  /javascript:/i,
  /onerror\s*=|onload\s*=/i,
  /data:text\/html/i,
  /union\s+select/i,
  /drop\s+table/i,
  /xss|csrf|sql\s+injection|sniffing|spoofing|phishing|clon(e|ing)|malware/i
];
const SECURITY_ALERT_MESSAGES = Object.freeze({
  en: "Security sweep blocked suspicious instructions. Please restate your OPS request without code or exploits.",
  es: "El barrido de seguridad bloqueó instrucciones sospechosas. Reformula tu solicitud OPS sin código ni exploits."
});
const WEBSITE_KEYWORDS   = ["website","site","chattia","product","service","support","order","account","pricing","contact","help"];

/* ---------- Minimal BM25-ish website KB ---------- */
const WEBSITE_KB = buildWebsiteKb();
const STOP_WORDS = {
  en: new Set("a,about,an,and,are,as,at,be,by,for,from,how,in,is,it,of,on,or,our,that,the,their,to,we,what,when,with,can".split(",")),
  es: new Set("a,al,como,con,de,del,el,ella,ellas,ellos,en,es,esta,este,las,los,para,por,que,se,son,su,sus,un,una,y,puede".split(","))
};
const AVG_DOC_LENGTH = WEBSITE_KB.reduce((s,d)=>s+d.content.split(/\s+/).length,0)/(WEBSITE_KB.length||1);

/* ======================================================================= */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    // Preflight for auth/health/fallback paths
    if ((url.pathname.startsWith("/auth/") || url.pathname.startsWith("/health/") || url.pathname.startsWith("/fallback/")) && method === "OPTIONS") {
      return applySecurityHeaders(new Response(null, { status: 204 }), request, env);
    }

    // CORS preflight for /api/*
    if (url.pathname.startsWith("/api/") && method === "OPTIONS") {
      return applySecurityHeaders(new Response(null,{status:204}), request, env);
    }

    // Health probes
    if (url.pathname === "/health" || url.pathname === "/health/ok") {
      return applySecurityHeaders(json({ ok:true }), request, env);
    }
    if (url.pathname === "/health/origin") {
      const origin = request.headers.get("Origin") || "";
      const allowed = getAllowedOrigin(origin, env);
      return applySecurityHeaders(json({ ok:true, reqOrigin: origin, allowedNow: Boolean(allowed) }), request, env);
    }
    if (url.pathname === "/health/summary") {
      const ttl = getSignatureTtl(env);
      return applySecurityHeaders(json({
        ok:true,
        signature_ttl: ttl,
        gateway: resolveIntegrityGateway(env),
        protocols: resolveIntegrityProtocols(env),
        allowed_origins: buildAllowedOrigins(env)
      }), request, env);
    }

    // Root or non-API (just OK)
    if (url.pathname === "/" || !url.pathname.startsWith("/api/") && !url.pathname.startsWith("/auth/") && !url.pathname.startsWith("/fallback/")) {
      return applySecurityHeaders(new Response("OK",{status:200}), request, env);
    }

    // Detached signature mint
    if (url.pathname === "/auth/issue") {
      if (method !== "POST") return applySecurityHeaders(json({error:"method_not_allowed"},405), request, env);
      const out = await handleAuthIssue(request, env);
      return applySecurityHeaders(out, request, env);
    }

    // Chat
    if (url.pathname === "/api/chat") {
      if (method !== "POST") return applySecurityHeaders(json({error:"method_not_allowed"},405), request, env);
      const out = await handleChatRequest(request, env);
      return applySecurityHeaders(out, request, env);
    }

    // STT
    if (url.pathname === "/api/stt") {
      if (method !== "POST") return applySecurityHeaders(json({error:"method_not_allowed"},405), request, env);
      const out = await handleSttRequest(request, env);
      return applySecurityHeaders(out, request, env);
    }

    // Client-side fallback escalation telemetry
    if (url.pathname === "/fallback/escalate") {
      if (method !== "POST") return applySecurityHeaders(json({ error: "method_not_allowed" }, 405), request, env);
      const gate = enforceIntegrityHeadersOnly(request, env);
      if (gate) return applySecurityHeaders(gate, request, env);
      let payload = {};
      try { payload = await request.json(); }
      catch { return applySecurityHeaders(json({ error: "Invalid JSON" }, 400), request, env); }
      await forwardEscalation({
        ...payload,
        gateway: "ops-integrity-gateway",
        timestamp: payload.timestamp || new Date().toISOString()
      }, env).catch(()=>{});
      return applySecurityHeaders(json({ escalated:true }), request, env);
    }

    return applySecurityHeaders(json({error:"not_found"},404), request, env);
  }
};

/* =========================== AUTH: /auth/issue =========================== */
async function handleAuthIssue(request, env) {
  const headerGate = enforceIntegrityHeadersOnly(request, env);
  if (headerGate) return headerGate;
  if (!env.SHARED_KEY) return json({error:"Signature service unavailable"},500);

  let payload;
  try { payload = await request.json(); } catch { return json({error:"Invalid JSON"},400); }

  const tsRaw     = payload?.ts ?? payload?.timestamp;
  const nonceRaw  = payload?.nonce;
  const methodRaw = payload?.method;
  const pathRaw   = payload?.path;
  const bodyShaRaw= payload?.body_sha256 ?? payload?.bodySha256;

  const ts = Number(tsRaw);
  const now = Math.floor(Date.now()/1000);
  const ttl = getSignatureTtl(env);
  if (!Number.isFinite(ts)) return json({error:"Invalid timestamp"},400);
  if (ts > now + 5 || now - ts > ttl) return json({error:"Timestamp out of range"},400);

  const nonce = typeof nonceRaw === "string" ? nonceRaw.trim().toLowerCase() : "";
  if (!/^[a-f0-9]{32}$/.test(nonce)) return json({error:"Invalid nonce"},400);

  const method = typeof methodRaw === "string" ? methodRaw.trim().toUpperCase() : "";
  if (method !== "POST") return json({error:"Unsupported method"},400);

  const path = typeof pathRaw === "string" ? pathRaw.trim() : "";
  if (!path.startsWith("/api/")) return json({error:"Invalid path"},400);

  const bodySha = typeof bodyShaRaw === "string" ? bodyShaRaw.trim().toLowerCase() : "";
  if (!/^[a-f0-9]{64}$/.test(bodySha)) return json({error:"Invalid body digest"},400);

  if (env.OPS_NONCE_KV) {
    const mintKey = `mint:${nonce}:${ts}`;
    const exists = await env.OPS_NONCE_KV.get(mintKey);
    if (exists) return json({error:"Nonce reuse detected"},409);
    await env.OPS_NONCE_KV.put(mintKey,"1",{expirationTtl:ttl});
  }

  const canonical = `${ts}.${nonce}.${method}.${path}.${bodySha}`;
  const signature = await hmacSha512B64(env.SHARED_KEY, canonical);
  const remaining = Math.max(0, ttl - Math.max(0, now - ts));

  return new Response(JSON.stringify({signature, expires_in: remaining}), {
    status:200,
    headers: {
      "content-type":"application/json; charset=UTF-8",
      "cache-control":"no-store",
      "x-signature-ttl": String(ttl)
    }
  });
}

/* ============================ CHAT: /api/chat ============================ */
async function handleChatRequest(request, env) {
  const honeypotBan = await checkHoneypotBan(request, env);
  if (honeypotBan?.blocked) return honeypotBlockedResponse(honeypotBan.reason, honeypotBan.until);

  const gate = await enforceIntegrity(request, env, "/api/chat");
  if (gate) return gate;

  try {
    const body = await request.json();

    const hp = detectHoneypotInObject(body, env);
    if (hp) {
      await registerHoneypotBan(request, env, hp);
      return honeypotBlockedResponse(hp.reason);
    }

    const turnstileToken = extractTurnstileToken(body);
    const turnstileGate  = await enforceTurnstile(turnstileToken, request, env);
    if (turnstileGate) return turnstileGate;

    const rawMetadata = body && typeof body === "object" ? body.metadata : undefined;
    const metadata = (rawMetadata && typeof rawMetadata === "object") ? { ...rawMetadata } : {};
    body.metadata = metadata;

    const { messages = [] } = body;
    const normalized = Array.isArray(messages)
      ? messages.filter(m => m && typeof m.content === "string" && m.content.trim())
      : [];

    const preferredLocale = detectPreferredLocale(normalized, metadata);
    if (!metadata.locale) metadata.locale = preferredLocale;

    const pol = evaluatePolicy(normalized);
    if (pol.blocked) return await buildGuardedResponse(pol.reply, env);

    const sanitized = normalized.map(m => m.role === "user"
      ? ({...m, content: sanitizeText(m.content)})
      : m
    );

    const preparedMessages = ensureGovernancePrompts(sanitized, metadata.locale);

    // Quick website KB route for default/fallback friendliness
    const lastUser = [...sanitized].reverse().find(m => m.role === "user")?.content || "";
    const kb = routeWebsiteDefaultFlow(lastUser);
    if (kb) return await buildKnowledgeResponse(kb, env, metadata.locale);

    // Primary model
    let model = selectChatModel(env, metadata);
    let ai = await env.AI.run(model, { messages: preparedMessages, max_tokens: getMaxTokens(env), temperature: 0.3, metadata });

    let reply =
      (typeof ai === "string" && ai) ||
      ai?.response || ai?.result || ai?.output_text ||
      getDefaultReply(metadata.locale);

    let trimmed = String(reply).trim();
    let conf = assessConfidence(trimmed, ai, metadata.locale);
    let escalated = Boolean(metadata?.escalated);

    // Escalate on low confidence
    if (conf.level === "low" && !escalated) {
      const bump = await escalateHighConfidenceChat({ body, sanitizedMessages: preparedMessages, request, env });
      if (bump?.reply) {
        reply = bump.reply;
        trimmed = String(reply).trim();
        conf = { level: "high", reasons: ["escalated"] };
        ai = bump.aiResponse ?? ai;
        model = bump.model ?? model;
        escalated = true;
      }
    }

    const digest = await sha512B64(trimmed);
    const gw = resolveIntegrityGateway(env);
    const protos = resolveIntegrityProtocols(env);

    return new Response(JSON.stringify({
      reply: trimmed,
      model,
      usage: ai?.usage ?? null,
      confidence: conf.level,                 // "high" | "medium" | "low"
      confidence_reasons: conf.reasons,
      escalated
    }), {
      status:200,
      headers:{
        "content-type":"application/json; charset=UTF-8",
        "cache-control":"no-store",
        "x-model": model,
        "x-reply-digest-sha512": digest,
        "x-integrity-gateway": gw,
        "x-integrity-protocols": protos,
        "x-confidence-level": conf.level,
        "x-confidence-reasons": Array.isArray(conf.reasons)?conf.reasons.join(","):""
      }
    });

  } catch {
    return json({error:"Failed to process request"},500);
  }
}

/* ============================= STT: /api/stt ============================= */
async function handleSttRequest(request, env) {
  const honeypotBan = await checkHoneypotBan(request, env);
  if (honeypotBan?.blocked) return honeypotBlockedResponse(honeypotBan.reason, honeypotBan.until);

  const gate = await enforceIntegrity(request, env, "/api/stt");
  if (gate) return gate;

  try {
    const ct = (request.headers.get("content-type") || "").toLowerCase();
    if (!ct.includes("multipart/form-data")) return json({error:"Expected multipart/form-data"},400);

    const form = await request.formData();

    const hp = detectHoneypotInForm(form, env);
    if (hp) {
      await registerHoneypotBan(request, env, hp);
      return honeypotBlockedResponse(hp.reason);
    }

    const token = extractTurnstileToken(form);
    const turnstileGate = await enforceTurnstile(token, request, env);
    if (turnstileGate) return turnstileGate;

    const audio = form.get("audio");
    if (!(audio instanceof File)) return json({error:"Audio blob missing"},400);

    const maxBytes = clampInt(env.MAX_AUDIO_BYTES, 8_000_000);
    if (audio.size > maxBytes) return json({error:"Audio payload exceeds limit"},413);

    const buf = await audio.arrayBuffer();
    const bytes = new Uint8Array(buf);
    const locale = sanitizeLocale(String(form.get("lang") || ""));
    const prefer = String(form.get("prefer") || "").trim().toLowerCase();
    const model = selectSttModel(env, prefer);

    const aiResponse = await env.AI.run(model, { audio: [...bytes], language: locale });
    const transcript = extractTranscript(aiResponse);
    const clean = sanitizeText(transcript);
    const transcriptDigest = await sha512B64(clean);
    const gw = resolveIntegrityGateway(env);
    const protos = resolveIntegrityProtocols(env);

    return new Response(JSON.stringify({ text: clean }), {
      status: 200,
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "cache-control": "no-store",
        "x-tier": aiResponse?.tier || "?",
        "x-model": model,
        "x-transcript-digest-sha512": transcriptDigest,
        "x-integrity-gateway": gw,
        "x-integrity-protocols": protos
      }
    });

  } catch {
    return json({error:"Failed to transcribe audio"},500);
  }
}

/* ============================ Escalation (L7) ============================ */
async function escalateHighConfidenceChat({ body, sanitizedMessages, request, env }) {
  const base = resolveHighConfidenceUrl(env);
  if (!base) return null;

  let target;
  try { target = new URL("/api/chat", base).toString(); }
  catch { return null; }

  const metadata = { ...(body?.metadata||{}), escalated: true, tier: body?.metadata?.tier || "premium" };
  const payload = { messages: sanitizedMessages, metadata };

  const headers = new Headers({ "content-type":"application/json" });
  for (const k of [
    "x-integrity","x-integrity-gateway","x-integrity-protocols",
    "x-request-signature","x-request-timestamp","x-request-nonce"
  ]) {
    const v = request.headers.get(k); if (v) headers.set(k, v);
  }

  try {
    const res = await fetch(target, { method:"POST", headers, body: JSON.stringify(payload) });
    if (!res.ok) return null;
    const data = await res.json();
    const reply =
      (typeof data === "string" && data) ||
      data?.reply || data?.response || data?.result || data?.output_text;
    if (!reply) return null;

    return {
      reply,
      aiResponse: { response: reply, usage: data?.usage ?? null },
      model: data?.model || data?.x_model || "escalated"
    };
  } catch {
    return null;
  }
}

async function forwardEscalation(payload, env) {
  const hook = (env.ESCALATION_WEBHOOK || "").trim();
  if (!hook) return;
  try {
    await fetch(hook, { method:"POST", headers:{ "content-type":"application/json" }, body: JSON.stringify(payload) });
  } catch {}
}

/* ============================ Policy + BM25 ============================ */
function sanitizeText(s) {
  if (!s) return "";
  const cleared = cleanseUserInput(String(s));
  return cleared.replace(/[^\x09\x0A\x0D\x20-\x7E\u00A0-\uFFFF]/g,"").replace(/\s+/g," ").trim();
}
function cleanseUserInput(input){
  if (!input) return "";
  return String(input)
    .replace(/<[^>]*>/g," ")
    .replace(/javascript:/gi,"")
    .replace(/data:text\/html[^\s]*/gi,"")
    .replace(/on\w+\s*=/gi," ")
    .replace(/\b(alert|prompt|confirm)\s*\(/gi,"$1 ")
    .trim();
}
function sanitizeLocale(s) {
  if (!s) return "en";
  const t = String(s).trim().toLowerCase();
  return /^[a-z]{2}(-[a-z]{2})?$/.test(t) ? t : "en";
}
function runSecuritySweep(messages, locale){
  if (!Array.isArray(messages) || !messages.length) return { blocked:false };
  const matches = [];
  for (const msg of messages){
    if (!msg || msg.role !== "user" || !msg.content) continue;
    const hits = detectThreatIndicators(msg.content);
    if (hits.length){
      matches.push({ hits, snippet: sanitizeText(String(msg.content)).slice(0,160) });
    }
  }
  if (!matches.length) return { blocked:false };
  return {
    blocked:true,
    reply: SECURITY_ALERT_MESSAGES[locale === "es" ? "es" : "en"],
    hits: matches
  };
}
function detectThreatIndicators(text){
  if (!text) return [];
  const normalized = String(text).toLowerCase();
  return SECURITY_THREAT_PATTERNS.filter(rx => rx.test(normalized)).map(rx => rx.toString());
}
function evaluatePolicy(messages) {
  if (!Array.isArray(messages)||!messages.length) return {blocked:false};
  const users = messages.filter(m=>m.role==="user");
  if (!users.length) return {blocked:false};
  const last = sanitizeText(users[users.length-1].content);
  if (!last) return {blocked:false};

  const lower = last.toLowerCase();
  const looksBad = MALICIOUS_PATTERNS.some(rx=>rx.test(lower));
  const onTopic  = WEBSITE_KEYWORDS.some(k=>lower.includes(k));
  if (!looksBad && onTopic) return {blocked:false};

  const langPreference = detectLanguage(last);
  const warning = WARNING_MESSAGES[langPreference] || WARNING_MESSAGES.en;
  const terminate = TERMINATE_MESSAGES[langPreference] || TERMINATE_MESSAGES.en;

  const guardCount = messages.filter(m=>m.role==="assistant" && ALL_GUARD_MESSAGES.some(msg => m.content.includes(msg))).length;
  if (guardCount>=1) return {blocked:true, reply:terminate};
  return {blocked:true, reply:warning};
}

function tokenize(s){ return s.toLowerCase().split(/[^a-záéíóúñü0-9]+/).filter(Boolean); }
function detectLanguage(s){
  if (!s) return "en";
  if (/[áéíóúñü¿¡]/i.test(s)) return "es";
  const lower = s.toLowerCase();
  const esHints = /(hola|buen[oa]s|gracias|por favor|necesito|operaciones|contacto|contratar|soporte|centro|llamar|consulta|ayuda|descubrimiento)/i.test(lower);
  const enHints = /(hello|hi|please|thanks|support|contact|pricing|order|help|operations|book)/i.test(lower);
  if (esHints && !enHints) return "es";
  return "en";
}
function computeIdf(term){
  const N = WEBSITE_KB.length || 1;
  const df = WEBSITE_KB.reduce((c,d)=>c + (d.content.toLowerCase().includes(term)?1:0),0) || 1;
  return Math.log((N - df + 0.5) / (df + 0.5) + 1);
}
function scoreDocumentBm25(doc, terms){
  const k1=1.2, b=0.75;
  const docLen = doc.content.split(/\s+/).length || 1;
  let score=0;
  for (const t of terms){
    const tf = (doc.content.toLowerCase().match(new RegExp(`\\b${escapeReg(t)}\\b`,"g"))||[]).length;
    if (!tf) continue;
    const idf = computeIdf(t);
    score += idf * (tf*(k1+1)) / (tf + k1*(1 - b + b*(docLen/(AVG_DOC_LENGTH||1))));
  }
  return score;
}
function escapeReg(s){ return s.replace(/[.*+?^${}()|[\]\\]/g,"\\$&"); }

function routeWebsiteDefaultFlow(usr){
  const q = sanitizeText(usr||""); if (!q) return null;
  const lang = detectLanguage(q);
  const terms = tokenize(q).filter(t=>!STOP_WORDS[lang]?.has(t));
  if (!terms.length) return null;
  let cands = WEBSITE_KB.filter(d=>d.lang===lang);
  if (!cands.length) cands = WEBSITE_KB;

  let best=null;
  for (const d of cands){
    const s = scoreDocumentBm25(d, terms);
    if (!best || s>best.score) best={doc:d,score:s};
  }
  if (!best || best.score < 1.15) return null;

  let reply = (lang==="es" ? best.doc.summaryEs : best.doc.summaryEn) || best.doc.content;
  return { type:"kb", reply, docId:best.doc.id, title:best.doc.title, language:lang, score:best.score };
}

async function buildKnowledgeResponse(kb, env, locale){
  const reply = (kb?.reply || "").trim();
  const language = (locale === "es" || kb?.language === "es") ? "es" : "en";
  const digest = await sha512B64(reply);
  const gw = resolveIntegrityGateway(env);
  const protos = resolveIntegrityProtocols(env);
  return new Response(JSON.stringify({
    reply,
    model: "kb",
    knowledge_id: kb?.docId || null,
    confidence: "high",
    confidence_reasons: ["website_kb"],
    escalated: false,
    language
  }), {
    status:200,
    headers:{
      "content-type":"application/json; charset=UTF-8",
      "cache-control":"no-store",
      "x-model":"kb",
      "x-reply-digest-sha512": digest,
      "x-knowledge-id": kb?.docId || "",
      "x-integrity-gateway": gw,
      "x-integrity-protocols": protos,
      "x-confidence-level":"high",
      "x-confidence-reasons":"website_kb"
    }
  });
}

async function buildGuardedResponse(message, env){
  const reply = (message || WARNING_MESSAGES.en).trim();
  const digest = await sha512B64(reply);
  const gw = resolveIntegrityGateway(env);
  const protos = resolveIntegrityProtocols(env);
  return new Response(JSON.stringify({
    reply,
    model: "policy",
    usage: null,
    confidence: "low",
    confidence_reasons: ["policy_guard"],
    escalated: false
  }), {
    status:200,
    headers:{
      "content-type":"application/json; charset=UTF-8",
      "cache-control":"no-store",
      "x-model":"policy",
      "x-reply-digest-sha512": digest,
      "x-integrity-gateway": gw,
      "x-integrity-protocols": protos,
      "x-confidence-level":"low",
      "x-confidence-reasons":"policy_guard"
    }
  });
}

function ensureGovernancePrompts(messages, locale){
  const filtered = [];
  const directoryPrompt = getDirectoryPrompt(locale);
  const systemPrompt = getSystemPrompt(locale);
  const languagePrompt = getLanguagePrompt(locale);
  const known = new Set([directoryPrompt.trim(), systemPrompt.trim(), languagePrompt.trim()]);
  for (const msg of messages || []){
    if (msg?.role === "system"){
      const content = (msg.content||"").trim();
      if (known.has(content)) continue;
    }
    filtered.push(msg);
  }
  return [
    {role:"system", content: directoryPrompt},
    {role:"system", content: systemPrompt},
    {role:"system", content: languagePrompt},
    ...filtered
  ];
}

function getSystemPrompt(locale){
  return SYSTEM_PROMPTS[locale === "es" ? "es" : "en"];
}
function getDirectoryPrompt(locale){
  return SERVICE_DIRECTORY_PROMPTS[locale === "es" ? "es" : "en"] || SERVICE_DIRECTORY_PROMPTS.en;
}
function getLanguagePrompt(locale){
  return LANGUAGE_PROMPTS[locale === "es" ? "es" : "en"];
}
function detectPreferredLocale(messages, metadata){
  const localeHint = metadata?.locale || metadata?.lang || metadata?.language;
  const sanitized = sanitizeLocale(localeHint || "");
  if (sanitized.startsWith("es")) return "es";
  if (sanitized.startsWith("en")) return "en";
  const lastUser = [...(messages||[])].reverse().find(m => m && m.role === "user" && m.content);
  if (lastUser) {
    const guess = detectLanguage(lastUser.content);
    if (guess === "es") return "es";
  }
  return "en";
}
function getDefaultReply(locale){
  return DEFAULT_FAILURE_REPLIES[locale === "es" ? "es" : "en"];
}

function buildWebsiteKb(){
  const docs = [
    {
      id: "ops-hero",
      lang: "en",
      title: "OPS Website — Hero",
      content:
        "Ops Online Support helps teams keep momentum by handling operations so you can focus on growth.",
      summaryEn:
        "Ops Online Support keeps you moving by handling operations so your team can focus on growth.",
      summaryEs:
        "Ops Online Support mantiene tu impulso gestionando operaciones para que tu equipo se enfoque en crecer."
    },
    {
      id: "ops-pillars",
      lang: "en",
      title: "Service pillars",
      content:
        "Service pillars: Business Operations, Contact Center, IT Support, Professionals On-Demand.",
      summaryEn:
        "Our pillars: Business Operations, Contact Center, IT Support, and Professionals On-Demand.",
      summaryEs:
        "Nuestros pilares: Operaciones de Negocio, Contact Center, Soporte TI y Profesionales On-Demand."
    }
  ];

  docs.push(...buildServiceDirectoryDocs());
  return docs;
}

function buildServiceDirectoryDocs(){
  if (!SERVICE_DIRECTORY) return [];
  const docs = [];
  const overview = SERVICE_DIRECTORY.overview;
  const serviceNames = SERVICE_DIRECTORY.servicePillars?.map(p=>p.name).join(", ") || "";
  const solutionNames = SERVICE_DIRECTORY.solutions?.map(s=>s.name).join(", ") || "";
  const proofPointsEn = SERVICE_DIRECTORY.proofPoints?.join(", ") || "n/a";
  const proofPointsEs = (SERVICE_DIRECTORY.proofPointsEs || SERVICE_DIRECTORY.proofPoints || []).join(", ") || proofPointsEn;
  if (overview){
    const overviewContentEn = `${overview.name} focuses on ${overview.focus}. Service pillars include ${serviceNames}. Solutions cover ${solutionNames}. Operational proof points: ${proofPointsEn}.`;
    const overviewContentEs = `${overview.name} se enfoca en ${overview.focusEs || overview.focus}. Los pilares incluyen ${serviceNames}. Las soluciones cubren ${solutionNames}. Pruebas operativas: ${proofPointsEs}.`;
    pushDocVariants(docs, {
      id: "ops-directory-overview",
      titleEn: `${overview.name} overview`,
      titleEs: `Resumen de ${overview.name}`,
      contentEn: overviewContentEn,
      contentEs: overviewContentEs,
      summaryEn: "OPS Remote Professional Network unites remote pods for Business Operations, Contact Center, IT Support, and Professionals on demand.",
      summaryEs: "La Red de Profesionales Remotos OPS reúne pods remotos para Operaciones, Contact Center, Soporte TI y especialistas bajo demanda."
    });
  }

  for (const pillar of SERVICE_DIRECTORY.servicePillars || []){
    pushDocVariants(docs, {
      id: `pillar-${slugifyId(pillar.name)}`,
      titleEn: `${pillar.name} pillar`,
      titleEs: `Pilar ${pillar.name}`,
      contentEn: pillar.summary,
      contentEs: pillar.summaryEs || pillar.summary,
      summaryEn: pillar.summary,
      summaryEs: pillar.summaryEs || pillar.summary
    });
  }

  for (const solution of SERVICE_DIRECTORY.solutions || []){
    pushDocVariants(docs, {
      id: `solution-${slugifyId(solution.name)}`,
      titleEn: `${solution.name} solution`,
      titleEs: `Solución ${solution.name}`,
      contentEn: solution.coverage,
      contentEs: solution.coverageEs || solution.coverage,
      summaryEn: solution.coverage,
      summaryEs: solution.coverageEs || solution.coverage
    });
  }

  const talent = SERVICE_DIRECTORY.talentNetwork || {};
  const talentLines = talent.applicationHighlights || [];
  const talentLinesEs = talent.applicationHighlightsEs || talentLines;
  const commitments = talent.commitments || [];
  const commitmentsEs = talent.commitmentsEs || commitments;
  if (talentLines.length){
    pushDocVariants(docs, {
      id: "talent-network-highlights",
      titleEn: "Talent network highlights",
      titleEs: "Highlights de la red de talento",
      contentEn: `Applicants emphasize ${talentLines.join("; ")}. Community commitments: ${commitments.join("; ")}.`,
      contentEs: `Las personas postulantes destacan ${talentLinesEs.join("; ")}. Compromisos comunitarios: ${commitmentsEs.join("; ")}.`,
      summaryEn: "OPS talent applicants share crafts, skills, education, continued learning, and guild interests across Business Operations, Contact Center, IT Support, Professionals, Analytics & Insights.",
      summaryEs: "Los postulantes comparten oficios, habilidades, estudios, aprendizaje continuo e intereses en Operaciones, Contact Center, Soporte TI, Profesionales y Analítica."
    });
  }

  if (SERVICE_DIRECTORY.contactPathways?.length){
    const contactEn = SERVICE_DIRECTORY.contactPathways.join("; ");
    const contactEs = (SERVICE_DIRECTORY.contactPathwaysEs || SERVICE_DIRECTORY.contactPathways).join("; ");
    pushDocVariants(docs, {
      id: "ops-contact-pathways",
      titleEn: "OPS contact pathways",
      titleEs: "Rutas de contacto OPS",
      contentEn: contactEn,
      contentEs: contactEs,
      summaryEn: "Contact OPS via discovery calls, direct consultations, or hiring remote specialists across CX, IT, and operations.",
      summaryEs: "Contacta a OPS mediante discovery calls, consultas directas o contratación de especialistas remotos en CX, TI y operaciones."
    });
  }

  return docs;
}

function translatePillarSummary(name, fallback){
  const dict = {
    "Business Operations": "Operaciones de Negocio: playbooks que preservan la higiene financiera, facturación y tableros ejecutivos.",
    "Contact Center (Beta)": "Contact Center (Beta): agentes omnicanal con señales de sentimiento y bases de conocimiento actualizadas.",
    "IT Support (Beta)": "Soporte TI (Beta): pods listos para incidentes con triaje documentado, telemetría integrada y continuidad.",
    "Professionals": "Profesionales: equipos de insights con analítica predictiva y marcos de retroalimentación orientados al crecimiento."
  };
  return dict[name] || fallback;
}
function translateSolutionSummary(name, fallback){
  const dict = {
    "Business Operations": "Cobertura de facturación, cuentas por pagar/cobrar, coordinación de proveedores, soporte administrativo y marketing.",
    "Contact Center (Beta)": "CX multicanal orientado a relaciones con resolución rápida.",
    "IT Support (Beta)": "Soporte TI integral con mesa de ayuda, tickets e incidentes.",
    "Professionals On Demand": "Asistentes y especialistas desplegables para sprints o compromisos prolongados."
  };
  return dict[name] || fallback;
}
function slugifyId(input){ return String(input||"").toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/(^-|-$)/g,""); }

/* ============================ Confidence ============================ */
function assessConfidence(reply, ai){
  const t = (reply||"").trim();
  if (!t) return {level:"low", reasons:["empty"]};
  const lower = t.toLowerCase();
  const uncertain = /(i\s+(am|'m)\s+(not\s+)?sure|i\s+(do\s+not|don't)\s+know|unable to|cannot|can't|no\s+estoy\s+segur[ao]|no\s+sé|no\s+puedo\s+responder)/i.test(lower);
  const refusal   = /(i\s*am\s*sorry|i'm\s*sorry|cannot\s+comply|unable\s+to\s+assist|lo\s+siento|no\s+puedo\s+cumplir|no\s+puedo\s+ayudarte)/i.test(lower);
  const informative = /(business operations|operaciones de negocio|contact center|centro de contacto|it support|soporte ti|professionals|profesionales)/i.test(lower);
  const len = t.length;
  const tokens = Number(ai?.usage?.total_tokens ?? ai?.usage?.totalTokens ?? 0);
  if (uncertain || refusal) return {level:"low", reasons:["uncertain_tone"]};
  if (informative && len>=160) return {level:"high", reasons:["rich_service_context"]};
  if (len<80 && tokens<150) return {level:"low", reasons:["brief"]};
  if (informative || len>=120) return {level:"high", reasons:["detailed"]};
  return {level:"medium", reasons:["default"]};
}

/* ============================== Security ============================== */
function applySecurityHeaders(resp, req, env){
  const h = new Headers(resp.headers);

  const origin = req.headers.get("Origin");
  const allow = getAllowedOrigin(origin, env);
  if (allow){
    h.set("Access-Control-Allow-Origin", allow);
    h.set("Access-Control-Allow-Credentials","true");
    h.set("Vary", mergeVary(h.get("Vary"), "Origin"));
  }

  h.set("Access-Control-Allow-Methods","POST, OPTIONS");
  h.set("Access-Control-Allow-Headers",
    "Content-Type, X-Integrity, X-Integrity-Gateway, X-Integrity-Protocols, X-Request-Signature, X-Request-Timestamp, X-Request-Nonce, X-OPS-Signature, X-OPS-Timestamp, X-OPS-Nonce, CF-Turnstile-Response, X-Turnstile-Token"
  );
  h.set("Access-Control-Max-Age","600");

  h.set("Content-Security-Policy","default-src 'none'; frame-ancestors 'none'; base-uri 'none';");
  h.set("X-Content-Type-Options","nosniff");
  h.set("X-Frame-Options","DENY");
  h.set("Referrer-Policy","same-origin");
  h.set("Permissions-Policy","microphone=(),camera=(),geolocation=()");
  h.set("Strict-Transport-Security","max-age=63072000; includeSubDomains; preload");

  const gw = resolveIntegrityGateway(env);
  const protos = resolveIntegrityProtocols(env);
  const channella = resolveChannellaCanonical(env);
  const integrityValue = resolveIntegrityValue(env);
  h.set("Cross-Origin-Resource-Policy","same-origin");
  h.set("Cross-Origin-Opener-Policy","same-origin");
  h.set("X-OPS-CYSEC-CORE","active");
  h.set("X-Compliance-Frameworks", protos);
  h.set("Integrity", integrityValue);
  h.set("X-Integrity-Gateway", gw);
  h.set("X-Integrity-Protocols", protos);
  h.set("X-Integrity", integrityValue);
  h.set("X-Integrity-Key", channella);
  h.set(CHANNELLA_HEADER, channella);
  const sessionNonce = (req.headers.get("x-session-nonce")||"").trim();
  if (sessionNonce) h.set("X-Session-Nonce", sessionNonce);

  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers: h });
}

function resolveIntegrityGateway(env){ const c = (env.INTEGRITY_GATEWAY||"").trim(); return c || DEFAULT_INTEGRITY_GATEWAY; }
function resolveIntegrityProtocols(env){ const c = (env.INTEGRITY_PROTOCOLS||"").trim(); return c || DEFAULT_INTEGRITY_PROTOCOLS; }

function getAllowedOrigin(origin, env){
  if (!origin) return null;
  const norm = origin.trim().toLowerCase();
  if (!norm) return null;

  const allowWorkers = env.ALLOW_WORKERS_DEV==="true";
  const allowDash    = env.ALLOW_DASH==="true";

  const list = buildAllowedOrigins(env);
  if (list.includes(norm)) return list[list.indexOf(norm)];

  if (allowWorkers && isWorkersDev(norm)) return origin;
  if (allowDash    && isDash(norm))       return origin;
  return null;
}
function buildAllowedOrigins(env){
  const gw = resolveIntegrityGateway(env).toLowerCase();
  const set = new Set(BASE_ALLOWED_ORIGINS.map(s=>s.toLowerCase()));
  set.add(gw);
  const conf = (env.INTEGRITY_GATEWAY||"").trim().toLowerCase();
  if (conf) set.add(conf);
  return Array.from(set);
}
function isWorkersDev(o){ try { return new URL(o).hostname.endsWith(".workers.dev"); } catch { return false; } }
function isDash(o){       try { return new URL(o).hostname.endsWith(".dash.cloudflare.com"); } catch { return false; } }
function mergeVary(ex,v){ if(!ex) return v; const S=new Set(ex.split(",").map(s=>s.trim()).filter(Boolean)); S.add(v); return Array.from(S).join(", "); }

/* =============================== Crypto =============================== */
async function sha256HexOfRequest(req){
  const buf = await req.arrayBuffer();
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(hash)].map(b=>b.toString(16).padStart(2,"0")).join("");
}
async function sha512B64(input){
  const enc = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-512", enc);
  return b64(hash);
}
async function hmacSha512B64(secret, message){
  if (!secret) throw new Error("missing_shared_key");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), {name:"HMAC", hash:"SHA-512"}, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return b64(sig);
}
function b64(buf){
  const u8 = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer||buf);
  let bin=""; for (let i=0;i<u8.length;i++) bin+=String.fromCharCode(u8[i]);
  return btoa(bin);
}

/* ================================ JSON ================================ */
function json(obj,status=200,extra){
  const h = {"content-type":"application/json; charset=UTF-8", ...(extra||{})};
  return new Response(JSON.stringify(obj), {status, headers:h});
}

/* ========================== Honeypot / KV =========================== */
async function checkHoneypotBan(request, env){
  const kv = env.OPS_BANLIST_KV || env.OPS_NONCE_KV;
  if (!kv) return null;
  const ip = getClientIp(request); if (!ip) return null;
  const key = `honeypot:block:${ip}`;
  const raw = await kv.get(key); if (!raw) return null;
  let p; try { p=JSON.parse(raw); } catch { p={reason:String(raw||"honeypot"), expiresAt:null}; }
  return { blocked:true, reason:p?.reason||"honeypot", until:p?.expiresAt||null };
}
async function registerHoneypotBan(request, env, detail){
  const kv = env.OPS_BANLIST_KV || env.OPS_NONCE_KV;
  const ip = getClientIp(request);
  const ttl = getHoneypotBlockTtl(env);
  const reason = detail?.reason || `honeypot:${detail?.field||"unknown"}`;
  if (kv && ip){
    const key = `honeypot:block:${ip}`;
    const now = Date.now();
    const expiresAt = now + ttl*1000;
    const payload = JSON.stringify({reason, createdAt:now, expiresAt, field:detail?.field||null, snippet:detail?.snippet||null});
    await kv.put(key, payload, {expirationTtl:ttl});
  }
  return reason;
}
function honeypotBlockedResponse(reason, until){
  const payload = { error:"access_denied", reason: reason||"honeypot" };
  if (until) payload.blocked_until = until;
  return json(payload,403,{"cache-control":"no-store","x-honeypot":"blocked","x-block-reason":reason||"honeypot"});
}
function detectHoneypotInObject(obj, env){
  if (!obj || typeof obj!=="object") return null;
  const fields = getHoneypotFieldNames(env);
  const stack=[obj], seen=new Set();
  while(stack.length){
    const cur = stack.pop();
    if (!cur || typeof cur!=="object") continue;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const entries = Array.isArray(cur) ? cur.entries() : Object.entries(cur);
    for (const [kRaw,v] of entries){
      const k = typeof kRaw==="string"?kRaw:String(kRaw);
      const low = k.toLowerCase();
      if (isHoneypotFieldName(low, fields) && isFilledHoneypotValue(v)) {
        return createHoneypotDetail(k, v);
      }
      if (shouldTraverse(v)) stack.push(v);
    }
  }
  return null;
}
function detectHoneypotInForm(form, env){
  const fields = getHoneypotFieldNames(env);
  for (const name of form.keys()){
    const low = String(name).toLowerCase();
    if (!isHoneypotFieldName(low, fields)) continue;
    const vals = form.getAll(name)||[];
    for (const val of vals){
      if (typeof val==="string" && val.trim()) return createHoneypotDetail(name, val);
    }
  }
  return null;
}
function createHoneypotDetail(field, value){
  const snippet = typeof value==="string" ? value.trim().slice(0,64)
                : Array.isArray(value) ? value.map(v=>String(v)).join(", ").slice(0,64)
                : typeof value==="object" ? JSON.stringify(value).slice(0,64)
                : String(value);
  return { field, reason:`honeypot:${String(field).toLowerCase()}`, snippet };
}
function isFilledHoneypotValue(v){
  if (typeof v==="string") return v.trim().length>0;
  if (typeof v==="number") return !Number.isNaN(v) && v!==0;
  if (Array.isArray(v)) return v.some(x=>isFilledHoneypotValue(x));
  if (shouldTraverse(v)) return Object.values(v).some(x=>isFilledHoneypotValue(x));
  return false;
}
function getHoneypotFieldNames(env){
  const extra = (env?.HONEYPOT_FIELDS||"").split(",").map(s=>s.trim().toLowerCase()).filter(Boolean);
  return Array.from(new Set([...DEFAULT_HONEYPOT_FIELDS, ...extra]));
}
function isHoneypotFieldName(name, allow){ if(!name) return false; return allow.includes(name)||name.includes("honeypot")||name.includes("bot")||name.includes("trap"); }
function shouldTraverse(v){
  if (!v) return false;
  if (Array.isArray(v)) return true;
  if (typeof v!=="object") return false;
  if (typeof File!=="undefined" && v instanceof File) return false;
  if (typeof Blob!=="undefined" && v instanceof Blob) return false;
  if (v instanceof ArrayBuffer) return false;
  if (ArrayBuffer.isView && ArrayBuffer.isView(v)) return false;
  const tag = Object.prototype.toString.call(v);
  return tag==="[object Object]" || tag==="[object Array]";
}
function getHoneypotBlockTtl(env){
  const raw = env?.HONEYPOT_BLOCK_TTL;
  const n = Number(raw);
  if (!Number.isFinite(n)||n<=0) return HONEYPOT_BLOCK_TTL_SECONDS;
  return Math.max(300, Math.min(604800, Math.floor(n)));
}
function getClientIp(req){
  const h = req.headers;
  return (h.get("cf-connecting-ip")||"").trim() ||
         (h.get("x-forwarded-for")||"").split(",").map(s=>s.trim()).find(Boolean) ||
         (h.get("x-real-ip")||"").trim() || null;
}

/* ============================ Turnstile ============================ */
function extractTurnstileToken(source){
  const keys = ["cf-turnstile-response","turnstile_response","turnstile-token","turnstile_token","turnstileResponse","turnstileToken","turnstile"];
  if (!source) return null;
  if (typeof FormData!=="undefined" && source instanceof FormData){
    for (const k of keys){ const v = source.get(k); if (typeof v==="string" && v.trim()) return v.trim(); }
    return null;
  }
  if (typeof source==="object"){
    for (const k of keys){ const v = source[k]; if (typeof v==="string" && v.trim()) return v.trim(); }
    if (source.metadata && typeof source.metadata==="object") return extractTurnstileToken(source.metadata);
  }
  return null;
}
async function enforceTurnstile(token, request, env){
  const secret = (env?.TURNSTILE_SECRET||"").trim();
  if (!secret) return null; // not required unless configured
  let resolved = typeof token==="string" ? token.trim() : "";
  if (!resolved){
    const h = request.headers.get("cf-turnstile-response") || request.headers.get("x-turnstile-token");
    if (h) resolved = h.trim();
  }
  if (!resolved) return json({error:"turnstile_required"},403,{"cache-control":"no-store","x-turnstile":"missing"});

  const params = new URLSearchParams();
  params.set("secret", secret);
  params.set("response", resolved);
  const ip = getClientIp(request); if (ip) params.set("remoteip", ip);

  try {
    const verify = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method:"POST",
      body: params,
      headers: {"content-type":"application/x-www-form-urlencoded"}
    });
    if (!verify.ok) return json({error:"turnstile_unreachable"},502,{"cache-control":"no-store","x-turnstile":String(verify.status)});
    const result = await verify.json();
    if (!result?.success){
      const codes = Array.isArray(result?.["error-codes"]) ? result["error-codes"].join(",") : "failed";
      return json({error:"turnstile_failed", code: codes},403,{"cache-control":"no-store","x-turnstile":codes||"failed"});
    }
    return null;
  } catch {
    return json({error:"turnstile_error"},500,{"cache-control":"no-store","x-turnstile":"exception"});
  }
}

/* ============================ Models / Limits ============================ */
function selectChatModel(env, metadata){
  const tier = typeof metadata?.tier === "string" ? metadata.tier.toLowerCase() : "";
  if (tier==="big"     && env.AI_LLM_BIG)     return env.AI_LLM_BIG;
  if (tier==="premium" && env.AI_LLM_PREMIUM) return env.AI_LLM_PREMIUM;
  return env.AI_LLM_DEFAULT || MODEL_ID;
}
function selectSttModel(env, prefer){
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

  const gatewayHeader = (request.headers.get("x-integrity-gateway")||"").trim();
  const expectedGateway = resolveIntegrityGateway(env);
  if (gatewayHeader && gatewayHeader !== expectedGateway) {
    return json({error:"invalid_integrity_gateway"},403,{"cache-control":"no-store"});
  }

  const channellaHeader = (request.headers.get("x-integrity-key") || request.headers.get(CHANNELLA_HEADER) || "").trim();
  const canonicalChannella = resolveChannellaCanonical(env);
  if (!channellaHeader) {
    return json({error:"missing_channella"},403,{"cache-control":"no-store"});
  }
  if (channellaHeader !== canonicalChannella) {
    return json({error:"invalid_channella"},403,{"cache-control":"no-store"});
  }
  const sessionNonce = (request.headers.get("x-session-nonce")||"").trim().toLowerCase();
  if (!/^[a-f0-9]{32}$/.test(sessionNonce)) {
    return json({error:"invalid_session_nonce"},403,{"cache-control":"no-store"});
  }
  return null;
}

/* ============================ Models / Limits ============================ */
function selectChatModel(env, metadata){
  const tier = typeof metadata?.tier === "string" ? metadata.tier.toLowerCase() : "";
  if (tier==="big"     && env.AI_LLM_BIG)     return env.AI_LLM_BIG;
  if (tier==="premium" && env.AI_LLM_PREMIUM) return env.AI_LLM_PREMIUM;
  return env.AI_LLM_DEFAULT || MODEL_ID;
}
function selectSttModel(env, prefer){
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
function getSignatureTtl(env){
  const fallback = 300;
  const v = env.SIG_TTL_SECONDS ? Number(env.SIG_TTL_SECONDS) : NaN;
  if (!Number.isFinite(v) || v <= 0) return fallback;
  return Math.max(60, Math.min(900, Math.floor(v)));
}
function getMaxTokens(env){
  const v = env.LLM_MAX_TOKENS ? Number(env.LLM_MAX_TOKENS) : NaN;
  if (!Number.isFinite(v) || v <= 0) return 768;
  return Math.min(1024, v);
}

/* ============================== Transcript ============================== */
function extractTranscript(res){
  if (!res) return "";
  if (typeof res === "string") return res;
  if (typeof res.text === "string") return res.text;
  if (Array.isArray(res.results) && res.results[0]?.text) return res.results[0].text;
  if (typeof res.output_text === "string") return res.output_text;
  return "";
}
function getSignatureTtl(env){
  const fallback = 300;
  const v = env.SIG_TTL_SECONDS ? Number(env.SIG_TTL_SECONDS) : NaN;
  if (!Number.isFinite(v) || v <= 0) return fallback;
  return Math.max(60, Math.min(900, Math.floor(v)));
}
function getMaxTokens(env){
  const v = env.LLM_MAX_TOKENS ? Number(env.LLM_MAX_TOKENS) : NaN;
  if (!Number.isFinite(v) || v <= 0) return 768;
  return Math.min(1024, v);
}

/* ============================== Transcript ============================== */
function extractTranscript(res){
  if (!res) return "";
  if (typeof res === "string") return res;
  if (typeof res.text === "string") return res.text;
  if (Array.isArray(res.results) && res.results[0]?.text) return res.results[0].text;
  if (typeof res.output_text === "string") return res.output_text;
  return "";
}
