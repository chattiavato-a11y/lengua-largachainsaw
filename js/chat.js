// js/chat.js — secure client wired to the withered-mouse-9aee Cloudflare Worker
// Usage: import this script in a page that defines appendMessage(role, text, meta?)
// and optionally provides window.FallbackKB.reply(text, { locale }) for local replies.

const CF_WORKER_URL = "https://withered-mouse-9aee.grabem-holdem-nuts-right.workers.dev/";
const API_BASE = CF_WORKER_URL.replace(/\/$/, "");
const INTEGRITY_VALUE = "https://chattiavato-a11y.github.io";
const INTEGRITY_PROTOCOLS = "CORS,CSP,OPS-CySec-Core,CISA,NIST,PCI-DSS,SHA-384,SHA-512";
const CHANNELLA_CANONICAL = "ops-channella-v1";
const CHAT_PATH = "/api/chat";
const AUTH_PATH = "/auth/issue";
const ESCALATE_PATH = "/fallback/escalate";
const SESSION_NONCE = randomHex(16);

async function sendMessage(userText) {
  // 1) Show user's message
  appendMessage("user", userText);

  try {
    const requestBody = JSON.stringify({
      messages: [
        { role: "user", content: userText }
      ],
      metadata: {
        // later you can add training_memory, tier, etc.
      }
    });

    const ts = Math.floor(Date.now() / 1000);
    const nonce = randomHex(16);
    const { signature } = await mintSignature({ body: requestBody, path: CHAT_PATH, nonce, timestamp: ts });

    const res = await fetch(API_BASE + CHAT_PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...integrityHeaders(nonce),
        "x-request-signature": signature,
        "x-request-timestamp": String(ts),
        "x-request-nonce": nonce
      },
      body: requestBody
    });

    const data = await res.json();

    let replyText = (data && data.reply) ? String(data.reply).trim() : "";
    const confidence = (data && data.confidence) || "unknown";

    let usedFallback = false;

    // 2) Decide whether to fallback (and escalate to the worker)
    if (!replyText || confidence === "low") {
      if (window.FallbackKB && typeof window.FallbackKB.reply === "function") {
        const fb = window.FallbackKB.reply(userText, { locale: "auto" });
        replyText = fb.text || "I’m here to help with OPS.";
        usedFallback = true;
        escalateFallback({ userText, confidence, replyText }).catch(() => {});
      }
    }

    // 3) Render assistant response (original or fallback)
    appendMessage("assistant", replyText, {
      confidence,
      escalated: !!data?.escalated,
      usedFallback
    });

  } catch (err) {
    console.error("chat error", err);
    const fb = window.FallbackKB && window.FallbackKB.reply
      ? window.FallbackKB.reply("fallback network error", { locale: "en" })
      : { text: "I’m having trouble connecting right now, but OPS is still here to help you." };

    escalateFallback({ userText, confidence: "error", replyText: fb.text }).catch(() => {});

    appendMessage("assistant", fb.text, {
      confidence: "low",
      usedFallback: true
    });
  }
}

async function mintSignature({ body, path, nonce, timestamp }) {
  const bodySha = await sha256Hex(body);
  const payload = {
    ts: timestamp,
    nonce,
    method: "POST",
    path,
    body_sha256: bodySha
  };

  const res = await fetch(API_BASE + AUTH_PATH, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...integrityHeaders(nonce)
    },
    body: JSON.stringify(payload)
  });

  if (!res.ok) throw new Error(`signature_issue_failed:${res.status}`);
  const data = await res.json();
  if (!data?.signature) throw new Error("signature_missing");
  return { signature: data.signature, bodySha };
}

async function escalateFallback(payload) {
  const body = JSON.stringify({
    ...payload,
    gateway: "withered-mouse-9aee",
    timestamp: payload.timestamp || new Date().toISOString()
  });

  await fetch(API_BASE + ESCALATE_PATH, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...integrityHeaders(SESSION_NONCE)
    },
    body
  });
}

function integrityHeaders(nonce) {
  return {
    "x-integrity": INTEGRITY_VALUE,
    "x-integrity-gateway": API_BASE,
    "x-integrity-protocols": INTEGRITY_PROTOCOLS,
    "x-integrity-key": CHANNELLA_CANONICAL,
    "x-ops-channella": CHANNELLA_CANONICAL,
    "x-session-nonce": nonce
  };
}

function randomHex(bytes = 16) {
  try {
    const cryptoObj = (typeof window !== "undefined" && window.crypto)
      ? window.crypto
      : (typeof crypto !== "undefined" ? crypto : null);
    if (cryptoObj?.getRandomValues) {
      const view = new Uint8Array(bytes);
      cryptoObj.getRandomValues(view);
      return Array.from(view, b => b.toString(16).padStart(2, "0")).join("");
    }
  } catch {}

  let fallback = "";
  for (let i = 0; i < bytes; i++) fallback += Math.floor(Math.random() * 256).toString(16).padStart(2, "0");
  return fallback;
}

async function sha256Hex(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const cryptoObj = (typeof window !== "undefined" && window.crypto)
    ? window.crypto
    : (typeof crypto !== "undefined" ? crypto : null);
  if (cryptoObj?.subtle?.digest) {
    const hash = await cryptoObj.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
  }
  // Very small fallback if SubtleCrypto is unavailable
  throw new Error("crypto_unavailable");
}

// Simple DOM helper stub — adjust to your actual UI
function appendMessage(role, text, meta) {
  // Your existing rendering logic here
  console.log(`${role}:`, text, meta || {});
}
