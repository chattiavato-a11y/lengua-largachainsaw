const MODEL_ID = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
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
}

type Message = {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
};

export default {
  /**
   * Main request handler for the Worker
   */
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/" || !url.pathname.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    if (url.pathname === "/api/chat") {
      if (request.method === "POST") {
        return handleChatRequest(request, env);
      }
      return new Response("Method not allowed", { status: 405 });
    }

    if (url.pathname === "/api/stt") {
      if (request.method === "POST") {
        return handleSttRequest(request, env);
      }
      return new Response("Method not allowed", { status: 405 });
    }

    return new Response("Not found", { status: 404 });
  },
};

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
      return buildGuardedResponse(policyCheck.reply);
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

    const body = JSON.stringify({
      reply: reply.trim(),
      model: chatModel,
      usage: aiResponse?.usage ?? null,
    });

    return new Response(body, {
      status: 200,
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "cache-control": "no-store",
        "x-model": chatModel,
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
  return input.replace(/[<>]/g, "").replace(/\s+/g, " ").trim();
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

function buildGuardedResponse(reply = WARNING_MESSAGE): Response {
  const body = JSON.stringify({
    reply,
    model: MODEL_ID,
    usage: null,
  });

  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store",
      "x-model": MODEL_ID,
    },
  });
}

function enforceIntegrity(request: Request, env: Env): Response | null {
  if (env.INTEGRITY_REQUIRED !== "true") {
    return null;
  }

  const headerName = "x-integrity";
  const provided = request.headers.get(headerName);
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

    return new Response(JSON.stringify({ text: sanitized }), {
      status: 200,
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "cache-control": "no-store",
        "x-tier": aiResponse?.tier || "?",
        "x-model": model,
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

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
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
