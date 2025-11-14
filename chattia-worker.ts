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

    return new Response("Not found", { status: 404 });
  },
};

async function handleChatRequest(request: Request, env: Env): Promise<Response> {
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

    const aiResponse: any = await env.AI.run(MODEL_ID, {
      messages: sanitizedMessages,
      max_tokens: 768,
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
      model: MODEL_ID,
      usage: aiResponse?.usage ?? null,
    });

    return new Response(body, {
      status: 200,
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "cache-control": "no-store",
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
    },
  });
}
