const MODEL_ID = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
const SYSTEM_PROMPT = `You are Chattia, an empathetic, security-aware assistant that
communicates with clarity and inclusive language. Deliver responses that are concise,
actionable, and aligned with human-computer interaction (HCI) best practices. Provide
step-by-step support when helpful, highlight important cautions, and remain compliant
with accessibility and privacy expectations.`;

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
      if (request.method === "OPTIONS") {
        return respondWithCors(null, { status: 204 }, request);
      }

      if (request.method === "POST") {
        return handleChatRequest(request, env);
      }

      return respondWithCors(
        JSON.stringify({ error: "Method not allowed" }),
        {
          status: 405,
          headers: { "content-type": "application/json" },
        },
        request,
      );
    }

    return respondWithCors(
      JSON.stringify({ error: "Not found" }),
      {
        status: 404,
        headers: { "content-type": "application/json" },
      },
      request,
    );
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

    if (!normalizedMessages.some((msg) => msg.role === "system")) {
      normalizedMessages.unshift({ role: "system", content: SYSTEM_PROMPT });
    }

    const aiResponse: any = await env.AI.run(MODEL_ID, {
      messages: normalizedMessages,
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

    return respondWithCors(
      body,
      {
        status: 200,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store",
        },
      },
      request,
    );
  } catch (error) {
    console.error("Error processing chat request:", error);
    return respondWithCors(
      JSON.stringify({ error: "Failed to process request" }),
      {
        status: 500,
        headers: { "content-type": "application/json" },
      },
      request,
    );
  }
}

function respondWithCors(
  body: BodyInit | null,
  init: ResponseInit,
  request: Request,
): Response {
  const headers = new Headers(init.headers);
  const cors = computeCorsHeaders(request);

  for (const [key, value] of Object.entries(cors)) {
    headers.set(key, value);
  }

  headers.append("vary", "origin");
  headers.append("vary", "access-control-request-headers");

  return new Response(body, { ...init, headers });
}

function computeCorsHeaders(request: Request): Record<string, string> {
  const origin = request.headers.get("Origin") ?? "*";
  const requestHeaders =
    request.headers.get("Access-Control-Request-Headers") ?? "content-type";

  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "POST,OPTIONS",
    "access-control-allow-headers": requestHeaders,
    "access-control-max-age": "86400",
  };
}
