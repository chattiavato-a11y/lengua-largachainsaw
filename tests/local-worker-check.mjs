import worker from '../chattia-worker.ts';

const textDecoder = new TextDecoder();

function createEnv({ assetBody = 'ok', aiReply = 'Test response' } = {}) {
  return {
    ASSETS: {
      async fetch(_request) {
        return new Response(assetBody, {
          status: 200,
          headers: { 'content-type': 'text/plain' },
        });
      },
    },
    AI: {
      async run(_model, _body) {
        return { response: aiReply, usage: { tokens: 42 } };
      },
    },
  };
}

async function readBody(response) {
  const arrayBuffer = await response.arrayBuffer();
  return textDecoder.decode(arrayBuffer);
}

async function testRootRoute() {
  const env = createEnv({ assetBody: 'index html stub' });
  const request = new Request('https://example.com/');
  const response = await worker.fetch(request, env);
  console.assert(response.status === 200, 'Expected status 200 for root');
  const body = await readBody(response);
  console.assert(body === 'index html stub', 'Expected asset body from stub');
}

async function testOptionsCors() {
  const env = createEnv();
  const request = new Request('https://example.com/api/chat', {
    method: 'OPTIONS',
    headers: { Origin: 'https://app.example', 'Access-Control-Request-Headers': 'content-type' },
  });
  const response = await worker.fetch(request, env);
  console.assert(response.status === 204, 'Expected 204 for OPTIONS');
  console.assert(response.headers.get('access-control-allow-origin') === 'https://app.example');
}

async function testChatEndpoint() {
  const env = createEnv({ aiReply: 'AI says hi' });
  const request = new Request('https://example.com/api/chat', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Origin: 'https://ui.example',
    },
    body: JSON.stringify({
      messages: [
        { role: 'user', content: 'Hello' },
      ],
    }),
  });

  const response = await worker.fetch(request, env);
  console.assert(response.status === 200, 'Expected 200 for chat response');
  const data = JSON.parse(await readBody(response));
  console.assert(data.reply === 'AI says hi', 'Expected AI reply in payload');
  console.assert(response.headers.get('access-control-allow-origin') === 'https://ui.example');
}

await testRootRoute();
await testOptionsCors();
await testChatEndpoint();

console.log('Local worker checks passed');
