/**
 * Real MCP server + client round trip over the official @modelcontextprotocol/sdk
 * InMemoryTransport (no sockets). The server registers an `add` tool whose handler
 * runs the Vitni middleware, attaching a signed receipt at
 * result._meta["dev.veritrail/receipt"].
 *
 * We use the low-level `Server` + `setRequestHandler(CallToolRequestSchema, ...)`
 * rather than the `McpServer` Zod sugar so the handler returns a plain result object
 * and we keep full control over the _meta envelope (and avoid outputSchema validation
 * stripping or rejecting it). This is the real protocol message flow.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import {
  vitniToolResult,
  TestSigner,
  generateTestSigner,
  McpResultLike,
} from './vitni-middleware.js';

export interface RoundTripOptions {
  signer?: TestSigner;
  toolName: 'add';
  args: { a: number; b: number };
}

export interface RoundTripResult {
  /** The CallTool result the client received, including _meta with the receipt. */
  result: McpResultLike;
  /** The signer whose public key the client should trust. */
  signer: TestSigner;
}

/**
 * Build an MCP server exposing a single co-signing `add` tool.
 * The published public key is exposed in the server's instructions/metadata so a
 * client can build its key registry (here we return the signer directly to the test).
 */
function buildServer(signer: TestSigner): Server {
  const server = new Server(
    { name: 'vitni-demo-server', version: '0.1.0' },
    {
      capabilities: { tools: {} },
      // Publish the trusted key registry in the server instructions (a real
      // deployment would expose this via a well-known endpoint or server metadata).
      instructions: JSON.stringify({
        vitni_keys: { [signer.performerId]: { [signer.kid]: signer.publicJwk } },
      }),
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'add',
        description: 'Add two numbers; emits a Vitni receipt in _meta.',
        inputSchema: {
          type: 'object',
          properties: { a: { type: 'number' }, b: { type: 'number' } },
          required: ['a', 'b'],
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const t0 = performance.now();
    const toolName = request.params.name;
    const params = request.params.arguments ?? {};

    if (toolName !== 'add') {
      return { content: [{ type: 'text', text: `unknown tool: ${toolName}` }], isError: true };
    }

    const a = Number((params as { a: number }).a);
    const b = Number((params as { b: number }).b);
    const sum = a + b;

    // The raw tool result (what a non-Vitni client would see).
    const result: McpResultLike = {
      content: [{ type: 'text', text: String(sum) }],
      structuredContent: { sum },
    };

    const wallMs = String(Math.max(0, Math.round(performance.now() - t0)));

    // Co-signing middleware: build + sign the receipt, attach at _meta.
    vitniToolResult({ signer, toolName, params, result, wallMs });

    return result;
  });

  return server;
}

/**
 * Run a full server<->client round trip over InMemoryTransport and return the
 * result the client received (with the receipt in _meta).
 */
export async function runRoundTrip(opts: RoundTripOptions): Promise<RoundTripResult> {
  const signer = opts.signer ?? generateTestSigner();
  const server = buildServer(signer);

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  const client = new Client({ name: 'vitni-demo-client', version: '0.1.0' }, { capabilities: {} });

  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  try {
    const result = (await client.callTool({
      name: opts.toolName,
      arguments: opts.args,
    })) as McpResultLike;

    return { result, signer };
  } finally {
    await client.close();
    await server.close();
  }
}
