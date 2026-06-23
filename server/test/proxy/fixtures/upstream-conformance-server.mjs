import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

let forwardedCallCount = 0;
const forwardedTools = [];

const echoSchema = {
  type: "object",
  properties: {
    message: { type: "string" },
    secret: { type: "string" },
  },
};

const emptySchema = {
  type: "object",
  properties: {},
};

const server = new Server(
  { name: "proxy-upstream-conformance-fixture", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "echo",
      description: "Echoes accepted arguments and records that forwarding happened.",
      inputSchema: echoSchema,
    },
    {
      name: "stats",
      description: "Reports forwarded call count without incrementing it.",
      inputSchema: emptySchema,
    },
    {
      name: "malformed",
      description: "Returns an intentionally malformed tool response.",
      inputSchema: emptySchema,
    },
    {
      name: "explode",
      description: "Throws an upstream error.",
      inputSchema: emptySchema,
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const name = request.params.name;
  const args = request.params.arguments ?? {};

  if (name === "stats") {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ forwardedCallCount, forwardedTools }),
        },
      ],
    };
  }

  if (name === "explode") {
    forwardedCallCount += 1;
    forwardedTools.push(name);
    throw new Error("fixture upstream exploded at /tmp/private-path");
  }

  if (name === "malformed") {
    forwardedCallCount += 1;
    forwardedTools.push(name);
    return { content: "not-an-array" };
  }

  if (name === "echo") {
    forwardedCallCount += 1;
    forwardedTools.push(name);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ echoed: args, forwardedCallCount }),
        },
      ],
    };
  }

  throw new Error(`unknown fixture tool: ${name}`);
});

await server.connect(new StdioServerTransport());
