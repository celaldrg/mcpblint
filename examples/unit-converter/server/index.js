#!/usr/bin/env node
// A tiny dependency-free MCP server over stdio (JSON-RPC, one message per line).
const readline = require("node:readline");

const precision = Number(process.env.UNITS_PRECISION ?? 3);
const units = {
  m: ["length", 1], km: ["length", 1000], mi: ["length", 1609.344], ft: ["length", 0.3048],
  kg: ["mass", 1], g: ["mass", 0.001], lb: ["mass", 0.45359237],
  c: ["temperature"], f: ["temperature"], k: ["temperature"],
};

function convert(value, from, to) {
  const a = units[from], b = units[to];
  if (!a || !b) throw new Error(`unknown unit: ${!a ? from : to}`);
  if (a[0] !== b[0]) throw new Error(`cannot convert ${a[0]} to ${b[0]}`);
  if (a[0] === "temperature") {
    const toK = { c: (v) => v + 273.15, f: (v) => (v - 32) * 5 / 9 + 273.15, k: (v) => v };
    const fromK = { c: (v) => v - 273.15, f: (v) => (v - 273.15) * 9 / 5 + 32, k: (v) => v };
    return fromK[to](toK[from](value));
  }
  return (value * a[1]) / b[1];
}

const tools = [
  {
    name: "convert",
    description: "Convert a value between two units, for example 5 mi to km",
    inputSchema: {
      type: "object",
      properties: { value: { type: "number" }, from: { type: "string" }, to: { type: "string" } },
      required: ["value", "from", "to"],
    },
  },
  { name: "list_units", description: "List the units the converter understands", inputSchema: { type: "object", properties: {} } },
];

function handle(msg) {
  switch (msg.method) {
    case "initialize":
      return { protocolVersion: msg.params?.protocolVersion ?? "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "unit-converter", version: "1.0.0" } };
    case "tools/list":
      return { tools };
    case "tools/call": {
      const { name, arguments: args = {} } = msg.params ?? {};
      if (name === "list_units") return { content: [{ type: "text", text: Object.keys(units).join(", ") }] };
      try {
        const out = convert(Number(args.value), String(args.from).toLowerCase(), String(args.to).toLowerCase());
        return { content: [{ type: "text", text: `${args.value} ${args.from} = ${out.toFixed(precision)} ${args.to}` }] };
      } catch (e) {
        return { content: [{ type: "text", text: e.message }], isError: true };
      }
    }
    case "ping":
      return {};
    default:
      return undefined;
  }
}

readline.createInterface({ input: process.stdin }).on("line", (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.id === undefined) return; // notification
  const result = handle(msg);
  const reply = result === undefined
    ? { jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: `method not found: ${msg.method}` } }
    : { jsonrpc: "2.0", id: msg.id, result };
  process.stdout.write(JSON.stringify(reply) + "\n");
});
