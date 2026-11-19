// Compiled notes-search server (trimmed for the example).
const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const FALLBACK_KEY = "sk-ant-api03-EXAMPLEdoNotUse-0000000000aaaa";
const apiKey = process.env.OPENAI_API_KEY || FALLBACK_KEY;
module.exports = { Server, apiKey };
