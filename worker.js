
const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";

const DEFAULT_ALLOWED_ORIGINS = [
  "https://esllammohsen.github.io"
];

const SYSTEM_INSTRUCTIONS = `
You are a senior network and security infrastructure engineer.

Help engineers troubleshoot:
Cisco, Cisco FTD, Cisco FMC, F5 BIG-IP, Palo Alto Networks,
Fortinet, FortiGate, FortiManager, and network infrastructure.

Return ONLY a valid JSON object with this structure:

{
  "summary": "Short explanation of the issue",
  "causes": [
    {
      "title": "Possible cause",
      "detail": "Explanation and how to verify"
    }
  ],
  "commands": [
    {
      "command": "Exact CLI command",
      "platform": "Product and CLI context",
      "description": "What the command does",
      "when_to_use": "When to use it",
      "risk": "Read-only",
      "source_title": "Documentation title",
      "source_url": ""
    }
  ],
  "sources": [
    {
      "title": "Documentation title",
      "url": ""
    }
  ],
  "safety_note": "Important safety information"
}

Rules:
- Never invent commands, command syntax, or URLs.
- Prefer read-only troubleshooting commands.
- Clearly identify configuration-changing commands.
- Clearly identify potentially disruptive commands.
- Specify the correct CLI context.
- Do not assume a software version.
- Mention version differences when relevant.
- Do not claim that live documentation was searched.
- Use official vendor documentation when a verified source is available.
- If a source URL is not verified, leave it empty.
- Return concise and useful results.
- Return valid JSON only, without Markdown fences.
`;

function getCorsHeaders(origin, allowedOrigins) {
  const isAllowed =
    allowedOrigins.includes("*") ||
    allowedOrigins.includes(origin);

  return {
    "Access-Control-Allow-Origin": isAllowed
      ? (allowedOrigins.includes("*") ? "*" : origin)
      : "null",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin"
  };
}

function jsonResponse(data, status, headers) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...headers
    }
  });
}

function parseAIResponse(output) {
  // JSON Mode may return an object directly.
  if (output && typeof output === "object") {
    return output;
  }

  if (typeof output !== "string" || !output.trim()) {
    throw new Error("Empty AI response");
  }

  let cleaned = output.trim();

  // Remove Markdown code fences if present.
  cleaned = cleaned
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/\s*```$/i, "")
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch (_) {
    // Try extracting the JSON object from surrounding text.
    const firstBrace = cleaned.indexOf("{");
    const lastBrace = cleaned.lastIndexOf("}");

    if (firstBrace !== -1 && lastBrace > firstBrace) {
      return JSON.parse(
        cleaned.substring(firstBrace, lastBrace + 1)
      );
    }

    throw new Error("AI response is not valid JSON");
  }
}

function normalizeResult(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("Invalid AI response structure");
  }

  return {
    summary: String(data.summary || ""),
    causes: Array.isArray(data.causes)
      ? data.causes.slice(0, 8)
      : [],
    commands: Array.isArray(data.commands)
      ? data.commands.slice(0, 10)
      : [],
    sources: Array.isArray(data.sources)
      ? data.sources.slice(0, 15)
      : [],
    safety_note: String(data.safety_note || "")
  };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";

    const allowedOrigins = (
      env.ALLOWED_ORIGINS ||
      DEFAULT_ALLOWED_ORIGINS.join(",")
    )
      .split(",")
      .map(item => item.trim())
      .filter(Boolean);

    const corsHeaders = getCorsHeaders(
      origin,
      allowedOrigins
    );

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    if (request.method !== "POST") {
      return jsonResponse(
        { error: "Use POST /search" },
        405,
        corsHeaders
      );
    }

    if (corsHeaders["Access-Control-Allow-Origin"] === "null") {
      return jsonResponse(
        { error: "Origin not allowed" },
        403,
        corsHeaders
      );
    }

    if (!env.AI) {
      return jsonResponse(
        { error: "Cloudflare AI binding is missing. Check wrangler.toml." },
        503,
        corsHeaders
      );
    }

    let body;

    try {
      body = await request.json();
    } catch (_) {
      return jsonResponse(
        { error: "Invalid JSON request body" },
        400,
        corsHeaders
      );
    }

    const query = String(body.query || "")
      .trim()
      .slice(0, 1500);

    const vendor = String(body.vendor || "Network infrastructure")
      .trim()
      .slice(0, 100);

    if (query.length < 4) {
      return jsonResponse(
        { error: "Please enter a more detailed question." },
        400,
        corsHeaders
      );
    }

    const userPrompt = `
Selected platform: ${vendor}

User question:
${query}

Explain the likely causes and provide accurate
diagnostic commands and troubleshooting steps.

Return the required JSON structure.
`;

    try {
      const result = await env.AI.run(MODEL, {
        messages: [
          {
            role: "system",
            content: SYSTEM_INSTRUCTIONS
          },
          {
            role: "user",
            content: userPrompt
          }
        ],
        response_format: {
          type: "json_object"
        },
        max_tokens: 2200,
        temperature: 0.2
      });

      // Support both JSON object and text responses.
      const output =
        result?.response ??
        result?.choices?.[0]?.message?.content ??
        result?.result?.response ??
        null;

      if (output === null || output === undefined) {
        return jsonResponse(
          {
            error: "Cloudflare AI returned an empty response."
          },
          502,
          corsHeaders
        );
      }

      let parsedData;

      try {
        parsedData = parseAIResponse(output);
        parsedData = normalizeResult(parsedData);
      } catch (parseError) {
        return jsonResponse(
          {
            error: "Could not process the AI response.",
            details: parseError.message
          },
          502,
          corsHeaders
        );
      }

      return jsonResponse(
        parsedData,
        200,
        corsHeaders
      );

    } catch (error) {
      return jsonResponse(
        {
          error: "Cloudflare AI request failed.",
          details: error?.message || "Unknown error"
        },
        502,
        corsHeaders
      );
    }
  }
};
