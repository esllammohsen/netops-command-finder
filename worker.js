
/**
 * NetOps Command Finder - Cloudflare Worker
 * Cloudflare Workers AI version (Gemini removed)
 * Required binding in wrangler.toml: [ai] binding = "AI"
 */
const DEFAULT_ALLOWED_ORIGINS = ["https://esllammohsen.github.io"];
const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";

const SYSTEM_INSTRUCTIONS = `You are a senior network and security infrastructure troubleshooting researcher.
Help network engineers troubleshoot Cisco, F5 BIG-IP, Palo Alto Networks, Fortinet, and related infrastructure.
Return ONLY valid JSON with this exact shape:
{
 "summary":"short explanation of what the symptom usually means",
 "causes":[{"title":"cause","detail":"why it may cause the symptom and how to validate it"}],
 "commands":[{"command":"exact CLI command","platform":"vendor/product and context","description":"what the command displays or does","when_to_use":"when/how to use it","risk":"Read-only | Changes configuration | Potentially disruptive","source_title":"source title","source_url":"https://..."}],
 "sources":[{"title":"source title","url":"https://..."}],
 "safety_note":"brief caution where appropriate"
}
Rules:
- Return 3-8 useful commands only when you can do so reliably. Do not pad with guesses.
- Never invent command syntax, flags, paths, or configuration hierarchy.
- Prefer diagnostic/read-only commands. Clearly label configuration changes, session clears, restarts, and production-impacting actions.
- State platform/context (e.g. F5 BIG-IP TMSH vs Linux shell, Cisco FTD diagnostic CLI vs FXOS, PAN-OS operational vs configuration mode).
- Do not assume the user's software version. Mention version caveats when known.
- Never ask for secrets, private keys, passwords, or full sensitive configurations.
- If exact syntax is uncertain, say so and omit the command.
- Do not fabricate source URLs or claim to have checked live documentation. If no verified source is available in the prompt, leave source_url empty and say that vendor documentation should be checked for the installed version.
- Output valid JSON only, no Markdown fences.`;

function corsHeaders(origin, allowed) {
  const permitted = allowed.includes("*") || allowed.includes(origin);
  return {
    "Access-Control-Allow-Origin": permitted ? (allowed.includes("*") ? "*" : origin) : "null",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin"
  };
}

function json(data, status, headers) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers }
  });
}

function parseJsonOutput(value) {
  const cleaned = String(value || "")
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/, "")
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch (_) {
    const start = cleaned.indexOf("{");
    const end = cleaned.lastIndexOf("}");
    if (start >= 0 && end > start) {
      return JSON.parse(cleaned.slice(start, end + 1));
    }
    throw new Error("The AI response was not valid JSON");
  }
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = (env.ALLOWED_ORIGINS || DEFAULT_ALLOWED_ORIGINS.join(","))
      .split(",").map(x => x.trim()).filter(Boolean);
    const headers = corsHeaders(origin, allowed);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers });
    }

    if (request.method !== "POST") {
      return json({ error: "Use POST /search" }, 405, headers);
    }

    if (headers["Access-Control-Allow-Origin"] === "null") {
      return json({ error: "Origin not allowed" }, 403, headers);
    }

    if (!env.AI) {
      return json({ error: "Workers AI binding AI is not configured" }, 503, headers);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "Invalid JSON body" }, 400, headers);
    }

    const query = String(body.query || "").trim().slice(0, 1200);
    const vendor = String(body.vendor || "Network infrastructure").trim().slice(0, 100);

    if (query.length < 4) {
      return json({ error: "Please describe the issue in more detail" }, 400, headers);
    }

    const userPrompt = `Device/vendor selected in the app: ${vendor}
User's issue: ${query}

Provide relevant CLI commands, likely causes, verification steps, and safety notes. Return only the required JSON object.`;

    try {
      const result = await env.AI.run(MODEL, {
        messages: [
          { role: "system", content: SYSTEM_INSTRUCTIONS },
          { role: "user", content: userPrompt }
        ],
        max_tokens: 1800,
        temperature: 0.2
       response_format: { type: "json_object" }
      });

      const output = result?.response ??
  result?.choices?.[0]?.message?.content ?? "";

if (!output) {
  return json({ error: "Cloudflare AI returned no text. Please try again." }, 502, headers);
}

let data;
try {
  data = typeof output === "object"
    ? output
    : parseJsonOutput(output);
} catch (_) {
  return json({ error: "The AI response could not be parsed. Please try again." }, 502, headers);
}
      }

      if (!Array.isArray(data.commands)) data.commands = [];
      if (!Array.isArray(data.causes)) data.causes = [];
      if (!Array.isArray(data.sources)) data.sources = [];

      data.commands = data.commands.slice(0, 10);
      data.causes = data.causes.slice(0, 8);
      data.sources = data.sources.slice(0, 15);

      return json(data, 200, headers);

    } catch (error) {
      return json({
        error: "Cloudflare AI request failed: " + (error.message || "unknown error")
      }, 502, headers);
    }
  }
};
