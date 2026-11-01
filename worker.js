/**
 * NetOps Command Finder - Cloudflare Worker (Gemini Free Tier)
 * Required secret: GEMINI_API_KEY
 * Optional variables: ALLOWED_ORIGINS, GEMINI_MODEL
 */
const DEFAULT_ALLOWED_ORIGINS = ["https://esllammohsen.github.io"];
const SYSTEM_INSTRUCTIONS = `You are a senior network and security infrastructure troubleshooting researcher.
You MUST use live Google Search grounding for every request. Search for commands beyond any local command database.
Prioritize official vendor documentation and vendor knowledge bases first (Cisco, F5, Palo Alto Networks, Fortinet, Microsoft, Linux man pages, etc. as relevant). Community sources may supplement but never outrank official documentation.
Return ONLY valid JSON with this exact shape:
{
 "summary":"short explanation of what the symptom usually means",
 "causes":[{"title":"cause","detail":"why it may cause the symptom and how to validate it"}],
 "commands":[{"command":"exact CLI command","platform":"vendor/product and context","description":"what the command displays or does","when_to_use":"when/how to use it","risk":"Read-only | Changes configuration | Potentially disruptive","source_title":"source title","source_url":"https://..."}],
 "sources":[{"title":"source title","url":"https://..."}],
 "safety_note":"brief caution where appropriate"
}
Rules:
- Return 3-8 useful commands when sources support them; do not pad with guesses.
- Commands must be grounded in search results. Never invent command syntax, flags, paths, or configuration hierarchy. If exact syntax cannot be verified, omit it and explain the limitation.
- Prefer diagnostic/read-only commands. Clearly label commands that change configuration, clear sessions, restart services, or can affect production.
- State platform/context (e.g. F5 BIG-IP TMSH vs Linux shell, Cisco FTD diagnostic CLI vs FXOS, PAN-OS operational vs configuration mode).
- Mention version caveats when sources show them. Do not assume the user's version.
- Never ask for secrets, private keys, passwords, or full sensitive configurations.
- If platform is unclear, state the assumption and include only safe, broadly applicable commands.
- Include source URLs for each command wherever possible and list key sources.
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
export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = (env.ALLOWED_ORIGINS || DEFAULT_ALLOWED_ORIGINS.join(","))
      .split(",").map(x => x.trim()).filter(Boolean);
    const headers = corsHeaders(origin, allowed);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
    if (request.method !== "POST") return json({ error: "Use POST /search" }, 405, headers);
    if (headers["Access-Control-Allow-Origin"] === "null") return json({ error: "Origin not allowed" }, 403, headers);
    if (!env.GEMINI_API_KEY) return json({ error: "Worker secret GEMINI_API_KEY is not configured" }, 503, headers);

    let body;
    try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400, headers); }
    const query = String(body.query || "").trim().slice(0, 1200);
    const vendor = String(body.vendor || "Network infrastructure").trim().slice(0, 100);
    if (query.length < 4) return json({ error: "Please describe the issue in more detail" }, 400, headers);

    const prompt = `${SYSTEM_INSTRUCTIONS}\n\nDevice/vendor selected in the app: ${vendor}\nUser's issue: ${query}\n\nResearch the issue and provide relevant CLI commands, likely causes, verification steps, and source links.`;
    const model = env.GEMINI_MODEL || "gemini-2.5-flash";
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
    try {
      const upstream = await fetch(endpoint, {
        method: "POST",
        headers: { "x-goog-api-key": env.GEMINI_API_KEY, "Content-Type": "application/json" },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: SYSTEM_INSTRUCTIONS }] },
          contents: [{ role: "user", parts: [{ text: `Device/vendor selected in the app: ${vendor}\nUser's issue: ${query}\n\nResearch this issue using live Google Search. Return relevant CLI commands, likely causes, verification steps, and source links.` }] }],
          tools: [{ google_search: {} }],
          generationConfig: { temperature: 0.2, maxOutputTokens: 5000, responseMimeType: "application/json" }
        })
      });
      const raw = await upstream.json();
      if (!upstream.ok) {
        const msg = raw?.error?.message || `Gemini API error ${upstream.status}`;
        return json({ error: msg }, 502, headers);
      }
      const text = (raw.candidates || []).flatMap(c => c.content?.parts || [])
        .map(p => p.text || "").join("\n").trim();
      let result;
      try {
        const cleaned = text.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
        result = JSON.parse(cleaned);
      } catch {
        return json({ error: "The research response could not be parsed. Please try again." }, 502, headers);
      }
      if (!Array.isArray(result.commands)) result.commands = [];
      if (!Array.isArray(result.causes)) result.causes = [];
      if (!Array.isArray(result.sources)) result.sources = [];
      // Add Google Search grounding sources returned by Gemini if not already listed.
      const grounding = (raw.candidates || []).flatMap(c => c.groundingMetadata?.groundingChunks || []);
      for (const item of grounding) {
        const web = item.web;
        if (web?.uri && !result.sources.some(s => s.url === web.uri)) {
          result.sources.push({ title: web.title || web.uri, url: web.uri });
        }
      }
      result.commands = result.commands.slice(0, 10);
      result.causes = result.causes.slice(0, 8);
      result.sources = result.sources.slice(0, 15);
      return json(result, 200, headers);
    } catch (error) {
      return json({ error: "Search service failed: " + (error.message || "unknown error") }, 502, headers);
    }
  }
};
