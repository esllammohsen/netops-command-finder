
/**
 * NetOps Command Finder
 * Tavily Real Internet Search + Cloudflare Workers AI
 *
 * Required:
 * - AI binding
 * - TAVILY_KEY secret
 */

const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";

const DEFAULT_ALLOWED_ORIGINS = [
  "https://esllammohsen.github.io"
];

const VENDOR_DOMAINS = {
  f5: [
    "my.f5.com",
    "clouddocs.f5.com",
    "techdocs.f5.com"
  ],
  cisco: [
    "cisco.com",
    "developer.cisco.com"
  ],
  paloalto: [
    "docs.paloaltonetworks.com",
    "knowledgebase.paloaltonetworks.com"
  ],
  fortinet: [
    "docs.fortinet.com",
    "community.fortinet.com"
  ],
  generic: [
    "cisco.com",
    "developer.cisco.com",
    "my.f5.com",
    "clouddocs.f5.com",
    "techdocs.f5.com",
    "docs.paloaltonetworks.com",
    "knowledgebase.paloaltonetworks.com",
    "docs.fortinet.com",
    "community.fortinet.com"
  ]
};

const SYSTEM_INSTRUCTIONS = `
You are a senior network and security infrastructure engineer.

Use ONLY the supplied web search results as evidence
for internet-found commands and source citations.

Return ONLY valid JSON:

{
 "summary": "short explanation",
 "causes": [
   {
     "title": "possible cause",
     "detail": "explanation and verification"
   }
 ],
 "commands": [
   {
     "command": "exact command",
     "platform": "vendor/product and CLI context",
     "description": "what it does",
     "when_to_use": "when to use it",
     "risk": "Read-only | Changes configuration | Potentially disruptive",
     "source_title": "exact source title or empty string",
     "source_url": "exact source URL or empty string"
   }
 ],
 "sources": [
   {
     "title": "source title",
     "url": "exact source URL"
   }
 ],
 "safety_note": "brief caution"
}

Rules:
- Never invent command syntax, flags, paths or URLs.
- Do not output commands unless search results support them.
- Prefer diagnostic/read-only commands.
- Clearly label configuration changes, session clears,
  restarts, failovers and disruptive actions.
- Specify CLI context wherever possible.
- Do not assume software versions.
- Use only URLs from supplied search results.
- If no reliable command is supported, return an empty commands array.
- Return valid JSON only, without Markdown fences.
`;

function corsHeaders(origin, allowed) {
  const permitted =
    allowed.includes("*") || allowed.includes(origin);

  return {
    "Access-Control-Allow-Origin": permitted
      ? (allowed.includes("*") ? "*" : origin)
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
  if (output && typeof output === "object") {
    return output;
  }

  if (typeof output !== "string" || !output.trim()) {
    throw new Error("Empty AI response");
  }

  let cleaned = output.trim()
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/\s*```$/i, "")
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch (_) {
    const first = cleaned.indexOf("{");
    const last = cleaned.lastIndexOf("}");

    if (first >= 0 && last > first) {
      return JSON.parse(cleaned.slice(first, last + 1));
    }

    throw new Error("AI response is not valid JSON");
  }
}

function getVendorKey(vendor, query) {
  const value = `${vendor} ${query}`.toLowerCase();

  if (/\bf5\b|big-?ip|tmsh|asm|awaf|ltm/.test(value)) {
    return "f5";
  }

  if (/cisco|\bftd\b|\bfmc\b|asa|catalyst/.test(value)) {
    return "cisco";
  }

  if (/palo alto|pan-os|panorama/.test(value)) {
    return "paloalto";
  }

  if (/fortinet|fortigate|fortimanager/.test(value)) {
    return "fortinet";
  }

  return "generic";
}

function makeSearchQuery(vendor, query) {
  return `${String(vendor || "network infrastructure").slice(0, 80)} ${String(query || "").slice(0, 280)} official documentation CLI troubleshooting command`.trim();
}

async function tavilySearch(apiKey, query, domains) {
  const response = await fetch(
    "https://api.tavily.com/search",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        api_key: apiKey,
        query,
        search_depth: "basic",
        topic: "general",
        max_results: 5,
        include_answer: false,
        include_raw_content: false,
        include_domains: domains
      })
    }
  );

  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    const detail =
      payload?.detail?.error ||
      payload?.error ||
      `Tavily HTTP ${response.status}`;

    throw new Error(detail);
  }

  return Array.isArray(payload.results)
    ? payload.results
    : [];
}

function cleanSearchResults(results) {
  return results.slice(0, 5)
    .map(item => ({
      title: String(item.title || "Untitled source").slice(0, 250),
      url: String(item.url || ""),
      content: String(item.content || "").slice(0, 1800),
      score: typeof item.score === "number"
        ? item.score
        : null
    }))
    .filter(item =>
      /^https:\/\//i.test(item.url) && item.content
    );
}

function normalizeAIData(data, searchResults) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("Invalid AI response structure");
  }

  const allowedSources = new Map(
    searchResults.map(source => [
      source.url,
      source.title
    ])
  );

  const commands = Array.isArray(data.commands)
    ? data.commands.slice(0, 10)
    : [];

  const safeCommands = commands
    .map(command => {
      const url =
        typeof command.source_url === "string" &&
        allowedSources.has(command.source_url)
          ? command.source_url
          : "";

      return {
        command: String(command.command || ""),
        platform: String(command.platform || ""),
        description: String(command.description || ""),
        when_to_use: String(command.when_to_use || ""),
        risk: String(command.risk || "Read-only"),
        source_title: url
          ? allowedSources.get(url)
          : "",
        source_url: url
      };
    })
    .filter(command => command.command);

  return {
    summary: String(data.summary || ""),

    causes: Array.isArray(data.causes)
      ? data.causes.slice(0, 8)
      : [],

    commands: safeCommands,

    // URLs are copied directly from Tavily.
    sources: searchResults.map(source => ({
      title: source.title,
      url: source.url
    })),

    safety_note: String(
      data.safety_note ||
      "Verify commands against the exact product and software version before execution."
    )
  };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";

    const allowed = (
      env.ALLOWED_ORIGINS ||
      DEFAULT_ALLOWED_ORIGINS.join(",")
    )
      .split(",")
      .map(item => item.trim())
      .filter(Boolean);

    const headers = corsHeaders(origin, allowed);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers
      });
    }

    if (request.method !== "POST") {
      return jsonResponse(
        { error: "Use POST /search" },
        405,
        headers
      );
    }

    if (headers["Access-Control-Allow-Origin"] === "null") {
      return jsonResponse(
        { error: "Origin not allowed" },
        403,
        headers
      );
    }

    if (!env.AI) {
      return jsonResponse(
        { error: "Cloudflare AI binding AI is not configured" },
        503,
        headers
      );
    }

    if (!env.TAVILY_KEY) {
      return jsonResponse(
        {
          error: "TAVILY_KEY secret is missing in Cloudflare Worker settings"
        },
        503,
        headers
      );
    }

    let body;

    try {
      body = await request.json();
    } catch (_) {
      return jsonResponse(
        { error: "Invalid JSON request body" },
        400,
        headers
      );
    }

    const query = String(body.query || "")
      .trim()
      .slice(0, 1200);

    const vendor = String(
      body.vendor || "Network infrastructure"
    )
      .trim()
      .slice(0, 100);

    if (query.length < 4) {
      return jsonResponse(
        {
          error: "Please describe the issue in more detail"
        },
        400,
        headers
      );
    }

    try {
      // 1. Determine vendor and official domains.
      const vendorKey = getVendorKey(vendor, query);

      const searchQuery = makeSearchQuery(
        vendor,
        query
      );

      // 2. Perform REAL Tavily internet search.
      const rawResults = await tavilySearch(
        env.TAVILY_KEY,
        searchQuery,
        VENDOR_DOMAINS[vendorKey]
      );

      const searchResults = cleanSearchResults(rawResults);

      if (searchResults.length === 0) {
        return jsonResponse(
          {
            error: "Tavily returned no usable official documentation results. Try adding the product model and software version."
          },
          502,
          headers
        );
      }

      // 3. Prepare actual search evidence for the AI.
      const evidence = searchResults
        .map((item, index) =>
          `[${index + 1}] ${item.title}\nURL: ${item.url}\nContent: ${item.content}`
        )
        .join("\n\n");

      const userPrompt = `
Selected platform/vendor: ${vendor}

User's issue:
${query}

REAL WEB SEARCH RESULTS:
${evidence}

Explain the issue and return only commands supported
by these search results.

Use exact source URLs from the results.
If no command is sufficiently supported,
return an empty commands array.

Return the required JSON object.
`;

      // 4. Analyze search results with Cloudflare AI.
      const aiResult = await env.AI.run(MODEL, {
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

      const output =
        aiResult?.response ??
        aiResult?.choices?.[0]?.message?.content ??
        aiResult?.result?.response ??
        null;

      if (output === null || output === undefined) {
        return jsonResponse(
          {
            error: "Cloudflare AI returned an empty response"
          },
          502,
          headers
        );
      }

      // 5. Parse and validate AI response.
      const parsed = parseAIResponse(output);

      const finalData = normalizeAIData(
        parsed,
        searchResults
      );

      return jsonResponse(
        finalData,
        200,
        headers
      );

    } catch (error) {
      return jsonResponse(
        {
          error: "Internet search or AI processing failed.",
          details: error?.message || "Unknown error"
        },
        502,
        headers
      );
    }
  }
};
