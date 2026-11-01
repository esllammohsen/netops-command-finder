
/**
 * NetOps Command Finder
 * Tavily targeted official documentation search
 * Cloudflare Workers AI + JSON Mode
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
    "techdocs.f5.com",
    "support.f5.com"
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
    "support.f5.com",
    "docs.paloaltonetworks.com",
    "knowledgebase.paloaltonetworks.com",
    "docs.fortinet.com",
    "community.fortinet.com"
  ]
};

const SYSTEM_INSTRUCTIONS = `
You are a senior network and security infrastructure engineer.

Your task is to analyze real web search results and answer
the user's exact technical question.

IMPORTANT:
Use ONLY the supplied search results as evidence for
internet-discovered commands and source citations.

Do not treat a result as relevant merely because it mentions
the same vendor or product family.

RELEVANCE RULES:
- Match the exact product and feature in the question.
- Respect the requested software version.
- Exclude unrelated products, mobile apps, integrations,
  cloud products, and unrelated deployment guides.
- For F5 BIG-IP questions, do not use F5 Access,
  OpenStack, or SSL Orchestrator results unless the
  question explicitly asks about them.
- Prefer official product documentation and vendor KB articles.
- If search results do not directly support the answer,
  clearly say that evidence is insufficient.

COMMAND RULES:
- Never invent commands, flags, paths, or configuration syntax.
- Do not infer a command from a general product description.
- Only provide commands directly supported by the search evidence.
- Do not confuse Linux OpenSSL commands with BIG-IP TMSH commands.
- Clearly identify the CLI context.
- Prefer read-only diagnostic commands.
- Mark configuration changes and disruptive operations.
- Do not recommend exporting or exposing private keys.
- If a command is not supported by the evidence, omit it.

Return ONLY valid JSON in this exact structure:

{
  "summary": "Answer to the exact question",
  "causes": [
    {
      "title": "Possible cause",
      "detail": "Explanation and verification"
    }
  ],
  "commands": [
    {
      "command": "Exact command",
      "platform": "Product, version and CLI context",
      "description": "What it does",
      "when_to_use": "When to use it",
      "risk": "Read-only | Changes configuration | Potentially disruptive",
      "source_title": "Exact source title",
      "source_url": "Exact source URL from search results"
    }
  ],
  "sources": [
    {
      "title": "Exact source title",
      "url": "Exact source URL from search results"
    }
  ],
  "safety_note": "Safety warning or verification limitation"
}

The sources array must contain ONLY results directly relevant
to the user's question.

If no relevant source exists:
- Return an empty sources array.
- Return an empty commands array.
- Explain that more specific documentation is needed.

Return valid JSON only, without Markdown fences.
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

  const cleaned = output.trim()
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

function detectVendor(vendor, query) {
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

function extractVersion(text) {
  const match = String(text).match(
    /\b(?:BIG-IP|TMOS|PAN-OS|FortiOS|FTD|FMC)?\s*v?(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)\b/i
  );

  return match ? match[1] : "";
}

function buildTargetedQuery(vendorKey, vendor, query) {
  const version = extractVersion(query);

  const productNames = {
    f5: "F5 BIG-IP TMOS",
    cisco: "Cisco network security product",
    paloalto: "Palo Alto Networks PAN-OS",
    fortinet: "Fortinet FortiGate FortiOS",
    generic: vendor
  };

  const product = productNames[vendorKey] || vendor;

  const versionText = version
    ? `software version ${version}`
    : "";

  return [
    product,
    versionText,
    query,
    "official technical documentation troubleshooting configuration CLI"
  ].filter(Boolean).join(" ");
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
        search_depth: "advanced",
        topic: "general",
        max_results: 8,
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
  return results.slice(0, 8)
    .map(item => ({
      title: String(item.title || "Untitled source").slice(0, 250),
      url: String(item.url || ""),
      content: String(item.content || "").slice(0, 2200),
      score: typeof item.score === "number"
        ? item.score
        : null
    }))
    .filter(item =>
      /^https:\/\//i.test(item.url) &&
      item.content.length > 30
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

  // Only allow citations that Tavily actually returned.
  const sources = Array.isArray(data.sources)
    ? data.sources
        .filter(source =>
          source &&
          typeof source.url === "string" &&
          allowedSources.has(source.url)
        )
        .slice(0, 8)
        .map(source => ({
          title: allowedSources.get(source.url),
          url: source.url
        }))
    : [];

  const approvedSourceUrls = new Set(
    sources.map(source => source.url)
  );

  const commands = Array.isArray(data.commands)
    ? data.commands.slice(0, 10)
    : [];

  const safeCommands = commands
    .map(command => {
      const url =
        typeof command.source_url === "string" &&
        approvedSourceUrls.has(command.source_url)
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
    .filter(command =>
      command.command &&
      command.source_url
    );

  return {
    summary: String(data.summary || ""),

    causes: Array.isArray(data.causes)
      ? data.causes.slice(0, 8)
      : [],

    commands: safeCommands,

    sources,

    safety_note: String(
      data.safety_note ||
      "Verify all commands against the installed product version before execution."
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
        { error: "TAVILY_KEY secret is missing" },
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
        { error: "Please describe the issue in more detail" },
        400,
        headers
      );
    }

    try {
      // Step 1: Identify vendor and exact product scope.
      const vendorKey = detectVendor(vendor, query);

      const domains = VENDOR_DOMAINS[vendorKey];

      // Step 2: Build a product- and version-aware query.
      const searchQuery = buildTargetedQuery(
        vendorKey,
        vendor,
        query
      );

      // Step 3: Search official vendor documentation.
      const rawResults = await tavilySearch(
        env.TAVILY_KEY,
        searchQuery,
        domains
      );

      const searchResults = cleanSearchResults(rawResults);

      if (searchResults.length === 0) {
        return jsonResponse(
          {
            error: "No usable official documentation results found. Try including the exact product and software version."
          },
          502,
          headers
        );
      }

      // Step 4: Send actual search evidence to the AI.
      const evidence = searchResults
        .map((item, index) => {
          return [
            `RESULT ${index + 1}`,
            `Title: ${item.title}`,
            `URL: ${item.url}`,
            `Relevance score: ${item.score ?? "Not provided"}`,
            `Content: ${item.content}`
          ].join("\n");
        })
        .join("\n\n----------------\n\n");

      const version = extractVersion(query);

      const userPrompt = `
Selected vendor: ${vendor}
Detected product family: ${vendorKey}
Requested version: ${version || "Not specified"}

EXACT USER QUESTION:
${query}

SEARCH RESULTS:
${evidence}

IMPORTANT TASK:
Evaluate every result for direct relevance to the exact
product, feature, and question.

Do not use results about unrelated products or integrations.
For example, if the question is about F5 BIG-IP Client SSL
certificate chains, exclude F5 Access mobile app and
OpenStack integration documentation.

Select only directly relevant sources.
Every command must be directly supported by at least
one selected source.

If the evidence is insufficient:
- Explain the limitation in summary.
- Return an empty commands array.
- Do not guess.

Return only the required JSON object.
`;

      // Step 5: Analyze evidence with Cloudflare Workers AI.
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
        max_tokens: 2400,
        temperature: 0.1
      });

      const output =
        aiResult?.response ??
        aiResult?.choices?.[0]?.message?.content ??
        aiResult?.result?.response ??
        null;

      if (output === null || output === undefined) {
        return jsonResponse(
          { error: "Cloudflare AI returned an empty response" },
          502,
          headers
        );
      }

      // Step 6: Parse and validate the AI response.
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
