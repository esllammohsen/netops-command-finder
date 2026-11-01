
const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
const DEFAULT_ALLOWED_ORIGINS = ["https://esllammohsen.github.io"];

const VENDORS = {
  f5: {
    label: "F5 BIG-IP / TMOS",
    domains: ["my.f5.com", "clouddocs.f5.com", "techdocs.f5.com", "support.f5.com"]
  },
  cisco: {
    label: "Cisco",
    domains: ["cisco.com", "developer.cisco.com"]
  },
  paloalto: {
    label: "Palo Alto Networks",
    domains: ["docs.paloaltonetworks.com", "knowledgebase.paloaltonetworks.com"]
  },
  fortinet: {
    label: "Fortinet",
    domains: ["docs.fortinet.com", "community.fortinet.com"]
  },
  generic: {
    label: "Network and security infrastructure",
    domains: [
      "cisco.com", "developer.cisco.com",
      "my.f5.com", "clouddocs.f5.com", "techdocs.f5.com", "support.f5.com",
      "docs.paloaltonetworks.com", "knowledgebase.paloaltonetworks.com",
      "docs.fortinet.com", "community.fortinet.com"
    ]
  }
};

const SYSTEM_PROMPT = `
You are a senior network and security engineer.

Use ONLY the supplied search evidence.
Answer the user's exact technical question.

STRICT RULES:
1. Match the exact vendor, product, feature and task.
2. Do not treat a vendor domain as proof that a page is relevant.
3. Exclude generic labs, unrelated products and unrelated tutorials.
4. Never invent commands, flags, paths or syntax.
5. Only suggest commands directly supported by the supplied source content.
6. Distinguish Linux shell commands from vendor CLI commands.
7. Never suggest displaying, copying, exporting or exposing private keys.
8. Prefer read-only diagnostic commands.
9. Clearly identify configuration-changing and disruptive commands.
10. If evidence is insufficient, return an empty commands array.
11. Do not claim that a command verifies something unless the source supports that exact purpose.
12. Do not assume a command is valid for a requested software version unless the evidence supports it.

Return ONLY valid JSON:
{
 "summary":"Answer",
 "causes":[{"title":"Cause","detail":"Explanation"}],
 "commands":[
  {
   "command":"Exact command",
   "platform":"Platform and CLI context",
   "description":"Purpose",
   "when_to_use":"When to use",
   "risk":"Read-only",
   "source_title":"Exact source title",
   "source_url":"Exact source URL"
  }
 ],
 "sources":[{"title":"Source title","url":"Exact URL"}],
 "safety_note":"Safety note"
}

Do not use Markdown fences.
`;

function response(data, status, headers) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...headers
    }
  });
}

function getCors(origin, allowed) {
  const valid = allowed.includes("*") || allowed.includes(origin);
  return {
    "Access-Control-Allow-Origin": valid
      ? (allowed.includes("*") ? "*" : origin)
      : "null",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin"
  };
}

function detectVendor(vendor, query) {
  const text = `${vendor} ${query}`.toLowerCase();

  if (/\bf5\b|big-?ip|tmsh|\bawaf\b|\basm\b|\bltm\b/.test(text)) return "f5";
  if (/cisco|\bftd\b|\bfmc\b|\basa\b|catalyst/.test(text)) return "cisco";
  if (/palo\s*alto|pan-os|panorama/.test(text)) return "paloalto";
  if (/fortinet|fortigate|fortimanager|fortios/.test(text)) return "fortinet";

  return "generic";
}

function extractVersion(text) {
  const match = String(text).match(
    /\b(?:BIG-IP|TMOS|PAN-OS|FortiOS|FTD|FMC)?\s*v?(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)\b/i
  );
  return match ? match[1] : "";
}

function buildQueries(vendorKey, vendor, query) {
  const config = VENDORS[vendorKey];
  const version = extractVersion(query);
  const versionText = version ? `version ${version}` : "";
  const q = query.replace(/\s+/g, " ").trim();

  if (vendorKey === "f5") {
    return [
      `F5 BIG-IP ${versionText} ${q} official technical documentation`,
      `F5 BIG-IP ${versionText} ${q} TMSH command reference`,
      `site:clouddocs.f5.com BIG-IP ${versionText} ${q}`
    ];
  }

  if (vendorKey === "cisco") {
    return [
      `Cisco ${versionText} ${q} official documentation`,
      `Cisco ${versionText} ${q} CLI command reference`,
      `site:cisco.com ${versionText} ${q}`
    ];
  }

  if (vendorKey === "paloalto") {
    return [
      `Palo Alto PAN-OS ${versionText} ${q} official documentation`,
      `PAN-OS ${versionText} ${q} CLI command reference`,
      `site:docs.paloaltonetworks.com ${versionText} ${q}`
    ];
  }

  if (vendorKey === "fortinet") {
    return [
      `Fortinet FortiOS ${versionText} ${q} official documentation`,
      `FortiGate ${versionText} ${q} CLI command reference`,
      `site:docs.fortinet.com ${versionText} ${q}`
    ];
  }

  return [
    `${vendor} ${q} official vendor documentation`,
    `${vendor} ${q} CLI command reference`,
    `${q} network security troubleshooting official documentation`
  ];
}

async function tavilySearch(apiKey, query, domains) {
  const res = await fetch("https://api.tavily.com/search", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
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
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(
      data?.detail?.error || data?.error || `Tavily HTTP ${res.status}`
    );
  }

  return Array.isArray(data.results) ? data.results : [];
}

function normalizeText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/https?:\/\/\S+/g, " ")
    .replace(/[^a-z0-9.+/#_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function getTokens(value) {
  const stopWords = new Set([
    "the", "and", "for", "with", "from", "that", "this",
    "how", "what", "when", "where", "are", "is", "on",
    "in", "to", "of", "a", "an", "using", "use", "check"
  ]);

  return normalizeText(value)
    .split(" ")
    .filter(word => word.length > 2 && !stopWords.has(word));
}

function isBadPage(result) {
  const title = normalizeText(result.title);
  const content = normalizeText(result.content);

  const badPatterns = [
    /\blab\s+\d+\b/,
    /\bhands on lab\b/,
    /\bvirtual lab\b/,
    /\btraining course\b/,
    /\bcourse overview\b/,
    /\bexam preparation\b/
  ];

  return badPatterns.some(pattern =>
    pattern.test(title) || pattern.test(content.slice(0, 250))
  );
}

function scoreRelevance(result, query, vendorKey) {
  if (isBadPage(result)) return 0;

  const text = normalizeText(
    `${result.title} ${result.content}`
  );

  const tokens = [...new Set(getTokens(query))];

  if (!tokens.length) return 0;

  let matched = 0;
  for (const token of tokens) {
    if (text.includes(token)) matched++;
  }

  let score = matched / tokens.length;

  const title = normalizeText(result.title);

  if (vendorKey === "f5" && (
    title.includes("big ip") ||
    title.includes("tmos") ||
    title.includes("client ssl") ||
    title.includes("ssl profile")
  )) {
    score += 0.2;
  }

  if (
    title.includes("command reference") ||
    title.includes("configuration guide") ||
    title.includes("administration guide")
  ) {
    score += 0.1;
  }

  return Math.min(score, 1);
}

function normalizeResults(items, query, vendorKey) {
  const seen = new Set();
  const results = [];

  for (const item of items) {
    const url = String(item?.url || "").trim();
    const content = String(item?.content || "").trim();

    if (!/^https:\/\//i.test(url)) continue;
    if (content.length < 30) continue;
    if (seen.has(url)) continue;

    seen.add(url);

    const result = {
      title: String(item.title || "Untitled source").slice(0, 250),
      url,
      content: content.slice(0, 2500),
      originalScore: Number(item.score || 0)
    };

    result.relevance = scoreRelevance(result, query, vendorKey);

    if (result.relevance >= 0.25) {
      results.push(result);
    }
  }

  return results
    .sort((a, b) =>
      (b.relevance + b.originalScore * 0.1) -
      (a.relevance + a.originalScore * 0.1)
    )
    .slice(0, 10);
}

function parseAI(output) {
  if (output && typeof output === "object") return output;

  if (typeof output !== "string" || !output.trim()) {
    throw new Error("Empty AI response");
  }

  const cleaned = output.trim()
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/\s*```$/i, "");

  try {
    return JSON.parse(cleaned);
  } catch (_) {
    const first = cleaned.indexOf("{");
    const last = cleaned.lastIndexOf("}");

    if (first >= 0 && last > first) {
      return JSON.parse(cleaned.slice(first, last + 1));
    }

    throw new Error("Invalid AI JSON response");
  }
}

// Strict check: the command itself must appear in the source content.
// This intentionally rejects commands that AI inferred or invented.
function commandAppearsInSource(command, source) {
  const normalizedCommand = normalizeText(command);
  const normalizedContent = normalizeText(source.content);

  if (normalizedCommand.length < 8) return false;

  return normalizedContent.includes(normalizedCommand);
}

function isSensitiveCommand(command) {
  const text = String(command || "").toLowerCase();

  const patterns = [
    /\bcat\b.*\b(key|private)\b/,
    /\bshow\b.*\bprivate[- ]key\b/,
    /\bexport\b.*\bprivate[- ]key\b/,
    /\bcopy\b.*\bprivate[- ]key\b/,
    /certificate_key_d/,
    /privatekey/
  ];

  return patterns.some(pattern => pattern.test(text));
}

function safeRisk(value) {
  const risk = String(value || "").toLowerCase();

  if (/disrupt|restart|reload|delete|remove|replace|modify|install|import|change/.test(risk)) {
    return "Potentially disruptive";
  }

  if (/config|write|set|create|update/.test(risk)) {
    return "Changes configuration";
  }

  return "Read-only";
}

function normalizeAIData(data, results) {
  const emptyResult = {
    summary: "The search results did not provide enough relevant evidence to verify commands for this question.",
    causes: [],
    commands: [],
    sources: [],
    safety_note: "No Internet commands are presented because the available sources did not sufficiently support them. Verify against the official documentation for your exact product and version."
  };

  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return emptyResult;
  }

  const byUrl = new Map(results.map(r => [r.url, r]));

  const selectedSources = Array.isArray(data.sources)
    ? data.sources
        .filter(s => s && byUrl.has(s.url))
        .map(s => byUrl.get(s.url))
    : [];

  const uniqueSources = [
    ...new Map(selectedSources.map(s => [s.url, s])).values()
  ];

  const sourceUrls = new Set(uniqueSources.map(s => s.url));

  const commands = (Array.isArray(data.commands) ? data.commands : [])
    .slice(0, 10)
    .filter(c => {
      if (!c || typeof c.command !== "string") return false;
      if (isSensitiveCommand(c.command)) return false;
      if (!sourceUrls.has(c.source_url)) return false;

      const source = byUrl.get(c.source_url);
      return source && commandAppearsInSource(c.command, source);
    })
    .map(c => ({
      command: c.command,
      platform: String(c.platform || ""),
      description: String(c.description || ""),
      when_to_use: String(c.when_to_use || ""),
      risk: safeRisk(c.risk),
      source_title: byUrl.get(c.source_url).title,
      source_url: c.source_url
    }));

  const verifiedSources = commands.length
    ? uniqueSources
    : [];

  return {
    summary: commands.length
      ? String(data.summary || "")
      : "The search found related documentation, but it did not provide enough direct evidence to verify an exact command for this task.",
    causes: Array.isArray(data.causes) ? data.causes.slice(0, 8) : [],
    commands,
    sources: verifiedSources.map(s => ({
      title: s.title,
      url: s.url
    })),
    safety_note: commands.length
      ? String(data.safety_note || "Verify commands against your exact software version before execution.")
      : "No verified Internet commands are displayed. The search results may be related to the topic but do not prove the exact command syntax and purpose."
  };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";

    const allowed = (env.ALLOWED_ORIGINS ||
      DEFAULT_ALLOWED_ORIGINS.join(","))
      .split(",")
      .map(x => x.trim())
      .filter(Boolean);

    const headers = getCors(origin, allowed);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers });
    }

    if (request.method !== "POST") {
      return response({ error: "Use POST /search" }, 405, headers);
    }

    if (headers["Access-Control-Allow-Origin"] === "null") {
      return response({ error: "Origin not allowed" }, 403, headers);
    }

    if (!env.AI) {
      return response({ error: "Cloudflare AI binding AI is missing" }, 503, headers);
    }

    if (!env.TAVILY_KEY) {
      return response({ error: "TAVILY_KEY secret is missing" }, 503, headers);
    }

    let body;

    try {
      body = await request.json();
    } catch (_) {
      return response({ error: "Invalid JSON request body" }, 400, headers);
    }

    const query = String(body.query || "").trim().slice(0, 1200);
    const vendor = String(body.vendor || "Network infrastructure").trim();

    if (query.length < 4) {
      return response({ error: "Please enter a more detailed question" }, 400, headers);
    }

    try {
      const vendorKey = detectVendor(vendor, query);
      const config = VENDORS[vendorKey];
      const queries = buildQueries(vendorKey, vendor, query);

      const batches = await Promise.all(
        queries.map(q => tavilySearch(env.TAVILY_KEY, q, config.domains))
      );

      const results = normalizeResults(
        batches.flat(),
        query,
        vendorKey
      );

      if (!results.length) {
        return response({
          summary: "No sufficiently relevant official documentation was found.",
          causes: [],
          commands: [],
          sources: [],
          safety_note: "No Internet commands are presented because relevant supporting evidence was not found."
        }, 200, headers);
      }

      const evidence = results.map((r, i) => `
RESULT ${i + 1}
Title: ${r.title}
URL: ${r.url}
Relevance: ${r.relevance}
Content:
${r.content}
`).join("\n-------------------\n");

      const version = extractVersion(query);

      const prompt = `
User-selected vendor: ${vendor}
Detected product: ${config.label}
Requested version: ${version || "Not specified"}

Exact user question:
${query}

Search evidence:
${evidence}

Important:
- Select only directly relevant sources.
- Do not select generic lab pages or unrelated documentation.
- Do not infer command syntax from a general description.
- A command must be explicitly present in the source content.
- If a source does not show the exact command, do not return it.
- Do not claim that a command verifies certificate chains unless the source explicitly supports that function.
- Do not provide commands that expose private keys.
- If no command is directly supported, return an empty commands array.
- Every source URL must be copied exactly.

Return the required JSON object only.
`;

      const aiResult = await env.AI.run(MODEL, {
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: prompt }
        ],
        response_format: { type: "json_object" },
        max_tokens: 2400,
        temperature: 0.1
      });

      const output =
        aiResult?.response ??
        aiResult?.choices?.[0]?.message?.content ??
        null;

      if (output === null || output === undefined) {
        throw new Error("Cloudflare AI returned an empty response");
      }

      const parsed = parseAI(output);
      const finalData = normalizeAIData(parsed, results);

      return response(finalData, 200, headers);

    } catch (error) {
      return response({
        error: "Internet search or AI processing failed.",
        details: error?.message || "Unknown error"
      }, 502, headers);
    }
  }
};
