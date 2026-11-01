
/**
 * NetOps Command Finder
 * Multi-query Tavily search + Cloudflare Workers AI
 * Required Cloudflare bindings/secrets:
 *   - AI (Workers AI binding)
 *   - TAVILY_KEY (Secret)
 */

const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
const DEFAULT_ALLOWED_ORIGINS = ["https://esllammohsen.github.io"];

const VENDOR_CONFIG = {
  f5: {
    label: "F5 BIG-IP / TMOS",
    domains: ["my.f5.com", "clouddocs.f5.com", "techdocs.f5.com", "support.f5.com"]
  },
  cisco: {
    label: "Cisco network and security products",
    domains: ["cisco.com", "developer.cisco.com"]
  },
  paloalto: {
    label: "Palo Alto Networks PAN-OS",
    domains: ["docs.paloaltonetworks.com", "knowledgebase.paloaltonetworks.com"]
  },
  fortinet: {
    label: "Fortinet FortiGate / FortiOS",
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

const SYSTEM_PROMPT = `You are a senior network and security infrastructure engineer.
Analyze the user's exact technical question using ONLY the supplied search results.

Relevance requirements:
- Match the exact product, feature, task, and requested software version.
- Prefer official vendor documentation and official vendor knowledge-base articles.
- Exclude unrelated products, mobile apps, cloud integrations, and unrelated guides, even if they belong to the same vendor.
- Treat search snippets as evidence, not proof of details they do not contain.

Command requirements:
- Only provide commands whose syntax and purpose are directly supported by supplied results.
- Never invent commands, flags, file paths, TMSH hierarchy, or configuration syntax.
- Identify the correct CLI context (for example, BIG-IP TMSH versus Linux shell).
- Prefer read-only diagnostics.
- Clearly label configuration changes and potentially disruptive actions.
- Never recommend exposing or copying private keys into chat or logs.
- If evidence is insufficient, return an empty commands array and explain the limitation.

Return ONLY a JSON object with this structure:
{
 "summary":"Answer to the exact question",
 "causes":[{"title":"Possible cause","detail":"Explanation and verification"}],
 "commands":[{"command":"Exact command","platform":"Product/version and CLI context","description":"What it does","when_to_use":"When to use it","risk":"Read-only | Changes configuration | Potentially disruptive","source_title":"Exact result title","source_url":"Exact result URL"}],
 "sources":[{"title":"Exact result title","url":"Exact result URL"}],
 "safety_note":"Safety or version caveat"
}

Every source_url must be copied exactly from the supplied results. Do not fabricate URLs. Return valid JSON only, without Markdown fences.`;

function corsHeaders(origin, allowed) {
  const ok = allowed.includes("*") || allowed.includes(origin);
  return {
    "Access-Control-Allow-Origin": ok ? (allowed.includes("*") ? "*" : origin) : "null",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin"
  };
}

function jsonResponse(data, status, headers) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers }
  });
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
  const m = String(text).match(/\b(?:BIG-IP|TMOS|PAN-OS|FortiOS|FTD|FMC)?\s*v?(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)\b/i);
  return m ? m[1] : "";
}

function buildQueries(vendorKey, vendor, query) {
  const config = VENDOR_CONFIG[vendorKey];
  const version = extractVersion(query);
  const product = config.label || vendor;
  const versionPhrase = version ? `version ${version}` : "";
  const cleanQuestion = query.replace(/\s+/g, " ").trim();

  // Three focused basic searches balance retrieval coverage and Tavily credit use.
  if (vendorKey === "f5") {
    return [
      `${product} ${versionPhrase} ${cleanQuestion} official documentation`,
      `F5 BIG-IP ${versionPhrase} ${cleanQuestion} TMSH configuration troubleshooting`,
      `F5 BIG-IP ${versionPhrase} ${cleanQuestion} site:clouddocs.f5.com OR site:my.f5.com`
    ];
  }
  if (vendorKey === "cisco") {
    return [
      `${product} ${versionPhrase} ${cleanQuestion} official configuration guide`,
      `Cisco ${versionPhrase} ${cleanQuestion} CLI troubleshooting command`,
      `Cisco ${versionPhrase} ${cleanQuestion} official technical documentation`
    ];
  }
  if (vendorKey === "paloalto") {
    return [
      `${product} ${versionPhrase} ${cleanQuestion} official documentation`,
      `PAN-OS ${versionPhrase} ${cleanQuestion} CLI troubleshooting`,
      `Palo Alto Networks ${versionPhrase} ${cleanQuestion} configuration guide`
    ];
  }
  if (vendorKey === "fortinet") {
    return [
      `${product} ${versionPhrase} ${cleanQuestion} official documentation`,
      `FortiGate FortiOS ${versionPhrase} ${cleanQuestion} CLI troubleshooting`,
      `Fortinet ${versionPhrase} ${cleanQuestion} administration guide`
    ];
  }
  return [
    `${vendor} ${cleanQuestion} official vendor documentation`,
    `${vendor} ${cleanQuestion} CLI troubleshooting commands`,
    `${cleanQuestion} network security configuration troubleshooting official documentation`
  ];
}

async function tavilySearch(apiKey, query, domains) {
  const response = await fetch("https://api.tavily.com/search", {
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

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = payload?.detail?.error || payload?.error || `Tavily HTTP ${response.status}`;
    throw new Error(detail);
  }
  return Array.isArray(payload.results) ? payload.results : [];
}

function normalizeResults(allResults) {
  const seen = new Set();
  const results = [];
  for (const item of allResults) {
    const url = String(item?.url || "").trim();
    const content = String(item?.content || "").trim();
    if (!/^https:\/\//i.test(url) || content.length < 25 || seen.has(url)) continue;
    seen.add(url);
    results.push({
      title: String(item.title || "Untitled source").slice(0, 250),
      url,
      content: content.slice(0, 1800),
      score: typeof item.score === "number" ? item.score : 0
    });
  }
  return results.sort((a, b) => b.score - a.score).slice(0, 10);
}

function parseAIResponse(output) {
  if (output && typeof output === "object") return output;
  if (typeof output !== "string" || !output.trim()) throw new Error("Empty AI response");
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
    if (first >= 0 && last > first) return JSON.parse(cleaned.slice(first, last + 1));
    throw new Error("AI response is not valid JSON");
  }
}

function normalizeAIData(data, results) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("Invalid AI response structure");
  }

  const resultByUrl = new Map(results.map(r => [r.url, r]));
  const requestedSources = Array.isArray(data.sources) ? data.sources : [];
  const sources = requestedSources
    .filter(s => s && typeof s.url === "string" && resultByUrl.has(s.url))
    .map(s => ({ title: resultByUrl.get(s.url).title, url: s.url }))
    .slice(0, 8);

  const approvedUrls = new Set(sources.map(s => s.url));
  const commands = (Array.isArray(data.commands) ? data.commands : [])
    .slice(0, 10)
    .map(c => {
      const sourceUrl = typeof c.source_url === "string" && approvedUrls.has(c.source_url)
        ? c.source_url : "";
      return {
        command: String(c.command || ""),
        platform: String(c.platform || ""),
        description: String(c.description || ""),
        when_to_use: String(c.when_to_use || ""),
        risk: String(c.risk || "Read-only"),
        source_title: sourceUrl ? resultByUrl.get(sourceUrl).title : "",
        source_url: sourceUrl
      };
    })
    .filter(c => c.command && c.source_url);

  return {
    summary: String(data.summary || ""),
    causes: Array.isArray(data.causes) ? data.causes.slice(0, 8) : [],
    commands,
    sources,
    safety_note: String(data.safety_note || "Verify commands against the exact product and software version before execution.")
  };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = (env.ALLOWED_ORIGINS || DEFAULT_ALLOWED_ORIGINS.join(","))
      .split(",").map(x => x.trim()).filter(Boolean);
    const headers = corsHeaders(origin, allowed);

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
    if (request.method !== "POST") return jsonResponse({ error: "Use POST /search" }, 405, headers);
    if (headers["Access-Control-Allow-Origin"] === "null") return jsonResponse({ error: "Origin not allowed" }, 403, headers);
    if (!env.AI) return jsonResponse({ error: "Cloudflare AI binding AI is not configured" }, 503, headers);
    if (!env.TAVILY_KEY) return jsonResponse({ error: "TAVILY_KEY secret is missing" }, 503, headers);

    let body;
    try {
      body = await request.json();
    } catch (_) {
      return jsonResponse({ error: "Invalid JSON request body" }, 400, headers);
    }

    const query = String(body.query || "").trim().slice(0, 1200);
    const vendor = String(body.vendor || "Network infrastructure").trim().slice(0, 100);
    if (query.length < 4) return jsonResponse({ error: "Please describe your issue in more detail" }, 400, headers);

    try {
      const vendorKey = detectVendor(vendor, query);
      const config = VENDOR_CONFIG[vendorKey];
      const queries = buildQueries(vendorKey, vendor, query);

      // Run three focused Tavily searches in parallel, then deduplicate results.
      const batches = await Promise.all(
        queries.map(q => tavilySearch(env.TAVILY_KEY, q, config.domains))
      );
      const results = normalizeResults(batches.flat());

      if (!results.length) {
        return jsonResponse({
          error: "No usable official documentation results were found. Try specifying the exact product, feature, and software version."
        }, 502, headers);
      }

      const evidence = results.map((r, i) => [
        `RESULT ${i + 1}`,
        `Title: ${r.title}`,
        `URL: ${r.url}`,
        `Relevance score: ${r.score}`,
        `Content: ${r.content}`
      ].join("\n")).join("\n\n----------------\n\n");

      const version = extractVersion(query);
      const prompt = `
Vendor selected by user: ${vendor}
Detected product family: ${config.label}
Requested software version: ${version || "Not specified"}

Exact user question:
${query}

Search queries used:
${queries.map((q, i) => `${i + 1}. ${q}`).join("\n")}

Deduplicated official-domain search evidence:
${evidence}

Task:
1. Select only sources directly relevant to the exact question.
2. Exclude unrelated vendor products, apps, integrations, and guides.
3. If the result snippets do not prove an exact command, do not provide that command.
4. Every command must cite one of the supplied result URLs exactly.
5. If there is not enough evidence, return no internet commands and clearly explain why.
6. Do not confuse an OpenSSL/Linux command with a BIG-IP TMSH command.

Return only the required JSON object.
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

      const output = aiResult?.response ?? aiResult?.choices?.[0]?.message?.content ?? null;
      if (output === null || output === undefined) {
        return jsonResponse({ error: "Cloudflare AI returned an empty response" }, 502, headers);
      }

      const parsed = parseAIResponse(output);
      const finalData = normalizeAIData(parsed, results);
      return jsonResponse(finalData, 200, headers);

    } catch (error) {
      return jsonResponse({
        error: "Internet search or AI processing failed.",
        details: error?.message || "Unknown error"
      }, 502, headers);
    }
  }
};
