
/**
 * NetOps Command Finder - Cloudflare Worker
 * Uses Tavily Search + Cloudflare Workers AI.
 *
 * Required Cloudflare configuration:
 * 1. AI binding
 * 2. TAVILY_KEY secret
 *
 * Endpoint: POST /search
 */

const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";

const DEFAULT_ALLOWED_ORIGINS = [
  "https://esllammohsen.github.io"
];

const VENDORS = {
  f5: {
    label: "F5 BIG-IP / TMOS",
    domains: [
      "my.f5.com",
      "clouddocs.f5.com",
      "techdocs.f5.com",
      "support.f5.com"
    ]
  },

  cisco: {
    label: "Cisco network and security products",
    domains: [
      "cisco.com",
      "developer.cisco.com"
    ]
  },

  paloalto: {
    label: "Palo Alto Networks PAN-OS",
    domains: [
      "docs.paloaltonetworks.com",
      "knowledgebase.paloaltonetworks.com"
    ]
  },

  fortinet: {
    label: "Fortinet FortiGate / FortiOS",
    domains: [
      "docs.fortinet.com",
      "community.fortinet.com"
    ]
  },

  generic: {
    label: "Network and security infrastructure",
    domains: [
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
  }
};

const SYSTEM_PROMPT = `
You are a professional network and security infrastructure
research assistant.

Use ONLY the supplied search results.

Return valid JSON with exactly these fields:

summary
causes
commands
sources
safety_note

CAUSE REQUIREMENTS:

Each cause must include:
- title
- detail
- source_url
- evidence_quote

The evidence_quote must be copied verbatim from the
supplied source content.

The quote must directly support the cause.

Do not infer a cause from a related setting or feature.

If direct evidence does not exist, omit the cause.

COMMAND REQUIREMENTS:

Each command must include:
- command
- platform
- description
- when_to_use
- risk
- source_title
- source_url

Only return commands when their exact syntax appears
in the supplied source content.

The source must also support the stated purpose.

Do not invent:
- Commands
- Flags
- Parameters
- File paths
- CLI contexts
- Configuration procedures

Clearly distinguish between:
- Vendor CLI
- Linux shell
- Expert mode
- Diagnostic CLI
- GUI instructions

Never provide commands that reveal, copy, export,
print, or expose private keys.

Prefer read-only commands.

Mark configuration changes and disruptive actions accurately.

Do not claim compatibility with a specific software version
unless the supplied evidence explicitly supports it.

SOURCES:

Only use URLs supplied in the search results.

Do not treat an official vendor domain alone as proof
that a page supports a command or cause.

Exclude unrelated pages, generic labs, and training material.

If evidence is insufficient, return empty causes and commands.

Never fabricate evidence.

Return JSON only.
`;

function corsHeaders(origin, allowed) {
  const ok =
    allowed.includes("*") ||
    allowed.includes(origin);

  return {
    "Access-Control-Allow-Origin": ok
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

function detectVendor(vendor, query) {
  const t = `${vendor} ${query}`.toLowerCase();

  if (
    /\bf5\b|big-?ip|tmsh|\bawaf\b|\basm\b|\bltm\b/.test(t)
  ) {
    return "f5";
  }

  if (
    /cisco|\bftd\b|\bfmc\b|\basa\b|catalyst/.test(t)
  ) {
    return "cisco";
  }

  if (
    /palo\s*alto|pan-os|panorama/.test(t)
  ) {
    return "paloalto";
  }

  if (
    /fortinet|fortigate|fortimanager|fortios/.test(t)
  ) {
    return "fortinet";
  }

  return "generic";
}

function extractVersion(text) {
  const match = String(text).match(
    /\b(?:BIG-IP|TMOS|PAN-OS|FortiOS|FTD|FMC)\s*v?(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)\b/i
  );

  return match ? match[1] : "";
}

function buildQueries(key, vendor, query) {
  const version = extractVersion(query);

  const versionText = version
    ? `version ${version}`
    : "";

  const cleanQuery = query
    .replace(/\s+/g, " ")
    .trim();

  if (key === "f5") {
    return [
      `F5 BIG-IP ${versionText} ${cleanQuery} official documentation`,
      `F5 BIG-IP ${versionText} ${cleanQuery} command reference TMSH`,
      `site:clouddocs.f5.com BIG-IP ${versionText} ${cleanQuery}`
    ];
  }

  if (key === "cisco") {
    return [
      `Cisco ${versionText} ${cleanQuery} official documentation`,
      `Cisco ${versionText} ${cleanQuery} CLI command reference`,
      `site:cisco.com ${versionText} ${cleanQuery}`
    ];
  }

  if (key === "paloalto") {
    return [
      `Palo Alto PAN-OS ${versionText} ${cleanQuery} official documentation`,
      `PAN-OS ${versionText} ${cleanQuery} CLI command reference`,
      `site:docs.paloaltonetworks.com ${versionText} ${cleanQuery}`
    ];
  }

  if (key === "fortinet") {
    return [
      `Fortinet FortiOS ${versionText} ${cleanQuery} official documentation`,
      `FortiGate ${versionText} ${cleanQuery} CLI command reference`,
      `site:docs.fortinet.com ${versionText} ${cleanQuery}`
    ];
  }

  return [
    `${vendor} ${cleanQuery} official documentation`,
    `${vendor} ${cleanQuery} CLI command reference`,
    `${cleanQuery} network security troubleshooting documentation`
  ];
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

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data?.detail?.error ||
      data?.error ||
      `Tavily HTTP ${response.status}`
    );
  }

  return Array.isArray(data.results)
    ? data.results
    : [];
}

function normalizeText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&gt;/g, ">")
    .replace(/&lt;/g, "<")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
}

function isIrrelevantPage(item) {
  const text = normalizeText(
    `${item.title} ${item.content.slice(0, 500)}`
  );

  return (
    /\blab\s*\d+\b|hands.on lab|virtual lab|exam preparation|course overview|training course/.test(text)
  );
}

function relevance(item, query) {
  if (isIrrelevantPage(item)) {
    return 0;
  }

  const content = normalizeText(
    `${item.title} ${item.content}`
  );

  const stopWords = new Set([
    "the", "and", "for", "with", "from",
    "that", "this", "how", "what", "when",
    "where", "are", "is", "on", "in", "to",
    "of", "a", "an", "using", "use", "check",
    "verify"
  ]);

  const terms = [
    ...new Set(
      normalizeText(query)
        .split(/[^a-z0-9.+#_-]+/)
        .filter(
          word =>
            word.length > 2 &&
            !stopWords.has(word)
        )
    )
  ];

  if (!terms.length) {
    return 0;
  }

  const matched = terms.filter(
    word => content.includes(word)
  ).length;

  return matched / terms.length;
}

function normalizeResults(items, query) {
  const seen = new Set();
  const output = [];

  for (const item of items) {
    const url = String(item?.url || "").trim();

    const content = String(
      item?.content || ""
    ).trim();

    if (
      !/^https:\/\//i.test(url) ||
      content.length < 35 ||
      seen.has(url)
    ) {
      continue;
    }

    let hostname;

    try {
      hostname = new URL(url).hostname.toLowerCase();
    } catch {
      continue;
    }

    const trustedDomain = Object.values(VENDORS)
      .some(vendor =>
        vendor.domains.some(
          domain =>
            hostname === domain ||
            hostname.endsWith(`.${domain}`)
        )
      );

    if (!trustedDomain) {
      continue;
    }

    const result = {
      title: String(
        item.title || "Untitled source"
      ).slice(0, 250),

      url,

      content: content.slice(0, 3000),

      score: Number(item.score || 0)
    };

    result.relevance = relevance(result, query);

    if (result.relevance >= 0.20) {
      seen.add(url);
      output.push(result);
    }
  }

  return output
    .sort(
      (a, b) =>
        (b.relevance + b.score * 0.1) -
        (a.relevance + a.score * 0.1)
    )
    .slice(0, 10);
}

function parseAI(output) {
  if (
    output &&
    typeof output === "object"
  ) {
    return output;
  }

  const text = String(output || "")
    .trim()
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/\s*```$/i, "");

  try {
    return JSON.parse(text);
  } catch {
    const start = text.indexOf("{");
    const end = text.lastIndexOf("}");

    if (start >= 0 && end > start) {
      return JSON.parse(
        text.slice(start, end + 1)
      );
    }

    throw new Error(
      "AI response is not valid JSON"
    );
  }
}

function commandIsSensitive(command) {
  return (
    /\b(private.?key|key.?file|certificate_key_d)\b/i.test(command) &&
    /\b(cat|type|more|less|copy|cp|export|show|list|print|dump)\b/i.test(command)
  );
}

function commandIsInSource(command, source) {
  const normalizedCommand = normalizeText(command);
  const normalizedSource = normalizeText(source.content);

  return (
    normalizedCommand.length >= 8 &&
    normalizedSource.includes(normalizedCommand)
  );
}

function quoteIsInSource(quote, source) {
  const normalizedQuote = normalizeText(quote);
  const normalizedSource = normalizeText(source.content);

  return (
    normalizedQuote.length >= 25 &&
    normalizedSource.includes(normalizedQuote)
  );
}

function riskLabel(value, command) {
  const text = `${value || ""} ${command || ""}`.toLowerCase();

  if (
    /\b(restart|reboot|reload|delete|remove|replace|force-full-load-push|clear|flush)\b/.test(text)
  ) {
    return "Potentially disruptive";
  }

  if (
    /\b(modify|install|import|create|set|save|enable|disable|export)\b/.test(text)
  ) {
    return "Changes configuration";
  }

  return "Read-only";
}

function normalizeAIData(data, results) {
  const sourcesByUrl = new Map(
    results.map(result => [
      result.url,
      result
    ])
  );

  const acceptedCauses = (
    Array.isArray(data?.causes)
      ? data.causes
      : []
  )
    .filter(cause => {
      const source = sourcesByUrl.get(
        cause?.source_url
      );

      return (
        source &&
        quoteIsInSource(
          cause.evidence_quote,
          source
        )
      );
    })
    .slice(0, 6);

  const causes = acceptedCauses.map(cause => ({
    title: String(cause.title || ""),
    detail: String(cause.detail || "")
  }));

  const commands = (
    Array.isArray(data?.commands)
      ? data.commands
      : []
  )
    .filter(command => {
      const source = sourcesByUrl.get(
        command?.source_url
      );

      return (
        source &&
        typeof command.command === "string" &&
        !commandIsSensitive(command.command) &&
        commandIsInSource(
          command.command,
          source
        )
      );
    })
    .slice(0, 10)
    .map(command => ({
      command: command.command,

      platform: String(
        command.platform || ""
      ),

      description: String(
        command.description || ""
      ),

      when_to_use: String(
        command.when_to_use || ""
      ),

      risk: riskLabel(
        command.risk,
        command.command
      ),

      source_title: sourcesByUrl.get(
        command.source_url
      ).title,

      source_url: command.source_url
    }));

  const acceptedUrls = new Set([
    ...acceptedCauses
      .map(cause => cause.source_url)
      .filter(Boolean),

    ...commands
      .map(command => command.source_url)
      .filter(Boolean)
  ]);

  const sources = [
    ...acceptedUrls
  ].map(url => ({
    title: sourcesByUrl.get(url).title,
    url
  }));

  const hasEvidence =
    causes.length > 0 ||
    commands.length > 0;

  return {
    summary: hasEvidence
      ? String(data.summary || "")
      : "Related pages were found, but they did not provide enough direct evidence to verify a cause or command for this exact question.",

    causes,

    commands,

    sources,

    safety_note: hasEvidence
      ? String(
          data.safety_note ||
          "Verify the exact product version and operational context before making changes."
        )
      : "No verified Internet causes or commands are displayed. The available search evidence did not directly support them."
  };
}

export default {
  async fetch(request, env) {
    const origin =
      request.headers.get("Origin") || "";

    const allowed = (
      env.ALLOWED_ORIGINS ||
      DEFAULT_ALLOWED_ORIGINS.join(",")
    )
      .split(",")
      .map(value => value.trim())
      .filter(Boolean);

    const headers = corsHeaders(
      origin,
      allowed
    );

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

    if (
      headers["Access-Control-Allow-Origin"] === "null"
    ) {
      return jsonResponse(
        { error: "Origin not allowed" },
        403,
        headers
      );
    }

    if (!env.AI) {
      return jsonResponse(
        {
          error: "Cloudflare Workers AI binding AI is not configured"
        },
        503,
        headers
      );
    }

    if (!env.TAVILY_KEY) {
      return jsonResponse(
        {
          error: "TAVILY_KEY secret is missing"
        },
        503,
        headers
      );
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return jsonResponse(
        { error: "Invalid JSON request body" },
        400,
        headers
      );
    }

    const query = String(
      body.query || ""
    )
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
          error: "Please describe your issue in more detail"
        },
        400,
        headers
      );
    }

    try {
      const vendorKey = detectVendor(
        vendor,
        query
      );

      const config = VENDORS[vendorKey];

      const queries = buildQueries(
        vendorKey,
        vendor,
        query
      );

      const batches = await Promise.all(
        queries.map(searchQuery =>
          tavilySearch(
            env.TAVILY_KEY,
            searchQuery,
            config.domains
          )
        )
      );

      const results = normalizeResults(
        batches.flat(),
        query
      );

      if (!results.length) {
        return jsonResponse(
          {
            summary: "No sufficiently relevant vendor documentation was found.",

            causes: [],

            commands: [],

            sources: [],

            safety_note: "No Internet commands or causes are displayed because relevant evidence was not found."
          },
          200,
          headers
        );
      }

      const evidence = results
        .map((result, index) =>
          `RESULT ${index + 1}
Title: ${result.title}
URL: ${result.url}
Content:
${result.content}`
        )
        .join("\n\n-----\n\n");

      const prompt = `
Vendor: ${vendor}

Detected product:
${config.label}

Version in question:
${extractVersion(query) || "Not specified"}

Exact user question:
${query}

Search evidence:
${evidence}

IMPORTANT VALIDATION RULES:

1. For every cause, include source_url and evidence_quote.

2. The evidence_quote must be copied exactly from the source content.

3. For every command, include source_url and reproduce the exact command text found in the source.

4. Do not reconstruct commands from examples or descriptions.

5. Do not infer a command's CLI mode unless the source states it.

6. Do not infer causes from a mention of a setting.

7. Do not present a configuration change as a read-only command.

8. Do not provide private-key extraction or exposure commands.

9. Sources must be exact URLs from the supplied evidence.

10. Return empty arrays when direct evidence is insufficient.

Return JSON only.
`;

      const ai = await env.AI.run(
        MODEL,
        {
          messages: [
            {
              role: "system",
              content: SYSTEM_PROMPT
            },
            {
              role: "user",
              content: prompt
            }
          ],

          response_format: {
            type: "json_object"
          },

          max_tokens: 2400,

          temperature: 0.1
        }
      );

      const output =
        ai?.response ??
        ai?.choices?.[0]?.message?.content ??
        null;

      if (
        output === null ||
        output === undefined
      ) {
        throw new Error(
          "Cloudflare AI returned an empty response"
        );
      }

      const result = normalizeAIData(
        parseAI(output),
        results
      );

      return jsonResponse(
        result,
        200,
        headers
      );

    } catch (error) {
      return jsonResponse(
        {
          error: "Internet search or AI processing failed.",

          details:
            error?.message || "Unknown error"
        },
        502,
        headers
      );
    }
  }
};
