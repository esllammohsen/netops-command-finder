/**
 * NetOps Command Finder - Cloudflare Worker
 * Uses Tavily search + Cloudflare Workers AI.
 * Required: AI binding and TAVILY_KEY secret.
 */
const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
const DEFAULT_ALLOWED_ORIGINS = ["https://esllammohsen.github.io"];

const VENDORS = {
  f5: { label: "F5 BIG-IP / TMOS", domains: ["my.f5.com", "clouddocs.f5.com", "techdocs.f5.com", "support.f5.com"] },
  cisco: { label: "Cisco network and security products", domains: ["cisco.com", "developer.cisco.com"] },
  paloalto: { label: "Palo Alto Networks PAN-OS", domains: ["docs.paloaltonetworks.com", "knowledgebase.paloaltonetworks.com"] },
  fortinet: { label: "Fortinet FortiGate / FortiOS", domains: ["docs.fortinet.com", "community.fortinet.com"] },
  generic: { label: "Network and security infrastructure", domains: ["cisco.com", "developer.cisco.com", "my.f5.com", "clouddocs.f5.com", "techdocs.f5.com", "support.f5.com", "docs.paloaltonetworks.com", "knowledgebase.paloaltonetworks.com", "docs.fortinet.com", "community.fortinet.com"] }
};

const SYSTEM_PROMPT = `You are a network and security infrastructure research assistant. Use ONLY the supplied search results.
Return JSON with exactly these fields: summary, causes, commands, sources, safety_note.
Each cause MUST include title, detail, source_url, evidence_quote. The quote must be copied verbatim from that source's supplied content and directly support the cause. If no direct evidence exists, omit the cause.
Each command MUST include command, platform, description, when_to_use, risk, source_title, source_url. Only return a command if its exact syntax appears in supplied source content AND that content supports the stated purpose. Do not invent or infer commands, flags, paths, or CLI context. Distinguish vendor CLI from Linux shell. Never provide commands that reveal, copy, export, or print private keys. Prefer read-only commands. Mark changes and disruptive actions accurately.
Sources must be selected from supplied results only. Do not treat a vendor domain as proof of relevance. Exclude generic labs and unrelated pages. If evidence is insufficient, return empty causes and commands and state that clearly. Do not claim version compatibility unless the evidence explicitly supports it. Output valid JSON only.`;

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
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", ...headers } });
}
function detectVendor(vendor, query) {
  const t = `${vendor} ${query}`.toLowerCase();
  if (/\bf5\b|big-?ip|tmsh|\bawaf\b|\basm\b|\bltm\b/.test(t)) return "f5";
  if (/cisco|\bftd\b|\bfmc\b|\basa\b|catalyst/.test(t)) return "cisco";
  if (/palo\s*alto|pan-os|panorama/.test(t)) return "paloalto";
  if (/fortinet|fortigate|fortimanager|fortios/.test(t)) return "fortinet";
  return "generic";
}
function extractVersion(text) {
  const m = String(text).match(/\b(?:BIG-IP|TMOS|PAN-OS|FortiOS|FTD|FMC)\s*v?(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)\b/i);
  return m ? m[1] : "";
}
function buildQueries(key, vendor, query) {
  const version = extractVersion(query);
  const v = version ? `version ${version}` : "";
  const q = query.replace(/\s+/g, " ").trim();
  if (key === "f5") return [
    `F5 BIG-IP ${v} ${q} official documentation`,
    `F5 BIG-IP ${v} ${q} command reference TMSH`,
    `site:clouddocs.f5.com BIG-IP ${v} ${q}`
  ];
  if (key === "cisco") return [
    `Cisco ${v} ${q} official documentation`,
    `Cisco ${v} ${q} CLI command reference`,
    `site:cisco.com ${v} ${q}`
  ];
  if (key === "paloalto") return [
    `Palo Alto PAN-OS ${v} ${q} official documentation`,
    `PAN-OS ${v} ${q} CLI command reference`,
    `site:docs.paloaltonetworks.com ${v} ${q}`
  ];
  if (key === "fortinet") return [
    `Fortinet FortiOS ${v} ${q} official documentation`,
    `FortiGate ${v} ${q} CLI command reference`,
    `site:docs.fortinet.com ${v} ${q}`
  ];
  return [`${vendor} ${q} official documentation`, `${vendor} ${q} CLI command reference`, `${q} network security troubleshooting documentation`];
}
async function tavilySearch(apiKey, query, domains) {
  const res = await fetch("https://api.tavily.com/search", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ api_key: apiKey, query, search_depth: "basic", topic: "general", max_results: 5, include_answer: false, include_raw_content: false, include_domains: domains })
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.detail?.error || data?.error || `Tavily HTTP ${res.status}`);
  return Array.isArray(data.results) ? data.results : [];
}
function normalizeText(s) {
  return String(s || "").toLowerCase().replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&gt;/g, ">").replace(/&lt;/g, "<").replace(/&amp;/g, "&").replace(/\s+/g, " ").trim();
}
function isIrrelevantPage(item) {
  const t = normalizeText(`${item.title} ${item.content.slice(0, 500)}`);
  return /\blab\s*\d+\b|hands.on lab|virtual lab|exam preparation|course overview|training course/.test(t);
}
function relevance(item, query) {
  if (isIrrelevantPage(item)) return 0;
  const content = normalizeText(`${item.title} ${item.content}`);
  const stop = new Set(["the","and","for","with","from","that","this","how","what","when","where","are","is","on","in","to","of","a","an","using","use","check","verify"]);
  const terms = [...new Set(normalizeText(query).split(/[^a-z0-9.+#_-]+/).filter(x => x.length > 2 && !stop.has(x)))];
  if (!terms.length) return 0;
  const matched = terms.filter(x => content.includes(x)).length;
  return matched / terms.length;
}
function normalizeResults(items, query) {
  const seen = new Set();
  const out = [];
  for (const x of items) {
    const url = String(x?.url || "").trim();
    const content = String(x?.content || "").trim();
    if (!/^https:\/\//i.test(url) || content.length < 35 || seen.has(url)) continue;
    let host;
    try { host = new URL(url).hostname.toLowerCase(); } catch { continue; }
    if (!Object.values(VENDORS).some(v => v.domains.some(d => host === d || host.endsWith(`.${d}`)))) continue;
    const item = { title: String(x.title || "Untitled source").slice(0, 250), url, content: content.slice(0, 3000), score: Number(x.score || 0) };
    item.relevance = relevance(item, query);
    if (item.relevance >= 0.20) { seen.add(url); out.push(item); }
  }
  return out.sort((a,b) => (b.relevance + b.score * 0.1) - (a.relevance + a.score * 0.1)).slice(0, 10);
}
function parseAI(output) {
  if (output && typeof output === "object") return output;
  const s = String(output || "").trim().replace(/^```json\s*/i, "").replace(/^```\s*/i, "").replace(/\s*```$/i, "");
  try { return JSON.parse(s); } catch {
    const a = s.indexOf("{"); const b = s.lastIndexOf("}");
    if (a >= 0 && b > a) return JSON.parse(s.slice(a, b + 1));
    throw new Error("AI response is not valid JSON");
  }
}
function commandIsSensitive(command) {
  return /\b(private.?key|key.?file|certificate_key_d)\b/i.test(command) && /\b(cat|type|more|less|copy|cp|export|show|list|print|dump)\b/i.test(command);
}
function commandIsInSource(command, source) {
  const c = normalizeText(command);
  const s = normalizeText(source.content);
  return c.length >= 8 && s.includes(c);
}
function quoteIsInSource(quote, source) {
  const q = normalizeText(quote);
  const s = normalizeText(source.content);
  return q.length >= 25 && s.includes(q);
}
function riskLabel(value, command) {
  const text = `${value || ""} ${command || ""}`.toLowerCase();
  if (/\b(restart|reboot|reload|delete|remove|replace|force-full-load-push|clear|flush)\b/.test(text)) return "Potentially disruptive";
  if (/\b(modify|install|import|create|set|save|enable|disable|export)\b/.test(text)) return "Changes configuration";
  return "Read-only";
}
function normalizeAIData(data, results) {
  const byUrl = new Map(results.map(r => [r.url, r]));
  const acceptedCauses = (Array.isArray(data?.causes) ? data.causes : []).filter(c => {
    const source = byUrl.get(c?.source_url);
    return source && quoteIsInSource(c.evidence_quote, source);
  }).slice(0, 6);
  const causes = acceptedCauses.map(c => ({ title: String(c.title || ""), detail: String(c.detail || "") }));

  const commands = (Array.isArray(data?.commands) ? data.commands : []).filter(c => {
    const source = byUrl.get(c?.source_url);
    return source && typeof c.command === "string" && !commandIsSensitive(c.command) && commandIsInSource(c.command, source);
  }).slice(0, 10).map(c => ({
    command: c.command,
    platform: String(c.platform || ""),
    description: String(c.description || ""),
    when_to_use: String(c.when_to_use || ""),
    risk: riskLabel(c.risk, c.command),
    source_title: byUrl.get(c.source_url).title,
    source_url: c.source_url
  }));

  const acceptedUrls = new Set([
    ...acceptedCauses.map(c => c.source_url).filter(Boolean),
    ...commands.map(c => c.source_url).filter(Boolean)
  ]);
  const sources = [...acceptedUrls].map(url => ({ title: byUrl.get(url).title, url }));
  const hasEvidence = causes.length > 0 || commands.length > 0;

  return {
    summary: hasEvidence ? String(data.summary || "") : "Related pages were found, but they did not provide enough direct evidence to verify a cause or command for this exact question.",
    causes,
    commands,
    sources,
    safety_note: hasEvidence ? String(data.safety_note || "Verify the exact product version and operational context before making changes.") : "No verified Internet causes or commands are displayed. The available search evidence did not directly support them."
  };
}

async function handleSearch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = (env.ALLOWED_ORIGINS || DEFAULT_ALLOWED_ORIGINS.join(",")).split(",").map(x => x.trim()).filter(Boolean);
    const headers = corsHeaders(origin, allowed);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
    if (request.method !== "POST") return jsonResponse({ error: "Use POST /search" }, 405, headers);
    if (headers["Access-Control-Allow-Origin"] === "null") return jsonResponse({ error: "Origin not allowed" }, 403, headers);
    if (!env.AI) return jsonResponse({ error: "Cloudflare Workers AI binding AI is not configured" }, 503, headers);
    if (!env.TAVILY_KEY) return jsonResponse({ error: "TAVILY_KEY secret is missing" }, 503, headers);

    let body;
    try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid JSON request body" }, 400, headers); }
    const query = String(body.query || "").trim().slice(0, 1200);
    const vendor = String(body.vendor || "Network infrastructure").trim().slice(0, 100);
    if (query.length < 4) return jsonResponse({ error: "Please describe your issue in more detail" }, 400, headers);

    try {
      const vendorKey = detectVendor(vendor, query);
      const config = VENDORS[vendorKey];
      const queries = buildQueries(vendorKey, vendor, query);
      const batches = await Promise.all(queries.map(q => tavilySearch(env.TAVILY_KEY, q, config.domains)));
      const results = normalizeResults(batches.flat(), query);
      if (!results.length) return jsonResponse({
        summary: "No sufficiently relevant vendor documentation was found.", causes: [], commands: [], sources: [],
        safety_note: "No Internet commands or causes are displayed because relevant evidence was not found."
      }, 200, headers);

      const evidence = results.map((r, i) => `RESULT ${i + 1}\nTitle: ${r.title}\nURL: ${r.url}\nContent:\n${r.content}`).join("\n\n-----\n\n");
      const prompt = `Vendor: ${vendor}\nDetected product: ${config.label}\nVersion in question: ${extractVersion(query) || "Not specified"}\nExact user question: ${query}\n\nSearch evidence:\n${evidence}\n\nFor every cause, include source_url and an evidence_quote copied exactly from its source content. For every command, include source_url and reproduce the exact command text found in that source. If a source does not explicitly show the command and support its purpose, omit it. Do not infer causes from a mention of a setting. Return empty arrays when evidence is insufficient. Sources must be exact URLs above. Return JSON only.`;

      const ai = await env.AI.run(MODEL, {
        messages: [{ role: "system", content: SYSTEM_PROMPT }, { role: "user", content: prompt }],
        response_format: { type: "json_object" },
        max_tokens: 2400,
        temperature: 0.1
      });
      const output = ai?.response ?? ai?.choices?.[0]?.message?.content ?? null;
      if (output === null || output === undefined) throw new Error("Cloudflare AI returned an empty response");
      const result = normalizeAIData(parseAI(output), results);
      if (env.DB && result.commands.length) {
        for (const c of result.commands) {
          const source = results.find(r => r.url === c.source_url);
          const id = 'web-' + crypto.randomUUID();
          await env.DB.prepare(`INSERT OR IGNORE INTO commands
            (id,vendor,category,title_ar,title_en,keywords_json,commands_json,explanation_ar,explanation_en,status,source_title,source_url,submitted_by)
            VALUES(?,?,?,?,?,?,?,?,?,'pending',?,?,?)`)
            .bind(id, vendor, 'Internet discovery', '', c.description || c.command.slice(0,120), JSON.stringify([query,c.platform||'',c.command]), JSON.stringify([c.command]), '', c.description || c.when_to_use || '', c.source_title || source?.title || '', c.source_url, 'internet-discovery').run();
          await env.DB.prepare('INSERT INTO audit_log(command_id,action,actor,details) VALUES(?,?,?,?)').bind(id,'submitted','internet-discovery',query).run();
        }
      }
      return jsonResponse(result, 200, headers);
    } catch (error) {
      return jsonResponse({ error: "Internet search or AI processing failed.", details: error?.message || "Unknown error" }, 502, headers);
    }
  }

const ADMIN_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NetOps Command Review</title><style>body{font:15px system-ui;margin:24px auto;padding:0 14px;max-width:1000px;background:#f5f7fb;color:#172033}h1{font-size:24px}.item{background:white;border:1px solid #dbe1ea;border-radius:12px;padding:16px;margin:14px 0}pre{white-space:pre-wrap;background:#f1f4f8;padding:12px;border-radius:8px;overflow:auto}.muted{color:#596579}.actions{display:flex;gap:8px;flex-wrap:wrap}button{padding:9px 14px;border:0;border-radius:7px;cursor:pointer} .yes{background:#176b45;color:white}.no{background:#a52c37;color:white}input{padding:9px;width:min(500px,90%)} </style></head><body><h1>NetOps Command Review</h1><p class="muted">Only approve commands after checking exact syntax, product, version, CLI context and source.</p><button onclick="load()">Refresh pending</button><main id="list">Loading…</main><script>
async function act(id,action){let note=prompt('Optional review note:')||'';let r=await fetch('/api/admin/'+action,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,note})});let j=await r.json();if(!r.ok){alert(j.error||'Request failed');return}load()}
async function load(){let root=document.getElementById('list');root.textContent='Loading…';try{let r=await fetch('/api/admin/pending');let j=await r.json();if(!r.ok)throw Error(j.error||'Could not load');root.innerHTML=j.commands.length?j.commands.map(x=>'<section class="item"><h3>'+esc(x.title_en||x.title_ar||x.id)+'</h3><p><b>'+esc(x.vendor)+' / '+esc(x.category)+'</b></p><p>'+esc(x.explanation_en||x.explanation_ar||'')+'</p><pre>'+esc(JSON.parse(x.commands_json||'[]').join('\\n'))+'</pre><p>Source: <a target="_blank" rel="noopener" href="'+esc(x.source_url)+'">'+esc(x.source_title||x.source_url)+'</a></p><p class="muted">Submitted: '+esc(x.created_at)+'</p><div class="actions"><button class="yes" onclick="act(\''+esc(x.id)+'\',\'approve\')">Approve</button><button class="no" onclick="act(\''+esc(x.id)+'\',\'reject\')">Reject</button></div></section>').join(''):'<p>No pending commands.</p>'}catch(e){root.textContent=e.message}}
function esc(s){return String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}load();</script></body></html>`;

function apiCors(origin, env) {
  const allowed = (env.ALLOWED_ORIGINS || DEFAULT_ALLOWED_ORIGINS.join(',')).split(',').map(x=>x.trim());
  const ok = allowed.includes('*') || allowed.includes(origin);
  return { 'Access-Control-Allow-Origin': ok ? (allowed.includes('*') ? '*' : origin) : 'null', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Vary': 'Origin' };
}
function apiJson(data, status=200, headers={}) { return new Response(JSON.stringify(data), {status, headers:{'Content-Type':'application/json; charset=utf-8',...headers}}); }
function safeVendor(v) { return String(v||'').trim().slice(0,80); }
function toSlug(v) { const x=safeVendor(v).toLowerCase(); if(/f5|big-?ip|tmos|awaf|asm|ltm/.test(x))return 'F5'; if(/cisco|ftd|fmc|asa|aci|catalyst/.test(x))return 'Cisco'; if(/palo|pan-os|panorama/.test(x))return 'Palo Alto'; if(/forti|fortigate|fortios/.test(x))return 'Fortinet'; return safeVendor(v)||'Network'; }

async function verifyAccess(request, env) {
  const team = String(env.ACCESS_TEAM_DOMAIN||'').replace(/^https?:\/\//,'').replace(/\/$/,'');
  const aud = String(env.ACCESS_AUD||'');
  const token = request.headers.get('CF-Access-Jwt-Assertion');
  if(!team || !aud || !token) return {ok:false,error:'Cloudflare Access is not configured or JWT is missing'};
  try {
    const parts=token.split('.'); if(parts.length!==3) throw new Error('Malformed Access JWT');
    const decode=s=>JSON.parse(atob(s.replace(/-/g,'+').replace(/_/g,'/')));
    const header=decode(parts[0]), payload=decode(parts[1]);
    if(header.alg!=='RS256') throw new Error('Unsupported JWT algorithm');
    const now=Math.floor(Date.now()/1000);
    if(payload.exp<now || payload.nbf>now) throw new Error('JWT expired or not active');
    if(payload.aud!==aud && !(Array.isArray(payload.aud)&&payload.aud.includes(aud))) throw new Error('Invalid Access audience');
    const jwksRes=await fetch(`https://${team}/cdn-cgi/access/certs`);
    if(!jwksRes.ok) throw new Error('Unable to retrieve Access signing keys');
    const jwks=await jwksRes.json(); const jwk=jwks.keys.find(k=>k.kid===header.kid);
    if(!jwk) throw new Error('Access signing key not found');
    const key=await crypto.subtle.importKey('jwk',jwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
    const data=new TextEncoder().encode(parts[0]+'.'+parts[1]);
    const sig=Uint8Array.from(atob(parts[2].replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
    if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,sig,data)) throw new Error('Invalid Access signature');
    return {ok:true,email:String(payload.email||'unknown')};
  } catch(e) { return {ok:false,error:e.message||'Access validation failed'}; }
}

async function adminRoute(request, env, path) {
  const auth=await verifyAccess(request,env);
  if(!auth.ok) return apiJson({error:'Unauthorized',details:auth.error},401);
  if(!env.DB) return apiJson({error:'D1 binding DB is missing'},503);
  if(request.method==='GET' && path==='/api/admin/pending') {
    const {results=[]}=await env.DB.prepare("SELECT * FROM commands WHERE status='pending' ORDER BY created_at DESC LIMIT 200").all();
    return apiJson({commands:results});
  }
  if(request.method==='POST' && (path==='/api/admin/approve'||path==='/api/admin/reject')) {
    let body;try{body=await request.json()}catch{return apiJson({error:'Invalid JSON'},400)}
    const id=String(body.id||'').slice(0,100), note=String(body.note||'').slice(0,1000);
    if(!id)return apiJson({error:'Command id is required'},400);
    const action=path.endsWith('/approve')?'approved':'rejected';
    const update=await env.DB.prepare("UPDATE commands SET status=?, reviewed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'), reviewed_by=?, review_note=? WHERE id=? AND status='pending'").bind(action,auth.email,note,id).run();
    if(!update.meta?.changes)return apiJson({error:'Pending command not found or already reviewed'},404);
    await env.DB.prepare('INSERT INTO audit_log(command_id,action,actor,details) VALUES(?,?,?,?)').bind(id,action,auth.email,note).run();
    return apiJson({ok:true,id,status:action});
  }
  return apiJson({error:'Not found'},404);
}

async function publicCommands(request, env) {
  if(!env.DB)return apiJson({error:'D1 binding DB is missing'},503);
  const url=new URL(request.url); const vendor=url.searchParams.get('vendor');
  let query="SELECT id,vendor,category,title_ar,title_en,keywords_json,commands_json,explanation_ar,explanation_en,source_title,source_url,created_at FROM commands WHERE status='approved'";
  const args=[]; if(vendor){query+=' AND lower(vendor)=lower(?)';args.push(vendor)} query+=' ORDER BY reviewed_at DESC LIMIT 500';
  const stmt=env.DB.prepare(query);const {results=[]}=args.length?await stmt.bind(...args).all():await stmt.all();
  return apiJson({commands:results.map(x=>({...x,keywords:JSON.parse(x.keywords_json||'[]'),commands:JSON.parse(x.commands_json||'[]')}))});
}

export default {
  async fetch(request, env) {
    const url=new URL(request.url); const origin=request.headers.get('Origin')||'';
    const headers=apiCors(origin,env);
    if(request.method==='OPTIONS') return new Response(null,{status:204,headers});
    if(url.pathname==='/search') return handleSearch(request,env);
    if(url.pathname==='/admin' || url.pathname==='/admin/') return new Response(ADMIN_HTML,{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'}});
    if(url.pathname==='/api/commands' && request.method==='GET') {
      if(headers['Access-Control-Allow-Origin']==='null') return apiJson({error:'Origin not allowed'},403,headers);
      return publicCommands(request,env).then(r=>{const h=new Headers(r.headers);Object.entries(headers).forEach(([k,v])=>h.set(k,v));return new Response(r.body,{status:r.status,headers:h})});
    }
    if(url.pathname.startsWith('/api/admin/')) return adminRoute(request,env,url.pathname);
    return apiJson({error:'Not found'},404,headers);
  }
};
