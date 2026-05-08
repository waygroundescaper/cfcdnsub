const CORS_HEADERS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "Content-Type, X-Admin-Token, Authorization"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...CORS_HEADERS
    }
  });
}

function text(body, status = 200, contentType = "text/plain; charset=utf-8") {
  return new Response(body, {
    status,
    headers: {
      "content-type": contentType,
      ...CORS_HEADERS
    }
  });
}

function b64EncodeUtf8(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

function b64DecodeUtf8(str) {
  return decodeURIComponent(escape(atob(str)));
}

function escapeYaml(str = "") {
  return String(str)
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, " ");
}

function parsePreferredEndpoints(input) {
  return String(input || "")
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => {
      const [raw, remark = ""] = line.split("#");
      const value = raw.trim();
      const match = value.match(/^(.*?)(?::(\d+))?$/);

      return {
        server: match?.[1] || value,
        port: match?.[2] ? Number(match[2]) : undefined,
        remark: remark.trim()
      };
    });
}

function parseVmess(link) {
  const raw = link.slice("vmess://".length).trim();
  const obj = JSON.parse(b64DecodeUtf8(raw));

  return {
    type: "vmess",
    name: obj.ps || "vmess",
    server: obj.add,
    port: Number(obj.port || 443),
    uuid: obj.id,
    cipher: obj.scy || "auto",
    network: obj.net || "ws",
    tls: obj.tls === "tls",
    host: obj.host || "",
    path: obj.path || "/",
    sni: obj.sni || obj.host || "",
    alpn: obj.alpn || "",
    fp: obj.fp || ""
  };
}

function parseUrlLike(link, type) {
  const u = new URL(link);

  return {
    type,
    name: decodeURIComponent(u.hash.replace(/^#/, "")) || type,
    server: u.hostname,
    port: Number(u.port || 443),
    password: type === "trojan" ? decodeURIComponent(u.username) : undefined,
    uuid: type === "vless" ? decodeURIComponent(u.username) : undefined,
    network: u.searchParams.get("type") || "tcp",
    tls: (u.searchParams.get("security") || "").toLowerCase() === "tls",
    host: u.searchParams.get("host") || u.searchParams.get("sni") || "",
    path: u.searchParams.get("path") || "/",
    sni: u.searchParams.get("sni") || u.searchParams.get("host") || "",
    fp: u.searchParams.get("fp") || "",
    alpn: u.searchParams.get("alpn") || "",
    flow: u.searchParams.get("flow") || ""
  };
}

function parseRawLinks(input) {
  const lines = String(input || "")
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean);

  const result = [];

  for (const line of lines) {
    if (line.startsWith("vmess://")) {
      result.push(parseVmess(line));
      continue;
    }

    if (line.startsWith("vless://")) {
      result.push(parseUrlLike(line, "vless"));
      continue;
    }

    if (line.startsWith("trojan://")) {
      result.push(parseUrlLike(line, "trojan"));
      continue;
    }

    try {
      const decoded = b64DecodeUtf8(line);
      if (/^(vmess|vless|trojan):\/\//m.test(decoded)) {
        result.push(...parseRawLinks(decoded));
      }
    } catch {}
  }

  return result;
}

function buildNodes(baseNodes, preferredEndpoints, options = {}) {
  const output = [];
  const prefix = String(options.namePrefix || "").trim();
  let counter = 0;

  for (const node of baseNodes) {
    for (const ep of preferredEndpoints) {
      counter++;

      const nameParts = [];
      if (node.name) nameParts.push(node.name);
      if (prefix) nameParts.push(prefix);
      nameParts.push(ep.remark || String(counter));

      output.push({
        ...node,
        name: nameParts.join(" | "),
        server: ep.server,
        port: ep.port || node.port,
        host: options.keepOriginalHost ? node.host : "",
        sni: options.keepOriginalHost ? node.sni : ""
      });
    }
  }

  return output;
}

function encodeVmess(node) {
  const obj = {
    v: "2",
    ps: node.name,
    add: node.server,
    port: String(node.port),
    id: node.uuid,
    aid: "0",
    scy: node.cipher || "auto",
    net: node.network || "ws",
    type: "none",
    host: node.host || "",
    path: node.path || "/",
    tls: node.tls ? "tls" : "",
    sni: node.sni || "",
    alpn: node.alpn || "",
    fp: node.fp || ""
  };

  return "vmess://" + b64EncodeUtf8(JSON.stringify(obj));
}

function encodeVless(node) {
  const url = new URL(`vless://${encodeURIComponent(node.uuid)}@${node.server}:${node.port}`);

  url.searchParams.set("type", node.network || "ws");
  if (node.tls) url.searchParams.set("security", "tls");
  if (node.host) url.searchParams.set("host", node.host);
  if (node.sni) url.searchParams.set("sni", node.sni);
  if (node.path) url.searchParams.set("path", node.path);
  if (node.alpn) url.searchParams.set("alpn", node.alpn);
  if (node.fp) url.searchParams.set("fp", node.fp);
  if (node.flow) url.searchParams.set("flow", node.flow);

  url.hash = node.name;
  return url.toString();
}

function encodeTrojan(node) {
  const url = new URL(`trojan://${encodeURIComponent(node.password)}@${node.server}:${node.port}`);

  if (node.network) url.searchParams.set("type", node.network);
  if (node.tls) url.searchParams.set("security", "tls");
  if (node.host) url.searchParams.set("host", node.host);
  if (node.sni) url.searchParams.set("sni", node.sni);
  if (node.path) url.searchParams.set("path", node.path);
  if (node.alpn) url.searchParams.set("alpn", node.alpn);
  if (node.fp) url.searchParams.set("fp", node.fp);

  url.hash = node.name;
  return url.toString();
}

function renderRaw(nodes) {
  const lines = nodes
    .map(node => {
      if (node.type === "vmess") return encodeVmess(node);
      if (node.type === "vless") return encodeVless(node);
      if (node.type === "trojan") return encodeTrojan(node);
      return "";
    })
    .filter(Boolean);

  return b64EncodeUtf8(lines.join("\n"));
}

function renderClash(nodes) {
  const proxies = nodes.map(node => {
    if (node.type === "vmess") {
      const lines = [
        `  - name: "${escapeYaml(node.name)}"`,
        `    type: vmess`,
        `    server: ${node.server}`,
        `    port: ${node.port}`,
        `    uuid: ${node.uuid}`,
        `    alterId: 0`,
        `    cipher: ${node.cipher || "auto"}`,
        `    udp: true`,
        `    tls: ${node.tls ? "true" : "false"}`,
        `    network: ${node.network || "ws"}`
      ];

      if (node.sni) lines.push(`    servername: "${escapeYaml(node.sni)}"`);

      if ((node.network || "ws") === "ws") {
        lines.push(
          `    ws-opts:`,
          `      path: "${escapeYaml(node.path || "/")}"`,
          `      headers:`,
          `        Host: "${escapeYaml(node.host || node.sni || "")}"`
        );
      }

      return lines.join("\n");
    }

    if (node.type === "vless") {
      const lines = [
        `  - name: "${escapeYaml(node.name)}"`,
        `    type: vless`,
        `    server: ${node.server}`,
        `    port: ${node.port}`,
        `    uuid: ${node.uuid}`,
        `    udp: true`,
        `    tls: ${node.tls ? "true" : "false"}`,
        `    network: ${node.network || "ws"}`
      ];

      if (node.sni) lines.push(`    servername: "${escapeYaml(node.sni)}"`);

      if ((node.network || "ws") === "ws") {
        lines.push(
          `    ws-opts:`,
          `      path: "${escapeYaml(node.path || "/")}"`,
          `      headers:`,
          `        Host: "${escapeYaml(node.host || node.sni || "")}"`
        );
      }

      return lines.join("\n");
    }

    if (node.type === "trojan") {
      const lines = [
        `  - name: "${escapeYaml(node.name)}"`,
        `    type: trojan`,
        `    server: ${node.server}`,
        `    port: ${node.port}`,
        `    password: "${escapeYaml(node.password || "")}"`,
        `    udp: true`
      ];

      if (node.sni) lines.push(`    sni: "${escapeYaml(node.sni)}"`);
      if (node.tls !== false) lines.push(`    tls: true`);
      if (node.network) lines.push(`    network: ${node.network}`);

      if (node.network === "ws") {
        lines.push(
          `    ws-opts:`,
          `      path: "${escapeYaml(node.path || "/")}"`,
          `      headers:`,
          `        Host: "${escapeYaml(node.host || node.sni || "")}"`
        );
      }

      return lines.join("\n");
    }

    return "";
  }).filter(Boolean);

  const proxyNames = nodes.map(node => `      - "${escapeYaml(node.name)}"`);

  const allGroupMembers = [
    `      - "自动选择"`,
    ...proxyNames,
    `      - DIRECT`
  ];

  const autoGroupMembers = proxyNames.length ? proxyNames : [`      - DIRECT`];

  return [
    `mixed-port: 7890`,
    `allow-lan: false`,
    `mode: rule`,
    `log-level: info`,
    `ipv6: true`,
    ``,
    `proxies:`,
    ...proxies,
    ``,
    `proxy-groups:`,
    `  - name: "自动选择"`,
    `    type: url-test`,
    `    url: "http://www.gstatic.com/generate_204"`,
    `    interval: 300`,
    `    tolerance: 50`,
    `    proxies:`,
    ...autoGroupMembers,
    ``,
    `  - name: "节点选择"`,
    `    type: select`,
    `    proxies:`,
    ...allGroupMembers,
    ``,
    `rules:`,
    `  - MATCH,节点选择`
  ].join("\n");
}

function renderSurge(nodes, baseUrl, accessToken) {
  const proxies = nodes
    .filter(node => node.type === "vmess" || node.type === "trojan")
    .map(node => {
      if (node.type === "vmess") {
        return `${node.name} = vmess, ${node.server}, ${node.port}, username=${node.uuid}, ws=true, ws-path=${node.path || "/"}, ws-headers=Host:${node.host || ""}, tls=${node.tls ? "true" : "false"}, sni=${node.sni || ""}`;
      }

      return `${node.name} = trojan, ${node.server}, ${node.port}, password=${node.password || ""}, sni=${node.sni || ""}`;
    });

  return [
    "[General]",
    "skip-proxy = 127.0.0.1, localhost",
    "",
    "[Proxy]",
    ...proxies,
    "",
    "[Proxy Group]",
    "Proxy = select, " + nodes
      .filter(n => n.type === "vmess" || n.type === "trojan")
      .map(n => n.name)
      .join(", "),
    "",
    "[Rule]",
    "FINAL,Proxy",
    "",
    "; token-protected subscription",
    `; ${baseUrl}?token=${accessToken}`
  ].join("\n");
}

function createShortId(length = 10) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = "";

  for (let i = 0; i < length; i++) {
    out += chars[bytes[i] % chars.length];
  }

  return out;
}

async function createUniqueShortId(env, tries = 8) {
  for (let i = 0; i < tries; i++) {
    const id = createShortId(10);
    const exists = await env.SUB_STORE.get(`sub:${id}`);
    if (!exists) return id;
  }

  throw new Error("无法生成唯一短链接，请稍后再试");
}

function normalizeLines(value = "") {
  return String(value)
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .sort()
    .join("\n");
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);

  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function buildDedupHash(body) {
  const normalized = {
    nodeLinks: normalizeLines(body.nodeLinks || ""),
    preferredIps: normalizeLines(body.preferredIps || ""),
    namePrefix: String(body.namePrefix || "").trim(),
    keepOriginalHost: body.keepOriginalHost !== false
  };

  return sha256Hex(JSON.stringify(normalized));
}

function validateAccessToken(url, env) {
  const expected = env.SUB_ACCESS_TOKEN;
  if (!expected) return { ok: true };

  const provided = url.searchParams.get("token") || "";

  if (!provided || provided !== expected) {
    return {
      ok: false,
      response: text("Forbidden: invalid token", 403)
    };
  }

  return { ok: true };
}

function checkAdmin(request, env) {
  const token = request.headers.get("X-Admin-Token") || "";
  return Boolean(env.ADMIN_TOKEN && token === env.ADMIN_TOKEN);
}

async function handleGenerate(request, env, url) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "请求体不是合法 JSON" }, 400);
  }

  const baseNodes = parseRawLinks(body.nodeLinks || "");
  const preferredEndpoints = parsePreferredEndpoints(body.preferredIps || "");

  if (!baseNodes.length) {
    return json({ ok: false, error: "没有识别到可用节点" }, 400);
  }

  if (!preferredEndpoints.length) {
    return json({ ok: false, error: "没有识别到可用优选地址" }, 400);
  }

  const options = {
    namePrefix: body.namePrefix || "",
    keepOriginalHost: body.keepOriginalHost !== false
  };

  const nodes = buildNodes(baseNodes, preferredEndpoints, options);

  const payload = {
    version: 2,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    options,
    nodes,
    downloadEnabled: false
  };

  const dedupHash = await buildDedupHash(body);
  const dedupKey = `dedup:${dedupHash}`;

  let id = await env.SUB_STORE.get(dedupKey);

  if (!id) {
    id = await createUniqueShortId(env);

    const ttl = 60 * 60 * 24 * 7;

    await env.SUB_STORE.put(`sub:${id}`, JSON.stringify(payload), {
      expirationTtl: ttl
    });

    await env.SUB_STORE.put(dedupKey, id, {
      expirationTtl: ttl
    });
  }

  const origin = url.origin;
  const accessToken = env.SUB_ACCESS_TOKEN || "";

  const withToken = target => {
    if (target) {
      return `${origin}/sub/${id}?target=${target}&token=${encodeURIComponent(accessToken)}`;
    }

    return `${origin}/sub/${id}?token=${encodeURIComponent(accessToken)}`;
  };

  return json({
    ok: true,
    storage: "kv",
    deduplicated: true,
    shortId: id,
    urls: {
      auto: withToken(""),
      raw: withToken("raw"),
      clash: withToken("clash"),
      surge: withToken("surge")
    },
    counts: {
      inputNodes: baseNodes.length,
      preferredEndpoints: preferredEndpoints.length,
      outputNodes: nodes.length
    },
    preview: nodes.slice(0, 20).map(node => ({
      name: node.name,
      type: node.type,
      server: node.server,
      port: node.port,
      host: node.host || "",
      sni: node.sni || ""
    })),
    warnings: accessToken
      ? []
      : ["未检测到 SUB_ACCESS_TOKEN，订阅链接将没有第二层访问保护。"]
  });
}

async function handleSub(request, url, env) {
  const tokenCheck = validateAccessToken(url, env);
  if (!tokenCheck.ok) return tokenCheck.response;

  const id = url.pathname.split("/").pop();
  if (!id) return text("missing id", 400);

  const raw = await env.SUB_STORE.get(`sub:${id}`);
  if (!raw) return text("not found", 404);

  const record = JSON.parse(raw);

  const globalAllow = await env.SUB_STORE.get("global:download:allow");

  if (globalAllow !== "true" && record.downloadEnabled !== true) {
    return text("Forbidden: subscription download is disabled", 403);
  }

  const nodes = record.nodes || [];
  const target = (url.searchParams.get("target") || "raw").toLowerCase();

  const ip =
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For") ||
    "unknown";

  const userAgent =
    request.headers.get("User-Agent") ||
    "unknown";

  await env.SUB_STORE.put(
    `download:${id}:${Date.now()}:${crypto.randomUUID()}`,
    JSON.stringify({
      id,
      ip,
      userAgent,
      target,
      time: new Date().toISOString()
    }),
    {
      expirationTtl: 60 * 60 * 24 * 30
    }
  );

  if (target === "clash") {
    return text(renderClash(nodes), 200, "text/yaml; charset=utf-8");
  }

  if (target === "surge") {
    return text(
      renderSurge(nodes, url.origin + url.pathname, env.SUB_ACCESS_TOKEN || ""),
      200,
      "text/plain; charset=utf-8"
    );
  }

  return text(renderRaw(nodes), 200, "text/plain; charset=utf-8");
}

async function handleAdminSubToggle(request, env, enabled) {
  if (!checkAdmin(request, env)) {
    return json({ ok: false, error: "Forbidden" }, 403);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "Invalid JSON" }, 400);
  }

  const id = String(body.id || "").trim();

  if (!id) {
    return json({ ok: false, error: "Missing id" }, 400);
  }

  const key = `sub:${id}`;
  const raw = await env.SUB_STORE.get(key);

  if (!raw) {
    return json({ ok: false, error: "Subscription not found" }, 404);
  }

  const record = JSON.parse(raw);
  record.downloadEnabled = enabled;
  record.updatedAt = new Date().toISOString();

  await env.SUB_STORE.put(key, JSON.stringify(record), {
    expirationTtl: 60 * 60 * 24 * 7
  });

  return json({
    ok: true,
    id,
    downloadEnabled: enabled
  });
}

async function handleAdminSubInfo(request, env, url) {
  if (!checkAdmin(request, env)) {
    return json({ ok: false, error: "Forbidden" }, 403);
  }

  const id = String(url.searchParams.get("id") || "").trim();

  if (!id) {
    return json({ ok: false, error: "Missing id" }, 400);
  }

  const raw = await env.SUB_STORE.get(`sub:${id}`);

  if (!raw) {
    return json({ ok: false, error: "Subscription not found" }, 404);
  }

  const record = JSON.parse(raw);

  const logs = [];
  const list = await env.SUB_STORE.list({
    prefix: `download:${id}:`,
    limit: 100
  });

  for (const item of list.keys) {
    const value = await env.SUB_STORE.get(item.name);
    if (value) {
      try {
        logs.push(JSON.parse(value));
      } catch {}
    }
  }

  logs.sort((a, b) => new Date(b.time) - new Date(a.time));

  return json({
    ok: true,
    id,
    downloadEnabled: record.downloadEnabled === true,
    createdAt: record.createdAt || null,
    updatedAt: record.updatedAt || null,
    nodeCount: (record.nodes || []).length,
    nodes: (record.nodes || []).map(n => ({
      name: n.name,
      type: n.type,
      server: n.server,
      port: n.port,
      host: n.host || "",
      sni: n.sni || ""
    })),
    logs
  });
}

async function handleAdminGlobalAllow(request, env) {
  if (!checkAdmin(request, env)) {
    return json({ ok: false, error: "Forbidden" }, 403);
  }

  await env.SUB_STORE.put("global:download:allow", "true", {
    expirationTtl: 60 * 5
  });

  return json({
    ok: true,
    message: "All downloads allowed for 5 minutes"
  });
}

async function handleAdminGlobalStatus(request, env) {
  if (!checkAdmin(request, env)) {
    return json({ ok: false, error: "Forbidden" }, 403);
  }

  const allowed = await env.SUB_STORE.get("global:download:allow");

  return json({
    ok: true,
    globalAllow: allowed === "true"
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS
      });
    }

    if (url.pathname === "/api/ping") {
      return json({
        ok: true,
        service: "ShadowEscaper Sub Worker",
        version: "admin-sub-v2"
      });
    }

    if (request.method === "POST" && url.pathname === "/api/generate") {
      return handleGenerate(request, env, url);
    }

    if (request.method === "POST" && url.pathname === "/api/admin/sub/enable") {
      return handleAdminSubToggle(request, env, true);
    }

    if (request.method === "POST" && url.pathname === "/api/admin/sub/disable") {
      return handleAdminSubToggle(request, env, false);
    }

    if (request.method === "GET" && url.pathname === "/api/admin/sub/info") {
      return handleAdminSubInfo(request, env, url);
    }

    if (request.method === "POST" && url.pathname === "/api/admin/sub/global-allow") {
      return handleAdminGlobalAllow(request, env);
    }

    if (request.method === "GET" && url.pathname === "/api/admin/sub/global-status") {
      return handleAdminGlobalStatus(request, env);
    }

    if (request.method === "GET" && url.pathname.startsWith("/sub/")) {
      return handleSub(request, url, env);
    }

    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return text("Not found", 404);
  }
};