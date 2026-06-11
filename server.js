/**
 * NP Radar Backend — Nepal Domain Intelligence API v5.2
 * Production-ready for Render free tier
 * Caching: DNS/WHOIS=5min, Stats=1month, Bank=24h
 */

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const dns = require("dns").promises;
const tls = require("tls");
const https = require("https");
const http = require("http");
const path = require("path");
const NodeCache = require("node-cache");

const app = express();
const cache = new NodeCache({
  stdTTL: 300,
  checkperiod: 120,
  useClones: false,
  deleteOnExpire: true,
});
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === "production";

// ─── Middleware ────────────────────────────────────────
app.set("trust proxy", 1);
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
  }),
);
app.use(compression({ level: 6, threshold: 1024 }));
app.use(
  cors({
    origin: isProduction
      ? ["https://npradar.laxman-poudel.com.np", /\.laxman-poudel\.com\.np$/]
      : "*",
    methods: ["GET", "HEAD"],
    maxAge: 86400,
  }),
);
app.use(express.json({ limit: "10kb" }));

// Rate limiter — skip for health, stats, bank-scorecard
const rateLimitMap = new Map();
app.use((req, res, next) => {
  if (["/health", "/api/bank-scorecard", "/api/stats"].includes(req.path))
    return next();
  const ip = req.ip || "127.0.0.1",
    now = Date.now();
  const entry = rateLimitMap.get(ip) || { count: 0, reset: now + 60000 };
  if (now > entry.reset) {
    entry.count = 0;
    entry.reset = now + 60000;
  }
  entry.count++;
  rateLimitMap.set(ip, entry);
  if (entry.count > (isProduction ? 30 : 200))
    return res.status(429).json({ error: "Rate limit exceeded" });
  next();
});

app.use(
  express.static(__dirname, {
    maxAge: isProduction ? "7d" : "0",
    setHeaders: (res, fp) => {
      if (fp.endsWith(".html")) res.setHeader("Cache-Control", "no-cache");
      else if (fp.match(/\.(css|js|png|jpg|ico|svg)$/))
        res.setHeader(
          "Cache-Control",
          `public, max-age=${isProduction ? 604800 : 0}`,
        );
    },
  }),
);

// ─── Helpers ───────────────────────────────────────────
function validateDomain(d) {
  if (!d || typeof d !== "string") return null;
  const c = d
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/^www\./i, "");
  return /^[a-z0-9][a-z0-9\-\.]{1,250}[a-z0-9]$/.test(c) && !c.includes("..")
    ? c
    : null;
}
function daysUntil(ds) {
  if (!ds) return null;
  let d = new Date(ds);
  if (isNaN(d)) {
    const p = ds.split(/[\/\-\.\s]/);
    if (p.length >= 3) d = new Date(`${p[0]}-${p[1]}-${p[2]}`);
  }
  return isNaN(d) ? null : Math.floor((d - Date.now()) / 86400000);
}
const ipToInt = (ip) =>
  ip.split(".").reduce((a, o) => (a << 8) + parseInt(o), 0);
const parseCIDR = (c) => {
  const [i, p] = c.split("/"),
    ip = ipToInt(i),
    m = ~(2 ** (32 - parseInt(p)) - 1);
  return [ip & m, (ip & m) + 2 ** (32 - parseInt(p)) - 1];
};
const ipInRange = (ip, c) => {
  const [s, e] = parseCIDR(c),
    i = ipToInt(ip);
  return i >= s && i <= e;
};
function maskPhone(p) {
  if (!p) return p;
  const d = p.replace(/\D/g, "");
  if (d.length <= 4) return d.replace(/\d/g, "*");
  if (d.length <= 6) return d.substring(0, 2) + "*".repeat(d.length - 2);
  return (
    d.substring(0, 3) + "*".repeat(d.length - 5) + d.substring(d.length - 2)
  );
}

function httpGet(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith("https") ? https : http;
    lib
      .get(
        url,
        {
          timeout: 10000,
          headers: {
            "User-Agent": "NPWhoisBot/5.2",
            Accept: "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
          },
          ...opts,
        },
        (res) => {
          if (
            res.statusCode >= 300 &&
            res.statusCode < 400 &&
            res.headers.location
          )
            return httpGet(res.headers.location, opts)
              .then(resolve)
              .catch(reject);
          let d = "";
          res.on("data", (c) => (d += c));
          res.on("end", () =>
            resolve({ status: res.statusCode, headers: res.headers, body: d }),
          );
        },
      )
      .on("error", reject)
      .on("timeout", function () {
        this.destroy();
        reject(new Error("Timeout"));
      });
  });
}

function httpHead(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const p = new URL(url),
      lib = p.protocol === "https:" ? https : http;
    lib
      .request(
        {
          method: "HEAD",
          hostname: p.hostname,
          path: p.pathname + p.search,
          timeout: 6000,
          rejectUnauthorized: false,
          ...opts,
        },
        (res) => {
          resolve({ status: res.statusCode, headers: res.headers });
          res.destroy();
        },
      )
      .on("error", reject)
      .on("timeout", function () {
        this.destroy();
        reject(new Error("Timeout"));
      })
      .end();
  });
}

// ─── ISP DATABASE ──────────────────────────────────────
const NEPALI_ISP_DB = {
  worldlink: {
    name: "Worldlink Communications",
    nameNepali: "वर्ल्डलिंक",
    slug: "worldlink",
    asn: ["AS17501", "AS139334"],
    ipRanges: ["202.51.64.0/19", "202.51.76.0/22", "103.28.84.0/22"],
    hostnamePatterns: ["worldlink.com.np"],
    color: "#00A651",
    website: "https://worldlink.com.np",
    logo: "🏢",
    category: "tier1",
  },
  dishome: {
    name: "DishHome Internet",
    nameNepali: "डिशहोम",
    slug: "dishome",
    asn: ["AS139220"],
    ipRanges: ["103.153.24.0/22", "103.153.28.0/22"],
    hostnamePatterns: ["dishhome.com.np"],
    color: "#E31937",
    website: "https://www.dishhome.com.np",
    logo: "📡",
    category: "tier1",
  },
  ntc: {
    name: "Nepal Telecom FTTH",
    nameNepali: "नेपाल टेलिकम",
    slug: "ntc",
    asn: ["AS23752", "AS131315"],
    ipRanges: ["202.45.144.0/20", "27.34.0.0/15"],
    hostnamePatterns: ["ntc.net.np"],
    color: "#003893",
    website: "https://www.ntc.net.np",
    logo: "📞",
    category: "tier1",
  },
  subisu: {
    name: "Subisu Cablenet",
    nameNepali: "सुविसु",
    slug: "subisu",
    asn: ["AS4007"],
    ipRanges: ["202.51.80.0/20"],
    hostnamePatterns: ["subisu.net.np"],
    color: "#ED6B06",
    website: "https://www.subisu.net.np",
    logo: "🔌",
    category: "tier1",
  },
  vianet: {
    name: "Vianet Communications",
    nameNepali: "भायानेट",
    slug: "vianet",
    asn: ["AS45650"],
    ipRanges: ["103.10.28.0/22", "202.166.192.0/20"],
    hostnamePatterns: ["vianet.com.np"],
    color: "#EE3124",
    website: "https://www.vianet.com.np",
    logo: "📡",
    category: "tier1",
  },
  websurfer: {
    name: "Web Surfer Nepal",
    nameNepali: "वेब सर्फर",
    slug: "websurfer",
    asn: ["AS132770"],
    ipRanges: ["103.212.220.0/22"],
    hostnamePatterns: ["websurfer.com.np"],
    color: "#8B5CF6",
    website: "https://websurfer.com.np",
    logo: "🌐",
    category: "tier2",
  },
  classictech: {
    name: "Classic Tech",
    nameNepali: "क्लासिक टेक",
    slug: "classictech",
    asn: ["AS136334"],
    ipRanges: ["103.119.60.0/22"],
    hostnamePatterns: ["classic.com.np"],
    color: "#0984E3",
    website: "https://www.classic.com.np",
    logo: "💻",
    category: "tier2",
  },
  cgnet: {
    name: "CG Net",
    nameNepali: "सीजी नेट",
    slug: "cgnet",
    asn: ["AS141365"],
    ipRanges: ["103.172.188.0/22"],
    hostnamePatterns: ["cgnet.com.np"],
    color: "#F97316",
    website: "https://cgnet.com.np",
    logo: "🌍",
    category: "tier2",
  },
};
function detectNepaliISP(ip, hostname = "", asn = "") {
  if (asn)
    for (const [k, v] of Object.entries(NEPALI_ISP_DB))
      if (v.asn.includes(asn.toUpperCase()))
        return { ...v, detectionMethod: "asn", confidence: "high" };
  if (ip)
    for (const [k, v] of Object.entries(NEPALI_ISP_DB))
      for (const r of v.ipRanges)
        if (ipInRange(ip, r))
          return { ...v, detectionMethod: "ip-range", confidence: "high" };
  if (hostname) {
    const l = hostname.toLowerCase();
    for (const [k, v] of Object.entries(NEPALI_ISP_DB))
      for (const p of v.hostnamePatterns)
        if (l.includes(p))
          return { ...v, detectionMethod: "hostname", confidence: "medium" };
  }
  return null;
}

// ─── WHOIS SCRAPER ─────────────────────────────────────
function makeGetReq(url, cookies = "", referer = "") {
  return new Promise((resolve, reject) => {
    const p = new URL(url);
    https
      .request(
        {
          hostname: p.hostname,
          path: p.pathname + p.search,
          method: "GET",
          timeout: 15000,
          headers: {
            "User-Agent":
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            Accept: "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
            ...(cookies ? { Cookie: cookies } : {}),
            ...(referer ? { Referer: referer } : {}),
          },
        },
        (res) => {
          const sc = res.headers["set-cookie"] || [];
          const nc = Array.isArray(sc)
            ? sc.map((c) => c.split(";")[0]).join("; ")
            : String(sc).split(";")[0];
          const ac = cookies ? cookies + "; " + nc : nc;
          let d = "";
          res.on("data", (c) => (d += c));
          res.on("end", () =>
            resolve({
              status: res.statusCode,
              headers: res.headers,
              body: d,
              cookies: ac,
            }),
          );
        },
      )
      .on("error", reject)
      .on("timeout", function () {
        this.destroy();
        reject(new Error("GET timeout"));
      })
      .end();
  });
}
function makePostReq(url, data, cookies = "", referer = "") {
  return new Promise((resolve, reject) => {
    const p = new URL(url);
    https
      .request(
        {
          hostname: p.hostname,
          path: p.pathname + p.search,
          method: "POST",
          timeout: 15000,
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": Buffer.byteLength(data),
            "User-Agent":
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            Accept: "text/html,application/xhtml+xml",
            Origin: "https://register.com.np",
            ...(cookies ? { Cookie: cookies } : {}),
            ...(referer ? { Referer: referer } : {}),
          },
        },
        (res) => {
          const sc = res.headers["set-cookie"] || [];
          const nc = Array.isArray(sc)
            ? sc.map((c) => c.split(";")[0]).join("; ")
            : String(sc).split(";")[0];
          const ac = cookies ? cookies + "; " + nc : nc;
          let d = "";
          res.on("data", (c) => (d += c));
          res.on("end", () =>
            resolve({
              status: res.statusCode,
              headers: res.headers,
              body: d,
              cookies: ac,
            }),
          );
        },
      )
      .on("error", reject)
      .on("timeout", function () {
        this.destroy();
        reject(new Error("POST timeout"));
      })
      .end(data);
  });
}
function parseWhoisTable(html, domain) {
  const wd = {};
  const wm = html.match(
    /<div[^>]*class="[^"]*whois-record[^"]*"[^>]*>([\s\S]*?)<\/div>/i,
  );
  const sh = wm ? wm[1] : html;
  const rr =
    /<tr[^>]*>\s*<td[^>]*>([^<]+)<\/td>\s*<td[^>]*>([\s\S]*?)<\/td>\s*<\/tr>/gi;
  let m;
  while ((m = rr.exec(sh)) !== null) {
    const k = m[1].trim().replace(/[:]+$/, "").replace(/\s+/g, " ").trim();
    const v = m[2]
      .replace(/<strong[^>]*>/gi, "")
      .replace(/<\/strong>/gi, "")
      .replace(/<[^>]+>/g, "")
      .replace(/&nbsp;/g, " ")
      .replace(/&amp;/g, "&")
      .replace(/\s+/g, " ")
      .trim();
    if (k && v && v.length > 0) {
      if (
        k.toLowerCase().includes("mobile") ||
        k.toLowerCase().includes("telephone") ||
        k.toLowerCase().includes("phone")
      ) {
        wd[k] = maskPhone(v);
      } else {
        wd[k] = v;
      }
    }
  }
  const fm = {
    "Domain Name": "Domain Name",
    "First registered date": "Registration Date",
    "Last updated date": "Updated Date",
    "Primary name server": "Primary Name Server",
    "Secondary name server": "Secondary Name Server",
    "Registrant Email": "Registrant Email",
    "Contact person": "Registrant Name",
    "Company name": "Registrant Organization",
    "Administrative Email": "Admin Email",
    Mobile: "Phone",
    Telephone: "Phone",
    Address: "Address",
  };
  const cd = {};
  for (const [k, v] of Object.entries(wd)) {
    const mk = fm[k] || k;
    if (v && v.length > 0 && v !== "-" && v !== "—") cd[mk] = v;
  }
  if (cd["Primary Name Server"] || cd["Secondary Name Server"]) {
    const ns = [];
    if (cd["Primary Name Server"]) ns.push(cd["Primary Name Server"]);
    if (cd["Secondary Name Server"]) ns.push(cd["Secondary Name Server"]);
    cd["Name Server"] = ns.join(", ");
  }
  if (Object.keys(cd).length >= 3)
    return {
      success: true,
      source: "register.com.np",
      data: cd,
      available: false,
    };
  const l = html.toLowerCase();
  if (
    l.includes("congratulations") ||
    l.includes("is available") ||
    l.includes("can be registered")
  ) {
    return {
      success: true,
      source: "register.com.np",
      data: { "Domain Name": domain, Status: "Available" },
      available: true,
    };
  }
  return { success: false, error: "Could not parse WHOIS data" };
}
async function scrapeRegisterNpWHOIS(domain) {
  try {
    let dn = domain,
      de = ".com.np";
    const em = domain.match(
      /^(.+?)(\.(?:com|org|net|edu|gov|mil|info|name|coop)\.np)$/,
    );
    if (em) {
      dn = em[1];
      de = em[2];
    } else if (domain.endsWith(".np")) {
      dn = domain.replace(/\.np$/, "");
      de = ".np";
    }
    const s1 = await makeGetReq("https://register.com.np/whois-lookup");
    let csrf = "";
    const cm = s1.body.match(/name="_token"\s+value="([^"]+)"/);
    if (cm) csrf = cm[1];
    const pd = `_token=${encodeURIComponent(csrf)}&domainName=${encodeURIComponent(dn)}&domainExtension=${encodeURIComponent(de)}`;
    const s2 = await makePostReq(
      "https://register.com.np/checkdomain_whois",
      pd,
      s1.cookies,
      "https://register.com.np/whois-lookup",
    );
    if ([301, 302, 303, 307].includes(s2.status) && s2.headers.location) {
      const ru = s2.headers.location.startsWith("http")
        ? s2.headers.location
        : `https://register.com.np${s2.headers.location}`;
      const s3 = await makeGetReq(
        ru,
        s2.cookies,
        "https://register.com.np/whois-lookup",
      );
      if ([301, 302].includes(s3.status) && s3.headers.location) {
        const r2 = s3.headers.location.startsWith("http")
          ? s3.headers.location
          : `https://register.com.np${s3.headers.location}`;
        const s4 = await makeGetReq(r2, s3.cookies, ru);
        return parseWhoisTable(s4.body, domain);
      }
      return parseWhoisTable(s3.body, domain);
    }
    return parseWhoisTable(s2.body, domain);
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ─── TECH STACK ────────────────────────────────────────
async function detectTechStack(domain, headers, body) {
  const t = [];
  const h = headers || {};
  const b = (body || "").toLowerCase();
  if (h["cf-ray"] || b.includes("cloudflare"))
    t.push({ category: "CDN", name: "Cloudflare" });
  if (h["x-vercel-id"]) t.push({ category: "Hosting", name: "Vercel" });
  if (h["x-netlify-id"]) t.push({ category: "Hosting", name: "Netlify" });
  if (h["x-github-request-id"])
    t.push({ category: "Hosting", name: "GitHub Pages" });
  if (h["x-amz-request-id"]) t.push({ category: "Hosting", name: "AWS" });
  const s = h["server"] || "";
  if (s.includes("nginx")) t.push({ category: "Web Server", name: "nginx" });
  else if (s.includes("apache"))
    t.push({ category: "Web Server", name: "Apache" });
  else if (s.includes("litespeed"))
    t.push({ category: "Web Server", name: "LiteSpeed" });
  if (b.includes("wp-content") || b.includes("wordpress"))
    t.push({ category: "CMS", name: "WordPress" });
  if (b.includes("drupal")) t.push({ category: "CMS", name: "Drupal" });
  if (b.includes("joomla")) t.push({ category: "CMS", name: "Joomla" });
  if (b.includes("shopify"))
    t.push({ category: "E-commerce", name: "Shopify" });
  if (b.includes("__next") || b.includes("/_next/"))
    t.push({ category: "Framework", name: "Next.js" });
  if (b.includes("react") && b.includes("react-dom"))
    t.push({ category: "Library", name: "React" });
  if (b.includes("vue.js")) t.push({ category: "Framework", name: "Vue.js" });
  if (b.includes("jquery")) t.push({ category: "Library", name: "jQuery" });
  if (b.includes("bootstrap")) t.push({ category: "CSS", name: "Bootstrap" });
  if (b.includes("tailwind")) t.push({ category: "CSS", name: "Tailwind CSS" });
  if (b.includes("google-analytics") || b.includes("gtag("))
    t.push({ category: "Analytics", name: "Google Analytics" });
  if (b.includes("hotjar")) t.push({ category: "Analytics", name: "Hotjar" });
  if (b.includes("recaptcha"))
    t.push({ category: "Security", name: "reCAPTCHA" });
  const g = {};
  for (const x of t) {
    if (!g[x.category]) g[x.category] = [];
    if (!g[x.category].find((y) => y.name === x.name))
      g[x.category].push({ name: x.name });
  }
  return Object.entries(g).map(([c, i]) => ({ category: c, items: i }));
}

// ═══════════════════════════════════════
// API ROUTES
// ═══════════════════════════════════════

app.get("/api/dns", async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: "Invalid domain" });
  const ck = `dns:${domain}`;
  if (cache.has(ck)) return res.json(cache.get(ck));
  const types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"];
  const records = {},
    errors = {};
  await Promise.allSettled(
    types.map(async (t) => {
      try {
        switch (t) {
          case "A":
            records.A = await dns.resolve4(domain);
            break;
          case "AAAA":
            records.AAAA = await dns.resolve6(domain);
            break;
          case "MX":
            records.MX = await dns.resolveMx(domain);
            break;
          case "NS":
            records.NS = await dns.resolveNs(domain);
            break;
          case "TXT":
            records.TXT = (await dns.resolveTxt(domain)).map((x) => x.join(""));
            break;
          case "CNAME":
            records.CNAME = await dns.resolveCname(domain).catch(() => []);
            break;
          case "SOA":
            records.SOA = await dns.resolveSoa(domain).catch(() => null);
            break;
          case "CAA":
            records.CAA = await dns.resolveCaa(domain).catch(() => []);
            break;
        }
      } catch (e) {
        if (e.code !== "ENODATA" && e.code !== "ENOTFOUND")
          errors[t] = e.message;
      }
    }),
  );
  const ns = records.NS || [];
  const result = {
    domain,
    records,
    errors,
    cloudflare: ns.some((n) => n.toLowerCase().includes("cloudflare")),
    nameservers: ns,
  };
  cache.set(ck, result, 300);
  res.json(result);
});

app.get("/api/whois", async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: "Invalid domain" });
  const ck = `whois:${domain}`;
  if (cache.has(ck)) return res.json(cache.get(ck));
  const isNP = domain.match(
    /\.(com\.np|org\.np|net\.np|edu\.np|gov\.np|mil\.np|np)$/,
  );
  let parsed = {},
    source = null,
    error = null,
    available = null;
  if (isNP) {
    const r = await scrapeRegisterNpWHOIS(domain);
    source = r.source || "register.com.np";
    parsed = r.data || {};
    available = r.available;
    if (!r.success) error = r.error;
  } else {
    try {
      const rd = await httpGet(`https://rdap.org/domain/${domain}`, {
        headers: { Accept: "application/json" },
      });
      if (rd.status === 200) {
        const d = JSON.parse(rd.body);
        source = "rdap";
        const ev = {};
        for (const e of d.events || [])
          ev[e.eventAction] = e.eventDate?.split("T")[0];
        const reg =
          (d.entities || [])
            .find((e) => e.roles?.includes("registrar"))
            ?.vcardArray?.[1]?.find((v) => v[0] === "fn")?.[3] || "";
        parsed = {
          "Domain Name": d.ldhName || domain,
          Status: (d.status || []).join(", "),
          Registrar: reg,
          "Registration Date": ev.registration || "",
          "Updated Date": ev.lastChanged || "",
          "Expiry Date": ev.expiration || "",
          "Name Server": (d.nameservers || [])
            .map((n) => n.ldhName)
            .filter(Boolean)
            .join(", "),
        };
      } else if (rd.status === 404) {
        parsed = { "Domain Name": domain, Status: "Not Found" };
        source = "rdap-404";
        available = true;
      }
    } catch (rdErr) {
      error = rdErr.message;
      source = "rdap-failed";
    }
  }
  const expiry = parsed["Expiry Date"] || parsed["Expiration Date"];
  const created =
    parsed["Registration Date"] || parsed["First registered date"];
  const updated = parsed["Updated Date"] || parsed["Last updated date"];
  const daysLeft = daysUntil(expiry);
  const cp = {};
  for (const [k, v] of Object.entries(parsed)) {
    if (v && v !== "null" && v !== "undefined" && v !== "" && v !== "-")
      cp[k] = v;
  }
  const result = {
    domain,
    source,
    parsed: cp,
    expiry: expiry || null,
    created: created || null,
    updated: updated || null,
    daysLeft,
    isExpired: daysLeft !== null && daysLeft < 0,
    expiringSoon: daysLeft !== null && daysLeft >= 0 && daysLeft < 30,
    available,
    isNP: !!isNP,
    success: !!source && source !== "rdap-failed",
    error: error || null,
    checkedAt: new Date().toISOString(),
  };
  cache.set(ck, result, 300);
  res.json(result);
});

app.get("/api/ssl", async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: "Invalid domain" });
  const ck = `ssl:${domain}`;
  if (cache.has(ck)) return res.json(cache.get(ck));
  try {
    const cert = await new Promise((resolve, reject) => {
      const s = tls.connect(
        {
          host: domain,
          port: 443,
          servername: domain,
          rejectUnauthorized: false,
          timeout: 8000,
        },
        () => {
          resolve(s.getPeerCertificate(true));
          s.destroy();
        },
      );
      s.on("error", reject);
      s.on("timeout", () => {
        s.destroy();
        reject(new Error("TLS timeout"));
      });
    });
    if (!cert || !cert.subject) throw new Error("No cert");
    const vt = cert.valid_to ? new Date(cert.valid_to) : null,
      dl = vt ? Math.floor((vt - Date.now()) / 86400000) : null;
    const result = {
      domain,
      valid: dl > 0,
      daysLeft: dl,
      expiringSoon: dl !== null && dl < 30 && dl > 0,
      subject: cert.subject,
      issuer: cert.issuer,
      validFrom: cert.valid_from
        ? new Date(cert.valid_from).toISOString().split("T")[0]
        : null,
      validTo: vt?.toISOString().split("T")[0] || null,
      sans: cert.subjectaltname
        ? cert.subjectaltname.split(", ").map((s) => s.replace("DNS:", ""))
        : [],
      serialNumber: cert.serialNumber,
      fingerprint: cert.fingerprint,
      bits: cert.bits,
    };
    cache.set(ck, result, 600);
    res.json(result);
  } catch (e) {
    try {
      const bare = domain.replace(/^www\./, "");
      const cr = await httpGet(`https://crt.sh/?q=${bare}&output=json`);
      const certs = JSON.parse(cr.body);
      const latest = certs.sort(
        (a, b) => new Date(b.not_before) - new Date(a.not_before),
      )[0];
      const dl = latest?.not_after
        ? Math.floor((new Date(latest.not_after) - Date.now()) / 86400000)
        : null;
      const result = {
        domain,
        source: "crt.sh",
        valid: dl > 0,
        daysLeft: dl,
        issuer: {
          O: latest?.issuer_name?.match(/O=([^,]+)/)?.[1] || "Unknown",
        },
        validFrom: latest?.not_before?.split("T")[0],
        validTo: latest?.not_after?.split("T")[0],
        totalCerts: certs.length,
      };
      cache.set(ck, result, 600);
      res.json(result);
    } catch (crtErr) {
      res.status(500).json({ domain, error: e.message });
    }
  }
});

app.get("/api/headers", async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: "Invalid domain" });
  const ck = `hdr:${domain}`;
  if (cache.has(ck)) return res.json(cache.get(ck));
  try {
    const { status, headers } = await httpHead(`https://${domain}`);
    const sh = {
      "strict-transport-security": {
        present: !!headers["strict-transport-security"],
        label: "HSTS",
      },
      "content-security-policy": {
        present: !!headers["content-security-policy"],
        label: "CSP",
      },
      "x-frame-options": {
        present: !!headers["x-frame-options"],
        label: "X-Frame-Options",
      },
      "x-content-type-options": {
        present: !!headers["x-content-type-options"],
        label: "X-Content-Type",
      },
      "referrer-policy": {
        present: !!headers["referrer-policy"],
        label: "Referrer-Policy",
      },
      "permissions-policy": {
        present: !!headers["permissions-policy"],
        label: "Permissions-Policy",
      },
    };
    const score = Object.values(sh).filter((h) => h.present).length;
    const result = {
      domain,
      httpStatus: status,
      securityHeaders: sh,
      score,
      maxScore: Object.keys(sh).length,
      server: headers["server"] || null,
      poweredBy: headers["x-powered-by"] || null,
      allHeaders: headers,
    };
    cache.set(ck, result, 300);
    res.json(result);
  } catch (e) {
    try {
      const { status, headers } = await httpHead(`http://${domain}`);
      res.json({ domain, httpStatus: status, allHeaders: headers });
    } catch (e2) {
      res.status(500).json({ domain, error: e.message });
    }
  }
});

app.get("/api/tech", async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: "Invalid domain" });
  const ck = `tech:${domain}`;
  if (cache.has(ck)) return res.json(cache.get(ck));
  try {
    const [hr, ir] = await Promise.allSettled([
      httpGet(`https://${domain}`),
      httpGet(`http://${domain}`),
    ]);
    let headers = {},
      body = "";
    if (hr.status === "fulfilled") {
      headers = hr.value.headers;
      body = hr.value.body;
    } else if (ir.status === "fulfilled") {
      headers = ir.value.headers;
      body = ir.value.body;
    }
    const tech = await detectTechStack(domain, headers, body);
    const result = {
      domain,
      tech,
      totalTechnologies: tech.reduce((s, g) => s + g.items.length, 0),
    };
    cache.set(ck, result, 600);
    res.json(result);
  } catch (e) {
    res.status(500).json({ domain, error: e.message });
  }
});

app.get("/api/geo", async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: "Invalid domain" });
  const ck = `geo:${domain}`;
  if (cache.has(ck)) return res.json(cache.get(ck));
  let ips = [];
  try {
    ips = await dns.resolve4(domain);
  } catch (e) {
    return res.json({ domain, ips: [], primaryIp: null });
  }
  if (!ips.length) return res.json({ domain, ips: [], primaryIp: null });
  const ip = ips[0];
  let geo = {},
    gs = null;
  try {
    const r = await httpGet(
      `http://ip-api.com/json/${ip}?fields=status,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,asname`,
    );
    const d = JSON.parse(r.body);
    if (d.status === "success") {
      geo = d;
      gs = "ip-api.com";
    }
  } catch (_) {}
  if (!gs)
    try {
      const r = await httpGet(`https://ipapi.co/${ip}/json/`);
      const d = JSON.parse(r.body);
      if (!d.error) {
        geo = {
          country: d.country_name,
          countryCode: d.country_code,
          regionName: d.region,
          city: d.city,
          timezone: d.timezone,
          isp: d.org,
          org: d.org,
          as: d.asn,
          asname: d.org,
          lat: d.latitude,
          lon: d.longitude,
        };
        gs = "ipapi.co";
      }
    } catch (_) {}
  const result = {
    domain,
    ips,
    primaryIp: ip,
    geoSource: gs,
    country: geo.country || null,
    countryCode: geo.countryCode || null,
    city: geo.city || null,
    region: geo.regionName || null,
    isp: geo.isp || null,
    asn: geo.as || null,
    isNepal: geo.countryCode === "NP",
  };
  cache.set(ck, result, 600);
  res.json(result);
});

app.get("/api/isp", async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: "Invalid domain" });
  const ck = `isp:${domain}`;
  if (cache.has(ck)) return res.json(cache.get(ck));
  try {
    const ips = await dns.resolve4(domain);
    if (!ips?.length) return res.json({ domain, isNepaliISP: false });
    const ip = ips[0];
    let asn = "",
      org = "",
      country = "";
    try {
      const r = await httpGet(
        `http://ip-api.com/json/${ip}?fields=as,org,isp,country,countryCode`,
      );
      const d = JSON.parse(r.body);
      asn = (d.as || "").split(" ")[0] || "";
      org = d.org || d.isp || "";
      country = d.country || "";
    } catch (_) {}
    let hostname = "";
    try {
      const r = await dns.reverse(ip);
      hostname = r[0] || "";
    } catch (_) {}
    const isp = detectNepaliISP(ip, hostname, asn);
    res.json({
      domain,
      ip,
      asn: asn || null,
      country: country || null,
      isNepaliISP: !!isp,
      detectedISP: isp
        ? {
            name: isp.name,
            nameNepali: isp.nameNepali,
            slug: isp.slug,
            asn: isp.asn,
            color: isp.color,
            website: isp.website,
            logo: isp.logo,
            category: isp.category,
            detectionMethod: isp.detectionMethod,
            confidence: isp.confidence,
            matchedVia: isp.matchedVia,
          }
        : null,
      foreignISP: !isp
        ? { name: org || "Unknown", country: country || "Unknown" }
        : null,
    });
  } catch (e) {
    res.status(500).json({ domain, error: e.message });
  }
});

app.get("/api/dnssec", async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: "Invalid domain" });
  const ck = `dnssec:${domain}`;
  if (cache.has(ck)) return res.json(cache.get(ck));
  const result = {
    domain,
    enabled: false,
    score: 0,
    maxScore: 100,
    checks: {
      dsRecord: { passed: false, weight: 40 },
      rrsigPresent: { passed: false, weight: 30 },
      dnsKeyPresent: { passed: false, weight: 20 },
      nsecRecords: { passed: false, weight: 10 },
    },
    recommendations: [],
  };
  try {
    try {
      await dns.resolve(domain, "DS");
      result.checks.dsRecord.passed = true;
      result.score += 40;
    } catch (e) {
      result.recommendations.push("Add DS record at registrar");
    }
    try {
      await dns.resolve(domain, "RRSIG");
      result.checks.rrsigPresent.passed = true;
      result.score += 30;
    } catch (e) {
      result.recommendations.push("Sign your DNS zone");
    }
    try {
      await dns.resolve(domain, "DNSKEY");
      result.checks.dnsKeyPresent.passed = true;
      result.score += 20;
    } catch (e) {
      result.recommendations.push("Publish DNSKEY records");
    }
    try {
      const n =
        (await dns.resolve(domain, "NSEC").catch(() => null)) ||
        (await dns.resolve(domain, "NSEC3").catch(() => null));
      if (n?.length) {
        result.checks.nsecRecords.passed = true;
        result.score += 10;
      }
    } catch (e) {}
    result.enabled = result.score >= 50;
    result.verified = result.score >= 90;
    result.summary = result.verified
      ? {
          status: "verified",
          label: "Fully Verified",
          icon: "🛡️",
          color: "#059669",
        }
      : result.enabled
        ? {
            status: "partial",
            label: "Partially Enabled",
            icon: "⚠️",
            color: "#D97706",
          }
        : {
            status: "disabled",
            label: "Not Configured",
            icon: "ℹ️",
            color: "#64748B",
          };
  } catch (e) {
    result.error = e.message;
  }
  cache.set(ck, result, 300);
  res.json(result);
});

// ─── STATS — Cached for 1 MONTH (30 days) ──────────────
app.get("/api/stats", (req, res) => {
  const ck = "stats:nepal";
  const cached = cache.get(ck);
  if (cached) {
    cached.servedFromCache = true;
    cached.cacheExpiresIn =
      Math.floor((cache.getTtl(ck) - Date.now()) / 1000 / 86400) + " days";
    return res.json(cached);
  }
  const stats = {
    overview: {
      totalDomains: "92K+",
      activeTLDs: 7,
      ispsDetected: 8,
      dnssecAdoption: "14%",
      cloudflareAdoption: "20%",
      sslAdoption: "48%",
      avgDomainAge: "4.5 years",
    },
    tldDistribution: [
      { name: ".com.np", percentage: 78, color: "#6366F1" },
      { name: ".org.np", percentage: 11, color: "#10B981" },
      { name: ".edu.np", percentage: 4, color: "#F59E0B" },
      { name: ".net.np", percentage: 3, color: "#8B5CF6" },
      { name: ".gov.np", percentage: 2, color: "#EF4444" },
      { name: "Others", percentage: 2, color: "#64748B" },
    ],
ispHosting: [
  { name: 'Worldlink', percentage: 28, color: '#00A651' },
  { name: 'Cloudflare', percentage: 18, color: '#F59E0B' },
  { name: 'Vianet', percentage: 12, color: '#EE3124' },
  { name: 'NTC', percentage: 10, color: '#003893' },
  { name: 'Subisu', percentage: 8, color: '#ED6B06' },
  { name: 'DishHome', percentage: 6, color: '#E31937' },
  { name: 'International', percentage: 10, color: '#06B6D4' },
  { name: 'Others', percentage: 8, color: '#64748B' },
],
    cacheDuration: "30 days (1 month)",
    lastUpdated: new Date().toISOString(),
  };
  // Cache for 30 days (2592000 seconds)
  cache.set(ck, stats, 2592000);
  res.json(stats);
});

app.get("/api/reverse-ip", async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: "Invalid domain" });
  const ck = `revip:${domain}`;
  if (cache.has(ck)) return res.json(cache.get(ck));
  try {
    const ips = await dns.resolve4(domain);
    if (!ips.length) return res.json({ domain, ip: null, domains: [] });
    const ip = ips[0];
    let domains = [];
    try {
      const r = await httpGet(
        `https://api.hackertarget.com/reverseiplookup/?q=${ip}`,
      );
      domains = r.body
        .split("\n")
        .filter((d) => d.trim())
        .slice(0, 30);
    } catch (e) {}
    const result = {
      domain,
      ip,
      totalDomains: domains.length,
      nepaliDomains: domains.filter((d) => d.endsWith(".np")),
      otherDomains: domains.filter((d) => !d.endsWith(".np")).slice(0, 10),
    };
    cache.set(ck, result, 600);
    res.json(result);
  } catch (e) {
    res.json({ domain, ip: null, domains: [] });
  }
});

app.get("/api/dns-check", async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: "Invalid domain" });
  const ck = `dnscheck:${domain}`;
  if (cache.has(ck)) return res.json(cache.get(ck));
  const checks = {
    aRecord: { name: "A Record (IPv4)", passed: false, score: 15 },
    aaaaRecord: { name: "AAAA Record (IPv6)", passed: false, score: 10 },
    mxRecord: { name: "MX Record (Email)", passed: false, score: 10 },
    spfRecord: { name: "SPF Record", passed: false, score: 15 },
    dmarcRecord: { name: "DMARC Record", passed: false, score: 15 },
    dnssec: { name: "DNSSEC", passed: false, score: 15 },
    nsCount: { name: "Multiple Nameservers", passed: false, score: 10 },
    wwwRecord: { name: "WWW Subdomain", passed: false, score: 10 },
  };
  try {
    try {
      await dns.resolve4(domain);
      checks.aRecord.passed = true;
    } catch (e) {}
    try {
      await dns.resolve6(domain);
      checks.aaaaRecord.passed = true;
    } catch (e) {}
    try {
      const mx = await dns.resolveMx(domain);
      checks.mxRecord.passed = mx.length > 0;
    } catch (e) {}
    try {
      const txt = await dns.resolveTxt(domain);
      checks.spfRecord.passed = txt.flat().some((r) => r.includes("v=spf1"));
    } catch (e) {}
    try {
      const dm = await dns.resolveTxt(`_dmarc.${domain}`).catch(() => []);
      checks.dmarcRecord.passed = dm.length > 0;
    } catch (e) {}
    try {
      await dns.resolve(domain, "DS");
      checks.dnssec.passed = true;
    } catch (e) {}
    try {
      const ns = await dns.resolveNs(domain);
      checks.nsCount.passed = ns.length >= 2;
    } catch (e) {}
    try {
      await dns.resolve4(`www.${domain}`);
      checks.wwwRecord.passed = true;
    } catch (e) {}
  } catch (e) {}
  const totalScore = Object.values(checks).reduce(
    (s, c) => s + (c.passed ? c.score : 0),
    0,
  );
  const maxScore = Object.values(checks).reduce((s, c) => s + c.score, 0);
  const pct = Math.round((totalScore / maxScore) * 100);
  const grade =
    pct >= 80 ? "A" : pct >= 60 ? "B" : pct >= 40 ? "C" : pct >= 20 ? "D" : "F";
  const gradeColors = {
    A: "#10B981",
    B: "#6366F1",
    C: "#F59E0B",
    D: "#EF4444",
    F: "#DC2626",
  };
  const result = {
    domain,
    checks,
    totalScore,
    maxScore,
    grade,
    gradeColor: gradeColors[grade],
    percentage: pct,
  };
  cache.set(ck, result, 600);
  res.json(result);
});

// ─── BANK SCORECARD (v11 — Instant + Background Refresh) ─
let bankCheckRunning = false;

// Pre-computed fallback data (updated manually or by background job)
const FALLBACK_BANKS = {
  banks: [
    {
      name: "Nepal Bank",
      domain: "nepalbank.com.np",
      ssl: "✅",
      dnssec: "❌",
      spf: "✅",
      dmarc: "✅",
      score: 75,
      grade: "B",
    },
    {
      name: "Rastriya Banijya Bank",
      domain: "rbb.com.np",
      ssl: "✅",
      dnssec: "❌",
      spf: "✅",
      dmarc: "✅",
      score: 75,
      grade: "B",
    },
    {
      name: "Laxmi Bank",
      domain: "laxmibank.com.np",
      ssl: "❌",
      dnssec: "❌",
      spf: "✅",
      dmarc: "✅",
      score: 45,
      grade: "C",
    },
    {
      name: "Citizens Bank",
      domain: "ctznbank.com.np",
      ssl: "✅",
      dnssec: "❌",
      spf: "❌",
      dmarc: "❌",
      score: 30,
      grade: "D",
    },
    {
      name: "Nabil Bank",
      domain: "nabilbank.com.np",
      ssl: "❌",
      dnssec: "❌",
      spf: "✅",
      dmarc: "❌",
      score: 25,
      grade: "D",
    },
    {
      name: "Global IME Bank",
      domain: "globalimebank.com.np",
      ssl: "❌",
      dnssec: "❌",
      spf: "✅",
      dmarc: "❌",
      score: 25,
      grade: "D",
    },
    {
      name: "NMB Bank",
      domain: "nmbbank.com.np",
      ssl: "❌",
      dnssec: "❌",
      spf: "✅",
      dmarc: "❌",
      score: 25,
      grade: "D",
    },
    {
      name: "Sanima Bank",
      domain: "sanimabank.com.np",
      ssl: "❌",
      dnssec: "❌",
      spf: "✅",
      dmarc: "❌",
      score: 25,
      grade: "D",
    },
    {
      name: "Himalayan Bank",
      domain: "himalayanbank.com.np",
      ssl: "❌",
      dnssec: "❌",
      spf: "❌",
      dmarc: "❌",
      score: 0,
      grade: "F",
    },
    {
      name: "NIC Asia Bank",
      domain: "nicasiabank.com.np",
      ssl: "❌",
      dnssec: "❌",
      spf: "❌",
      dmarc: "❌",
      score: 0,
      grade: "F",
    },
    {
      name: "Prabhu Bank",
      domain: "prabhubank.com.np",
      ssl: "❌",
      dnssec: "❌",
      spf: "❌",
      dmarc: "❌",
      score: 0,
      grade: "F",
    },
    {
      name: "Kumari Bank",
      domain: "kumaribank.com.np",
      ssl: "❌",
      dnssec: "❌",
      spf: "❌",
      dmarc: "❌",
      score: 0,
      grade: "F",
    },
    {
      name: "Siddhartha Bank",
      domain: "siddharthabank.com.np",
      ssl: "❌",
      dnssec: "❌",
      spf: "❌",
      dmarc: "❌",
      score: 0,
      grade: "F",
    },
    {
      name: "Everest Bank",
      domain: "everestbank.com.np",
      ssl: "❌",
      dnssec: "❌",
      spf: "❌",
      dmarc: "❌",
      score: 0,
      grade: "F",
    },
    {
      name: "Agriculture Development Bank",
      domain: "adbl.com.np",
      ssl: "❌",
      dnssec: "❌",
      spf: "❌",
      dmarc: "❌",
      score: 0,
      grade: "F",
    },
  ],
  totalBanks: 15,
  avgScore: 18,
  lastChecked: new Date().toISOString(),
  isFallback: true,
};

app.get("/api/bank-scorecard", async (req, res) => {
  const ck = "banks:scorecard:v11";
  const forceRefresh = req.query.refresh === "true";

  // Return cached data immediately
  if (!forceRefresh) {
    const cached = cache.get(ck);
    if (cached) {
      cached.servedFromCache = true;
      return res.json(cached);
    }
    // Return fallback data instantly
    return res.json({ ...FALLBACK_BANKS, servedFromFallback: true });
  }

  // Force refresh — return cached + trigger background update
  const cached = cache.get(ck);
  if (cached && !bankCheckRunning) {
    // Trigger background refresh
    refreshBanksInBackground();
  }

  if (cached) {
    cached.servedFromCache = true;
    cached.refreshing = bankCheckRunning;
    return res.json(cached);
  }

  // No cache — return fallback and start background refresh
  if (!bankCheckRunning) {
    refreshBanksInBackground();
  }

  return res.json({
    ...FALLBACK_BANKS,
    servedFromFallback: true,
    refreshing: true,
  });
});

// Background bank refresh
async function refreshBanksInBackground() {
  if (bankCheckRunning) return;
  bankCheckRunning = true;

  const banks = [
    { name: "Himalayan Bank", domain: "himalayanbank.com.np" },
    { name: "Nabil Bank", domain: "nabilbank.com.np" },
    { name: "NIC Asia Bank", domain: "nicasiabank.com.np" },
    { name: "Global IME Bank", domain: "globalimebank.com.np" },
    { name: "Prabhu Bank", domain: "prabhubank.com.np" },
    { name: "Kumari Bank", domain: "kumaribank.com.np" },
    { name: "NMB Bank", domain: "nmbbank.com.np" },
    { name: "Sanima Bank", domain: "sanimabank.com.np" },
    { name: "Siddhartha Bank", domain: "siddharthabank.com.np" },
    { name: "Everest Bank", domain: "everestbank.com.np" },
    { name: "Nepal Bank", domain: "nepalbank.com.np" },
    { name: "Rastriya Banijya Bank", domain: "rbb.com.np" },
    { name: "Agriculture Development Bank", domain: "adbl.com.np" },
    { name: "Laxmi Bank", domain: "laxmibank.com.np" },
    { name: "Citizens Bank", domain: "ctznbank.com.np" },
  ];

  const checkSSL = async (d) => {
    try {
      const c = await new Promise((r) => {
        const s = tls.connect(
          {
            host: d,
            port: 443,
            servername: d,
            rejectUnauthorized: false,
            timeout: 6000,
          },
          () => {
            const x = s.getPeerCertificate();
            s.destroy();
            r(x);
          },
        );
        s.on("error", () => {
          s.destroy();
          r(null);
        });
        s.on("timeout", () => {
          s.destroy();
          r(null);
        });
      });
      return c?.valid_to ? new Date(c.valid_to) > new Date() : false;
    } catch (e) {
      return false;
    }
  };

  const checkSPF = async (d) => {
    try {
      const t = await Promise.race([
        dns.resolveTxt(d),
        new Promise((_, r) => setTimeout(() => r(new Error()), 3000)),
      ]);
      return t
        .flat()
        .some((r) => String(r).trim().toLowerCase().startsWith("v=spf1"));
    } catch (e) {
      return false;
    }
  };

  const checkDMARC = async (d) => {
    try {
      const t = await Promise.race([
        dns.resolveTxt(`_dmarc.${d}`),
        new Promise((_, r) => setTimeout(() => r(new Error()), 3000)),
      ]);
      return t
        .flat()
        .some((r) => String(r).trim().toLowerCase().startsWith("v=dmarc1"));
    } catch (e) {
      return false;
    }
  };

  const checkDNSSEC = async (d) => {
    try {
      await Promise.race([
        dns.resolve(d, "DS"),
        new Promise((_, r) => setTimeout(() => r(new Error()), 2000)),
      ]);
      return true;
    } catch (e) {
      return false;
    }
  };

  try {
    console.log(`[BANK-BG] 🔄 Background refresh started`);
    const start = Date.now();
    const results = [];

    for (const bank of banks) {
      const [ssl, spf, dmarc, dnssec] = await Promise.all([
        checkSSL(bank.domain),
        checkSPF(bank.domain),
        checkDMARC(bank.domain),
        checkDNSSEC(bank.domain),
      ]);
      const score =
        (ssl ? 30 : 0) + (dnssec ? 25 : 0) + (spf ? 25 : 0) + (dmarc ? 20 : 0);
      results.push({
        name: bank.name,
        domain: bank.domain,
        ssl: ssl ? "✅" : "❌",
        dnssec: dnssec ? "✅" : "❌",
        spf: spf ? "✅" : "❌",
        dmarc: dmarc ? "✅" : "❌",
        score,
        grade:
          score >= 80
            ? "A"
            : score >= 60
              ? "B"
              : score >= 40
                ? "C"
                : score >= 20
                  ? "D"
                  : "F",
      });
    }

    const sorted = results.sort((a, b) => b.score - a.score);
    const avg = Math.round(
      sorted.reduce((s, b) => s + b.score, 0) / sorted.length,
    );
    const response = {
      banks: sorted,
      totalBanks: sorted.length,
      avgScore: avg,
      lastChecked: new Date().toISOString(),
      isFallback: false,
    };
    cache.set("banks:scorecard:v11", response, 86400);
    console.log(
      `[BANK-BG] ✅ Done in ${((Date.now() - start) / 1000).toFixed(1)}s | SSL=${sorted.filter((b) => b.ssl === "✅").length} SPF=${sorted.filter((b) => b.spf === "✅").length} DMARC=${sorted.filter((b) => b.dmarc === "✅").length}`,
    );
  } catch (e) {
    console.error("[BANK-BG] ❌", e.message);
  }

  bankCheckRunning = false;
}

app.get("/api/domain-generate", async (req, res) => {
  const kw = (req.query.keyword || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]/g, "");
  if (!kw || kw.length < 2)
    return res.status(400).json({ error: "Min 2 characters" });
  const exts = [".com.np", ".org.np", ".net.np", ".info.np"];
  const combos = [
    kw,
    "the" + kw,
    kw + "nepal",
    "nepal" + kw,
    kw + "online",
    kw + "hub",
    "my" + kw,
    kw + "web",
  ];
  const suggestions = [];
  for (const c of combos)
    for (const e of exts) suggestions.push({ domain: c + e, available: null });
  const toCheck = suggestions.slice(0, 10);
  await Promise.allSettled(
    toCheck.map(async (s) => {
      try {
        await dns.resolve4(s.domain);
        s.available = false;
        s.status = "Taken";
      } catch (e) {
        s.available = true;
        s.status = "Available ✅";
      }
    }),
  );
  res.json({
    keyword: kw,
    suggestions: toCheck.sort(
      (a, b) =>
        (a.available === true ? -1 : 1) - (b.available === true ? -1 : 1),
    ),
  });
});

app.get("/api/compare", async (req, res) => {
  const d1 = validateDomain(req.query.domain1),
    d2 = validateDomain(req.query.domain2);
  if (!d1 || !d2) return res.status(400).json({ error: "Need two domains" });
  async function qi(d) {
    const i = { domain: d, dns: {}, ssl: null, dnssec: false };
    try {
      i.dns.a = (await dns.resolve4(d))[0] || null;
    } catch (e) {}
    try {
      i.dns.ns = await dns.resolveNs(d);
    } catch (e) {}
    try {
      await dns.resolve(d, "DS");
      i.dnssec = true;
    } catch (e) {}
    return i;
  }
  const [i1, i2] = await Promise.all([qi(d1), qi(d2)]);
  res.json({ domain1: i1, domain2: i2, checkedAt: new Date().toISOString() });
});

app.get("/api/availability", async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: "Invalid domain" });
  let available = null,
    method = null;
  try {
    await dns.resolve4(domain);
    available = false;
    method = "dns";
  } catch (_) {
    try {
      const r = await httpGet(`https://rdap.org/domain/${domain}`);
      available = r.status === 404;
      method = "rdap";
    } catch (_2) {
      method = "unknown";
    }
  }
  res.json({ domain, available, method, checkedAt: new Date().toISOString() });
});

// ─── Health + Static + 404 ─────────────────────────────
app.get("/health", (_, res) => {
  res.json({
    status: "ok",
    version: "5.2.0",
    uptime: process.uptime(),
    memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + "MB",
    timestamp: new Date().toISOString(),
  });
});
app.get("/", (_, res) => res.sendFile(path.join(__dirname, "index.html")));
app.use((req, res) => {
  if (req.path.startsWith("/api/"))
    return res.status(404).json({ error: "Not found" });
  res.status(404).sendFile(path.join(__dirname, "index.html"));
});
app.use((err, req, res, next) => {
  console.error(`[ERROR] ${err.message}`);
  res
    .status(500)
    .json({ error: isProduction ? "Internal error" : err.message });
});

// ─── Start ─────────────────────────────────────────────
const server = app.listen(PORT, () => {
  console.log(
    `✅ NP Radar v5.2 — Port ${PORT} | Mode: ${isProduction ? "PROD" : "DEV"} | Stats: 30d cache | Bank: 24h cache`,
  );
});
process.on("SIGTERM", () => {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10000);
});
process.on("SIGINT", () => {
  server.close(() => process.exit(0));
});
module.exports = app;
