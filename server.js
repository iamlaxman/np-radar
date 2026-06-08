/**
 * NP Radar Backend — Nepal Domain Intelligence API v5.1 (Production Ready)
 * 
 * Production Features:
 * - Helmet.js for security headers
 * - Compression for bandwidth optimization
 * - express-rate-limit for proper rate limiting
 * - Request size limiting
 * - Graceful shutdown
 * - Trust proxy for reverse proxy setups
 * - Production logging
 * - Cache optimization
 */

const express        = require('express');
const cors           = require('cors');
const helmet         = require('helmet');
const compression    = require('compression');
const rateLimit      = require('express-rate-limit');
const dns            = require('dns').promises;
const net            = require('net');
const tls            = require('tls');
const https          = require('https');
const http           = require('http');
const path           = require('path');
const NodeCache      = require('node-cache');

const app   = express();
const cache = new NodeCache({ 
  stdTTL: 300,
  checkperiod: 60,
  useClones: false,
  deleteOnExpire: true,
});

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const isProduction = NODE_ENV === 'production';

// ═══════════════════════════════════════════════════════
// PRODUCTION MIDDLEWARE
// ═══════════════════════════════════════════════════════

// 1. Trust proxy (required behind nginx/cloudflare/reverse proxy)
app.set('trust proxy', 1);

// 2. Helmet — Security headers
app.use(helmet({
  contentSecurityPolicy: false, // Allow inline styles (Tailwind)
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
}));

// 3. Compression — Gzip/brotli responses
app.use(compression({
  level: 6,
  threshold: 1024, // Only compress responses > 1KB
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  },
}));

// 4. CORS — Allow frontend domains
const corsOptions = {
  origin: isProduction 
    ? [
        'https://npradar.laxman-poudel.com.np',
        'https://laxman-poudel.com.np',
        /\.laxman-poudel\.com\.np$/,
      ]
    : '*',
  methods: ['GET', 'HEAD'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400, // 24 hours
};
app.use(cors(corsOptions));

// 5. Rate Limiting — Proper with express-rate-limit
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: isProduction ? 60 : 200, // 60/min in production, 200/min in dev
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Rate limit exceeded',
    retryAfter: '60 seconds',
    message: 'Too many requests. Please try again in a minute.',
  },
  keyGenerator: (req) => {
    return req.ip || req.connection.remoteAddress || 'unknown';
  },
  skip: (req) => {
    // Don't rate limit health checks
    return req.path === '/health';
  },
});
app.use('/api/', limiter);

// 6. Body parser with size limits
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// 7. Request logging (minimal)
if (!isProduction) {
  app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
      const duration = Date.now() - start;
      if (req.path.startsWith('/api/') || req.path === '/health') {
        console.log(`${req.method} ${req.path} → ${res.statusCode} (${duration}ms)`);
      }
    });
    next();
  });
}

// 8. Static files with caching
const staticOptions = {
  maxAge: isProduction ? '7d' : '0',
  etag: true,
  lastModified: true,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    } else if (filePath.match(/\.(css|js|png|jpg|ico|svg)$/)) {
      res.setHeader('Cache-Control', `public, max-age=${isProduction ? 604800 : 0}`);
    }
  },
};
app.use(express.static(__dirname, staticOptions));

// ═══════════════════════════════════════════════════════
// HELPERS (Same as before)
// ═══════════════════════════════════════════════════════

function validateDomain(domain) {
  if (!domain || typeof domain !== 'string') return null;
  const clean = domain.trim().toLowerCase()
    .replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/^www\./i, '');
  if (!/^[a-z0-9][a-z0-9\-\.]{1,250}[a-z0-9]$/.test(clean)) return null;
  if (clean.includes('..')) return null;
  return clean;
}

function httpGet(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, { 
      timeout: 15000, 
      headers: { 
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
      }, 
      ...opts 
    }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return httpGet(res.headers.location, opts).then(resolve).catch(reject);
      }
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

function httpHead(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === 'https:' ? https : http;
    const req = lib.request({
      method: 'HEAD', hostname: parsed.hostname, path: parsed.pathname + parsed.search,
      timeout: 8000, rejectUnauthorized: false, ...opts
    }, res => { resolve({ status: res.statusCode, headers: res.headers }); res.destroy(); });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('HEAD timeout')); });
    req.end();
  });
}

function daysUntil(dateStr) {
  if (!dateStr) return null;
  let d = new Date(dateStr);
  if (isNaN(d)) {
    const parts = dateStr.split(/[\/\-\.\s]/);
    if (parts.length >= 3) d = new Date(`${parts[0]}-${parts[1]}-${parts[2]}`);
  }
  if (isNaN(d)) return null;
  return Math.floor((d - Date.now()) / 86_400_000);
}

function ipToInt(ip) { return ip.split('.').reduce((acc, o) => (acc << 8) + parseInt(o), 0); }
function parseCIDR(cidr) {
  const [ip, p] = cidr.split('/');
  const i = ipToInt(ip);
  const m = ~(2 ** (32 - parseInt(p)) - 1);
  return [i & m, (i & m) + 2 ** (32 - parseInt(p)) - 1];
}
function ipInRange(ip, cidr) { const [s, e] = parseCIDR(cidr); return ipToInt(ip) >= s && ipToInt(ip) <= e; }

function maskPhoneNumber(phone) {
  if (!phone || typeof phone !== 'string') return phone;
  const digits = phone.replace(/\D/g, '');
  if (digits.length <= 4) return digits.replace(/\d/g, '*');
  if (digits.length <= 6) return digits.substring(0, 2) + '*'.repeat(digits.length - 2);
  return digits.substring(0, 3) + '*'.repeat(digits.length - 5) + digits.substring(digits.length - 2);
}

// ═══════════════════════════════════════════════════════
// ISP DATABASE (8 Nepali ISPs)
// ═══════════════════════════════════════════════════════

const NEPALI_ISP_DB = {
  worldlink: { name: 'Worldlink Communications', nameNepali: 'वर्ल्डलिंक', slug: 'worldlink', asn: ['AS17501', 'AS139334'], ipRanges: ['202.51.64.0/19', '202.51.76.0/22', '103.28.84.0/22', '103.69.124.0/22', '103.120.200.0/22', '103.10.28.0/22', '103.119.60.0/22'], hostnamePatterns: ['worldlink.com.np', 'wlink.com.np', 'wl.net.np'], color: '#00A651', website: 'https://worldlink.com.np', logo: '🏢', category: 'tier1' },
  dishome: { name: 'DishHome Internet', nameNepali: 'डिशहोम', slug: 'dishome', asn: ['AS139220'], ipRanges: ['103.153.24.0/22', '103.153.28.0/22', '103.176.184.0/22'], hostnamePatterns: ['dishhome.com.np', 'dishmedia.com.np'], color: '#E31937', website: 'https://www.dishhome.com.np', logo: '📡', category: 'tier1' },
  ntc: { name: 'Nepal Telecom FTTH', nameNepali: 'नेपाल टेलिकम', slug: 'ntc', asn: ['AS23752', 'AS131315', 'AS136201'], ipRanges: ['202.45.144.0/20', '27.34.0.0/15', '110.44.112.0/20', '113.199.192.0/19', '43.245.124.0/22', '103.90.176.0/22'], hostnamePatterns: ['ntc.net.np', 'ntc.com.np', 'nepaltelecom.com.np'], color: '#003893', website: 'https://www.ntc.net.np', logo: '📞', category: 'tier1' },
  subisu: { name: 'Subisu Cablenet', nameNepali: 'सुविसु', slug: 'subisu', asn: ['AS4007'], ipRanges: ['202.51.80.0/20', '202.166.193.0/24', '103.69.126.0/24'], hostnamePatterns: ['subisu.net.np', 'subisu.com.np', 'cablenet.com.np'], color: '#ED6B06', website: 'https://www.subisu.net.np', logo: '🔌', category: 'tier1' },
  vianet: { name: 'Vianet Communications', nameNepali: 'भायानेट', slug: 'vianet', asn: ['AS45650'], ipRanges: ['103.10.28.0/22', '103.233.152.0/22', '202.166.192.0/20'], hostnamePatterns: ['vianet.com.np', 'vianet.net.np', 'mos.com.np'], color: '#EE3124', website: 'https://www.vianet.com.np', logo: '📡', category: 'tier1' },
  websurfer: { name: 'Web Surfer Nepal', nameNepali: 'वेब सर्फर', slug: 'websurfer', asn: ['AS132770'], ipRanges: ['103.212.220.0/22', '103.212.224.0/22'], hostnamePatterns: ['websurfer.com.np'], color: '#8B5CF6', website: 'https://websurfer.com.np', logo: '🌐', category: 'tier2' },
  classictech: { name: 'Classic Tech', nameNepali: 'क्लासिक टेक', slug: 'classictech', asn: ['AS136334'], ipRanges: ['103.119.60.0/22', '103.119.62.0/24'], hostnamePatterns: ['classic.com.np', 'classictech.com.np'], color: '#0984E3', website: 'https://www.classic.com.np', logo: '💻', category: 'tier2' },
  cgnet: { name: 'CG Net', nameNepali: 'सीजी नेट', slug: 'cgnet', asn: ['AS141365'], ipRanges: ['103.172.188.0/22', '103.172.190.0/24'], hostnamePatterns: ['cgnet.com.np', 'cgcomm.com.np'], color: '#F97316', website: 'https://cgnet.com.np', logo: '🌍', category: 'tier2' },
};

function detectNepaliISP(ip, hostname = '', asn = '') {
  if (asn) for (const [k, v] of Object.entries(NEPALI_ISP_DB)) if (v.asn.includes(asn.toUpperCase())) return { ...v, detectionMethod: 'asn', confidence: 'high', matchedVia: asn.toUpperCase() };
  if (ip) for (const [k, v] of Object.entries(NEPALI_ISP_DB)) for (const r of v.ipRanges) if (ipInRange(ip, r)) return { ...v, detectionMethod: 'ip-range', confidence: 'high', matchedVia: r };
  if (hostname) { const l = hostname.toLowerCase(); for (const [k, v] of Object.entries(NEPALI_ISP_DB)) for (const p of v.hostnamePatterns) if (l.includes(p)) return { ...v, detectionMethod: 'hostname', confidence: 'medium', matchedVia: p }; }
  return null;
}

// ═══════════════════════════════════════════════════════
// WHOIS SCRAPER (Same as before — HTTP web scraping)
// ═══════════════════════════════════════════════════════

function makeGetRequest(url, cookies = '', referer = '') {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
    };
    if (cookies) headers['Cookie'] = cookies;
    if (referer) headers['Referer'] = referer;
    const req = https.request({
      hostname: parsed.hostname, path: parsed.pathname + parsed.search,
      method: 'GET', timeout: 15000, headers,
    }, res => {
      const setCookies = res.headers['set-cookie'] || [];
      const newCookies = Array.isArray(setCookies) ? setCookies.map(c => c.split(';')[0]).join('; ') : String(setCookies).split(';')[0];
      const allCookies = cookies ? cookies + '; ' + newCookies : newCookies;
      let data = ''; res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data, cookies: allCookies }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('GET timeout')); });
    req.end();
  });
}

function makePostRequest(url, postData, cookies = '', referer = '') {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(postData),
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9', 'Origin': 'https://register.com.np',
    };
    if (cookies) headers['Cookie'] = cookies;
    if (referer) headers['Referer'] = referer;
    const req = https.request({
      hostname: parsed.hostname, path: parsed.pathname + parsed.search,
      method: 'POST', timeout: 15000, headers,
    }, res => {
      const setCookies = res.headers['set-cookie'] || [];
      const newCookies = Array.isArray(setCookies) ? setCookies.map(c => c.split(';')[0]).join('; ') : String(setCookies).split(';')[0];
      const allCookies = cookies ? cookies + '; ' + newCookies : newCookies;
      let data = ''; res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data, cookies: allCookies }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('POST timeout')); });
    req.write(postData); req.end();
  });
}

function parseWhoisTable(html, domain) {
  const whoisData = {};
  const whoisMatch = html.match(/<div[^>]*class="[^"]*whois-record[^"]*"[^>]*>([\s\S]*?)<\/div>/i);
  const searchHtml = whoisMatch ? whoisMatch[1] : html;
  const rowRegex = /<tr[^>]*>\s*<td[^>]*>([^<]+)<\/td>\s*<td[^>]*>([\s\S]*?)<\/td>\s*<\/tr>/gi;
  let match, count = 0;
  while ((match = rowRegex.exec(searchHtml)) !== null) {
    const key = match[1].trim().replace(/[:]+$/, '').replace(/\s+/g, ' ').trim();
    const value = match[2].replace(/<strong[^>]*>/gi, '').replace(/<\/strong>/gi, '').replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();
    if (key && value && value.length > 0) {
      if (key.toLowerCase().includes('mobile') || key.toLowerCase().includes('telephone') || key.toLowerCase().includes('phone')) {
        whoisData[key] = maskPhoneNumber(value);
      } else { whoisData[key] = value; }
      count++;
    }
  }
  const fieldMap = {
    'Domain Name': 'Domain Name', 'First registered date': 'Registration Date',
    'Last updated date': 'Updated Date', 'Primary name server': 'Primary Name Server',
    'Secondary name server': 'Secondary Name Server', 'Registrant Email': 'Registrant Email',
    'Contact person': 'Registrant Name', 'Company name': 'Registrant Organization',
    'Administrative Email': 'Admin Email', 'Mobile': 'Phone', 'Telephone': 'Phone', 'Address': 'Address',
  };
  const cleanedData = {};
  for (const [key, value] of Object.entries(whoisData)) {
    const mappedKey = fieldMap[key] || key;
    if (value && value.length > 0 && value !== '-' && value !== '—') cleanedData[mappedKey] = value;
  }
  if (cleanedData['Primary Name Server'] || cleanedData['Secondary Name Server']) {
    const ns = [];
    if (cleanedData['Primary Name Server']) ns.push(cleanedData['Primary Name Server']);
    if (cleanedData['Secondary Name Server']) ns.push(cleanedData['Secondary Name Server']);
    cleanedData['Name Server'] = ns.join(', ');
  }
  if (Object.keys(cleanedData).length >= 3) return { success: true, source: 'register.com.np', data: cleanedData, available: false };
  const lower = html.toLowerCase();
  if (lower.includes('congratulations') || lower.includes('is available') || lower.includes('can be registered')) {
    return { success: true, source: 'register.com.np', data: { 'Domain Name': domain, 'Status': 'Available' }, available: true };
  }
  return { success: false, error: 'Could not parse WHOIS data' };
}

async function scrapeRegisterNpWHOIS(domain) {
  try {
    let domainName = domain, domainExtension = '.com.np';
    const extMatch = domain.match(/^(.+?)(\.(?:com|org|net|edu|gov|mil|info|name|coop)\.np)$/);
    if (extMatch) { domainName = extMatch[1]; domainExtension = extMatch[2]; }
    else if (domain.endsWith('.np')) { domainName = domain.replace(/\.np$/, ''); domainExtension = '.np'; }
    const step1 = await makeGetRequest('https://register.com.np/whois-lookup');
    let csrfToken = '';
    const csrfMatch = step1.body.match(/name="_token"\s+value="([^"]+)"/);
    if (csrfMatch) csrfToken = csrfMatch[1];
    const postData = `_token=${encodeURIComponent(csrfToken)}&domainName=${encodeURIComponent(domainName)}&domainExtension=${encodeURIComponent(domainExtension)}`;
    const step2 = await makePostRequest('https://register.com.np/checkdomain_whois', postData, step1.cookies, 'https://register.com.np/whois-lookup');
    if ([301, 302, 303, 307].includes(step2.status) && step2.headers.location) {
      const redirectUrl = step2.headers.location.startsWith('http') ? step2.headers.location : `https://register.com.np${step2.headers.location}`;
      const step3 = await makeGetRequest(redirectUrl, step2.cookies, 'https://register.com.np/whois-lookup');
      if ([301, 302].includes(step3.status) && step3.headers.location) {
        const redirect2Url = step3.headers.location.startsWith('http') ? step3.headers.location : `https://register.com.np${step3.headers.location}`;
        const step4 = await makeGetRequest(redirect2Url, step3.cookies, redirectUrl);
        return parseWhoisTable(step4.body, domain);
      }
      return parseWhoisTable(step3.body, domain);
    }
    return parseWhoisTable(step2.body, domain);
  } catch (error) { return { success: false, error: error.message }; }
}

// ═══════════════════════════════════════════════════════
// TECH STACK DETECTION
// ═══════════════════════════════════════════════════════

async function detectTechStack(domain, headers, body) {
  const tech = [];
  const h = headers || {};
  const b = (body || '').toLowerCase();
  const headerStr = JSON.stringify(h).toLowerCase();

  // CDN
  if (h['cf-ray'] || h['server']?.includes('cloudflare') || b.includes('cloudflare')) tech.push({ category: 'CDN', name: 'Cloudflare', icon: 'fa-cloud' });
  if (h['x-served-by']?.includes('fastly')) tech.push({ category: 'CDN', name: 'Fastly', icon: 'fa-cloud' });
  if (h['x-cache']?.includes('akamai')) tech.push({ category: 'CDN', name: 'Akamai', icon: 'fa-cloud' });

  // Hosting
  if (h['x-vercel-id']) tech.push({ category: 'Hosting', name: 'Vercel', icon: 'fa-server' });
  if (h['x-netlify-id']) tech.push({ category: 'Hosting', name: 'Netlify', icon: 'fa-server' });
  if (h['x-github-request-id']) tech.push({ category: 'Hosting', name: 'GitHub Pages', icon: 'fa-server' });
  if (h['x-amz-request-id']) tech.push({ category: 'Hosting', name: 'AWS', icon: 'fa-server' });

  // Web Server
  const server = h['server'] || '';
  if (server.includes('nginx')) tech.push({ category: 'Web Server', name: 'nginx', icon: 'fa-globe' });
  else if (server.includes('apache')) tech.push({ category: 'Web Server', name: 'Apache', icon: 'fa-globe' });
  else if (server.includes('litespeed')) tech.push({ category: 'Web Server', name: 'LiteSpeed', icon: 'fa-globe' });
  else if (server.includes('cloudflare')) tech.push({ category: 'Web Server', name: 'Cloudflare', icon: 'fa-globe' });

  // CMS
  if (b.includes('wp-content') || b.includes('wordpress')) tech.push({ category: 'CMS', name: 'WordPress', icon: 'fa-file-lines' });
  if (b.includes('drupal')) tech.push({ category: 'CMS', name: 'Drupal', icon: 'fa-file-lines' });
  if (b.includes('joomla')) tech.push({ category: 'CMS', name: 'Joomla', icon: 'fa-file-lines' });
  if (b.includes('shopify')) tech.push({ category: 'E-commerce', name: 'Shopify', icon: 'fa-cart-shopping' });
  if (b.includes('woocommerce')) tech.push({ category: 'E-commerce', name: 'WooCommerce', icon: 'fa-cart-shopping' });
  if (b.includes('wixsite')) tech.push({ category: 'Builder', name: 'Wix', icon: 'fa-pen-ruler' });
  if (b.includes('squarespace')) tech.push({ category: 'Builder', name: 'Squarespace', icon: 'fa-pen-ruler' });
  if (b.includes('webflow')) tech.push({ category: 'Builder', name: 'Webflow', icon: 'fa-pen-ruler' });

  // JS Frameworks
  if (b.includes('__next') || b.includes('/_next/')) tech.push({ category: 'Framework', name: 'Next.js', icon: 'fa-code' });
  if (b.includes('__nuxt') || b.includes('/_nuxt/')) tech.push({ category: 'Framework', name: 'Nuxt.js', icon: 'fa-code' });
  if (b.includes('react') && b.includes('react-dom')) tech.push({ category: 'Library', name: 'React', icon: 'fa-code' });
  if (b.includes('vue.js') || b.includes('vue-router')) tech.push({ category: 'Framework', name: 'Vue.js', icon: 'fa-code' });
  if (b.includes('angular')) tech.push({ category: 'Framework', name: 'Angular', icon: 'fa-code' });
  if (b.includes('jquery')) tech.push({ category: 'Library', name: 'jQuery', icon: 'fa-code' });

  // CSS
  if (b.includes('bootstrap')) tech.push({ category: 'CSS', name: 'Bootstrap', icon: 'fa-paint-brush' });
  if (b.includes('tailwindcss') || b.includes('tailwind')) tech.push({ category: 'CSS', name: 'Tailwind CSS', icon: 'fa-paint-brush' });

  // Analytics
  if (b.includes('google-analytics') || b.includes('gtag(')) tech.push({ category: 'Analytics', name: 'Google Analytics', icon: 'fa-chart-line' });
  if (b.includes('gtm.js') || b.includes('googletagmanager')) tech.push({ category: 'Analytics', name: 'Google Tag Manager', icon: 'fa-chart-line' });
  if (b.includes('hotjar')) tech.push({ category: 'Analytics', name: 'Hotjar', icon: 'fa-chart-line' });
  if (b.includes('clarity.ms')) tech.push({ category: 'Analytics', name: 'Microsoft Clarity', icon: 'fa-chart-line' });

  // Security
  if (b.includes('recaptcha')) tech.push({ category: 'Security', name: 'reCAPTCHA', icon: 'fa-shield-halved' });

  const grouped = {};
  for (const t of tech) {
    if (!grouped[t.category]) grouped[t.category] = [];
    if (!grouped[t.category].find(x => x.name === t.name)) grouped[t.category].push({ name: t.name, icon: t.icon });
  }
  return Object.entries(grouped).map(([category, items]) => ({ category, items }));
}

// ═══════════════════════════════════════════════════════
// API ROUTES (Same as before — all endpoints work)
// ═══════════════════════════════════════════════════════

app.get('/api/dns', async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: 'Invalid domain' });
  const ck = `dns:${domain}`; if(cache.has(ck)) return res.json(cache.get(ck));
  const types = ['A','AAAA','MX','NS','TXT','CNAME','SOA','CAA','SRV'];
  const records = {}, errors = {};
  await Promise.allSettled(types.map(async t => {
    try {
      switch(t){case'A':records.A=await dns.resolve4(domain);break;case'AAAA':records.AAAA=await dns.resolve6(domain);break;case'MX':records.MX=await dns.resolveMx(domain);break;case'NS':records.NS=await dns.resolveNs(domain);break;case'TXT':records.TXT=(await dns.resolveTxt(domain)).map(x=>x.join(''));break;case'CNAME':records.CNAME=await dns.resolveCname(domain).catch(()=>[]);break;case'SOA':records.SOA=await dns.resolveSoa(domain).catch(()=>null);break;case'CAA':records.CAA=await dns.resolveCaa(domain).catch(()=>[]);break;case'SRV':records.SRV=await dns.resolveSrv(domain).catch(()=>[]);break;}
    } catch(e) { if(e.code!=='ENODATA'&&e.code!=='ENOTFOUND') errors[t]=e.message; }
  }));
  const ns = records.NS || [];
  const result = { domain, records, errors, cloudflare: ns.some(n=>n.toLowerCase().includes('cloudflare')), nameservers: ns };
  cache.set(ck, result); res.json(result);
});

app.get('/api/whois', async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: 'Invalid domain' });
  const ck = `whois:${domain}`; if(cache.has(ck)) return res.json(cache.get(ck));
  const isNP = domain.match(/\.(com\.np|org\.np|net\.np|edu\.np|gov\.np|mil\.np|np)$/);
  let parsed = {}, source = null, error = null, available = null;
  if (isNP) {
    const result = await scrapeRegisterNpWHOIS(domain);
    source = result.source || 'register.com.np'; parsed = result.data || {}; available = result.available;
    if (!result.success) error = result.error;
  } else {
    try {
      const rdap = await httpGet(`https://rdap.org/domain/${domain}`, { headers: { 'Accept': 'application/json' } });
      if (rdap.status === 200) { const d = JSON.parse(rdap.body); source = 'rdap'; const events = {}; for (const ev of (d.events || [])) events[ev.eventAction] = ev.eventDate?.split('T')[0]; const reg = (d.entities || []).find(e => e.roles?.includes('registrar'))?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || ''; parsed = { 'Domain Name': d.ldhName || domain, 'Status': (d.status || []).join(', '), 'Registrar': reg, 'Registration Date': events.registration || '', 'Updated Date': events.lastChanged || '', 'Expiry Date': events.expiration || '', 'Name Server': (d.nameservers || []).map(n => n.ldhName).filter(Boolean).join(', ') }; }
      else if (rdap.status === 404) { parsed = { 'Domain Name': domain, 'Status': 'Not Found' }; source = 'rdap-404'; available = true; }
    } catch (rdapErr) { error = rdapErr.message; source = 'rdap-failed'; }
  }
  const expiry = parsed['Expiry Date'] || parsed['Expiration Date'];
  const created = parsed['Registration Date'] || parsed['First registered date'];
  const updated = parsed['Updated Date'] || parsed['Last updated date'];
  const daysLeft = daysUntil(expiry);
  const cleanParsed = {};
  for (const [k, v] of Object.entries(parsed)) { if (v && v !== 'null' && v !== 'undefined' && v !== '' && v !== '-') cleanParsed[k] = v; }
  res.json({ domain, source, parsed: cleanParsed, expiry: expiry || null, created: created || null, updated: updated || null, daysLeft, isExpired: daysLeft !== null && daysLeft < 0, expiringSoon: daysLeft !== null && daysLeft >= 0 && daysLeft < 30, available, isNP: !!isNP, success: !!source && source !== 'rdap-failed', error: error || null, checkedAt: new Date().toISOString() });
});

app.get('/api/ssl', async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: 'Invalid domain' });
  const ck = `ssl:${domain}`; if(cache.has(ck)) return res.json(cache.get(ck));
  try {
    const cert = await new Promise((resolve, reject) => { const s = tls.connect({ host: domain, port: 443, servername: domain, rejectUnauthorized: false, timeout: 8000 }, () => { resolve(s.getPeerCertificate(true)); s.destroy(); }); s.on('error', reject); s.on('timeout', () => { s.destroy(); reject(new Error('TLS timeout')); }); });
    if (!cert || !cert.subject) throw new Error('No cert');
    const vt = cert.valid_to ? new Date(cert.valid_to) : null, dl = vt ? Math.floor((vt - Date.now()) / 86400000) : null;
    const result = { domain, valid: dl > 0, daysLeft: dl, expiringSoon: dl !== null && dl < 30 && dl > 0, subject: cert.subject, issuer: cert.issuer, validFrom: cert.valid_from ? new Date(cert.valid_from).toISOString().split('T')[0] : null, validTo: vt?.toISOString().split('T')[0] || null, sans: cert.subjectaltname ? cert.subjectaltname.split(', ').map(s => s.replace('DNS:', '')) : [], serialNumber: cert.serialNumber, fingerprint: cert.fingerprint, bits: cert.bits };
    cache.set(ck, result); res.json(result);
  } catch(e) {
    try { const bare = domain.replace(/^www\./, ''); const crtsh = await httpGet(`https://crt.sh/?q=${bare}&output=json`); const certs = JSON.parse(crtsh.body); const latest = certs.sort((a,b) => new Date(b.not_before) - new Date(a.not_before))[0]; const dl = latest?.not_after ? Math.floor((new Date(latest.not_after) - Date.now()) / 86400000) : null; const result = { domain, source: 'crt.sh', valid: dl > 0, daysLeft: dl, issuer: { O: latest?.issuer_name?.match(/O=([^,]+)/)?.[1] || 'Unknown' }, validFrom: latest?.not_before?.split('T')[0], validTo: latest?.not_after?.split('T')[0], totalCerts: certs.length }; cache.set(ck, result); res.json(result); }
    catch(crtErr) { res.status(500).json({ domain, error: e.message }); }
  }
});

app.get('/api/headers', async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: 'Invalid domain' });
  const ck = `hdr:${domain}`; if(cache.has(ck)) return res.json(cache.get(ck));
  try {
    const { status, headers } = await httpHead(`https://${domain}`);
    const sh = {
      'strict-transport-security': { present: !!headers['strict-transport-security'], value: headers['strict-transport-security'] || null, label: 'HSTS' },
      'content-security-policy': { present: !!headers['content-security-policy'], value: headers['content-security-policy']?.substring(0, 80) || null, label: 'CSP' },
      'x-frame-options': { present: !!headers['x-frame-options'], value: headers['x-frame-options'] || null, label: 'X-Frame-Options' },
      'x-content-type-options': { present: !!headers['x-content-type-options'], value: headers['x-content-type-options'] || null, label: 'X-Content-Type' },
      'referrer-policy': { present: !!headers['referrer-policy'], value: headers['referrer-policy'] || null, label: 'Referrer-Policy' },
      'permissions-policy': { present: !!headers['permissions-policy'], value: headers['permissions-policy']?.substring(0, 80) || null, label: 'Permissions-Policy' },
    };
    const score = Object.values(sh).filter(h => h.present).length;
    const result = { domain, httpStatus: status, securityHeaders: sh, score, maxScore: Object.keys(sh).length, server: headers['server'] || null, poweredBy: headers['x-powered-by'] || null, allHeaders: headers };
    cache.set(ck, result); res.json(result);
  } catch(e) { try { const { status, headers } = await httpHead(`http://${domain}`); res.json({ domain, httpStatus: status, httpsError: e.message, allHeaders: headers }); } catch(e2) { res.status(500).json({ domain, error: e.message }); } }
});

app.get('/api/tech', async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: 'Invalid domain' });
  const ck = `tech:${domain}`; if(cache.has(ck)) return res.json(cache.get(ck));
  try {
    const [httpsResult, httpResult] = await Promise.allSettled([
      httpGet(`https://${domain}`, { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; NPWhoisBot/5.0)' } }),
      httpGet(`http://${domain}`, { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; NPWhoisBot/5.0)' } }),
    ]);
    let headers = {}, body = '';
    if (httpsResult.status === 'fulfilled') { headers = httpsResult.value.headers; body = httpsResult.value.body; }
    else if (httpResult.status === 'fulfilled') { headers = httpResult.value.headers; body = httpResult.value.body; }
    const tech = await detectTechStack(domain, headers, body);
    const title = body.match(/<title[^>]*>([^<]+)<\/title>/i)?.[1] || null;
    const desc = body.match(/<meta[^>]*name="description"[^>]*content="([^"]+)"/i)?.[1] || null;
    const result = { domain, tech, title, description: desc, totalTechnologies: tech.reduce((s, g) => s + g.items.length, 0) };
    cache.set(ck, result, 600); res.json(result);
  } catch(e) { res.status(500).json({ domain, error: e.message }); }
});

app.get('/api/geo', async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: 'Invalid domain' });
  const ck = `geo:${domain}`; if(cache.has(ck)) return res.json(cache.get(ck));
  let ips = []; try { ips = await dns.resolve4(domain); } catch(e) { return res.json({ domain, ips: [], primaryIp: null }); }
  if(!ips.length) return res.json({ domain, ips: [], primaryIp: null });
  const ip = ips[0]; let geo = {}, gs = null;
  try { const r = await httpGet(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,asname`); const d = JSON.parse(r.body); if(d.status === 'success') { geo = d; gs = 'ip-api.com'; } } catch(_) {}
  if(!gs) try { const r = await httpGet(`https://ipapi.co/${ip}/json/`); const d = JSON.parse(r.body); if(!d.error) { geo = { country: d.country_name, countryCode: d.country_code, regionName: d.region, city: d.city, timezone: d.timezone, isp: d.org, org: d.org, as: d.asn, asname: d.org, lat: d.latitude, lon: d.longitude }; gs = 'ipapi.co'; } } catch(_) {}
  const result = { domain, ips, primaryIp: ip, geoSource: gs, country: geo.country || null, countryCode: geo.countryCode || null, city: geo.city || null, region: geo.regionName || null, isp: geo.isp || null, asn: geo.as || null, asnName: geo.asname || null, lat: geo.lat || null, lon: geo.lon || null, isNepal: geo.countryCode === 'NP' };
  cache.set(ck, result); res.json(result);
});

app.get('/api/isp', async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: 'Invalid domain' });
  const ck = `isp:${domain}`; if(cache.has(ck)) return res.json(cache.get(ck));
  try { const ips = await dns.resolve4(domain); if(!ips?.length) return res.json({ domain, isNepaliISP: false }); const ip = ips[0]; let asn = '', org = '', country = ''; try { const r = await httpGet(`http://ip-api.com/json/${ip}?fields=as,org,isp,country,countryCode`); const d = JSON.parse(r.body); asn = (d.as||'').split(' ')[0] || ''; org = d.org||d.isp||''; country = d.country||''; } catch(_) {} let hostname = ''; try { const r = await dns.reverse(ip); hostname = r[0]||''; } catch(_) {} const isp = detectNepaliISP(ip, hostname, asn); res.json({ domain, ip, asn: asn||null, country: country||null, countryCode: isp ? 'NP' : (country || null), isNepaliISP: !!isp, detectedISP: isp ? { name: isp.name, nameNepali: isp.nameNepali, slug: isp.slug, asn: isp.asn, color: isp.color, website: isp.website, logo: isp.logo, category: isp.category, detectionMethod: isp.detectionMethod, confidence: isp.confidence, matchedVia: isp.matchedVia } : null, foreignISP: !isp ? { name: org||'Unknown', country: country||'Unknown' } : null }); }
  catch(e) { res.status(500).json({ domain, error: e.message }); }
});

app.get('/api/dnssec', async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: 'Invalid domain' });
  const ck = `dnssec:${domain}`; if(cache.has(ck)) return res.json(cache.get(ck));
  const result = { domain, enabled: false, score: 0, maxScore: 100, checks: { dsRecord: { passed: false, weight: 40 }, rrsigPresent: { passed: false, weight: 30 }, dnsKeyPresent: { passed: false, weight: 20 }, nsecRecords: { passed: false, weight: 10 } }, recommendations: [] };
  try { try { await dns.resolve(domain, 'DS'); result.checks.dsRecord.passed = true; result.score += 40; } catch(e) { result.recommendations.push('Add DS record at registrar'); } try { await dns.resolve(domain, 'RRSIG'); result.checks.rrsigPresent.passed = true; result.score += 30; } catch(e) { result.recommendations.push('Sign your DNS zone'); } try { await dns.resolve(domain, 'DNSKEY'); result.checks.dnsKeyPresent.passed = true; result.score += 20; } catch(e) { result.recommendations.push('Publish DNSKEY records'); } try { const n = await dns.resolve(domain, 'NSEC').catch(()=>null) || await dns.resolve(domain, 'NSEC3').catch(()=>null); if(n?.length) { result.checks.nsecRecords.passed = true; result.score += 10; } } catch(e) {} result.enabled = result.score >= 50; result.verified = result.score >= 90; result.summary = result.verified ? { status: 'verified', label: 'Fully Verified', icon: '🛡️', color: '#059669' } : result.enabled ? { status: 'partial', label: 'Partially Enabled', icon: '⚠️', color: '#D97706' } : { status: 'disabled', label: 'Not Configured', icon: 'ℹ️', color: '#64748B' }; result.nepalContext = { adoptionRate: 12 }; }
  catch(e) { result.error = e.message; }
  cache.set(ck, result); res.json(result);
});

app.get('/api/stats', (req, res) => {
  const ck = 'stats:nepal'; if(cache.has(ck)) return res.json(cache.get(ck));
  const stats = { overview: { totalDomains: '85,000+', activeTLDs: 7, ispsDetected: 8, dnssecAdoption: '12%', cloudflareAdoption: '18%', sslAdoption: '45%', avgDomainAge: '4.2 years' }, tldDistribution: [{ name: '.com.np', percentage: 80, color: '#6366F1' }, { name: '.org.np', percentage: 10, color: '#10B981' }, { name: '.edu.np', percentage: 4, color: '#F59E0B' }, { name: '.net.np', percentage: 3, color: '#8B5CF6' }, { name: '.gov.np', percentage: 2, color: '#EF4444' }, { name: 'Others', percentage: 1, color: '#64748B' }], ispHosting: [{ name: 'Worldlink', percentage: 35, color: '#00A651' }, { name: 'NTC', percentage: 22, color: '#003893' }, { name: 'Vianet', percentage: 18, color: '#EE3124' }, { name: 'Subisu', percentage: 10, color: '#ED6B06' }, { name: 'DishHome', percentage: 8, color: '#E31937' }, { name: 'Others', percentage: 7, color: '#64748B' }], lastUpdated: new Date().toISOString() };
  cache.set(ck, stats, 3600); res.json(stats);
});

app.get('/api/reverse-ip', async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: 'Invalid domain' });
  const ck = `revip:${domain}`; if(cache.has(ck)) return res.json(cache.get(ck));
  try { const ips = await dns.resolve4(domain); if(!ips.length) return res.json({ domain, ip: null, domains: [] }); const ip = ips[0]; let domains = []; try { const r = await httpGet(`https://api.hackertarget.com/reverseiplookup/?q=${ip}`); domains = r.body.split('\n').filter(d => d.trim()).slice(0, 30); } catch(e) {} res.json({ domain, ip, totalDomains: domains.length, nepaliDomains: domains.filter(d => d.endsWith('.np')), otherDomains: domains.filter(d => !d.endsWith('.np')).slice(0, 10) }); }
  catch(e) { res.json({ domain, ip: null, domains: [] }); }
});

app.get('/api/dns-check', async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: 'Invalid domain' });
  const ck = `dnscheck:${domain}`; if(cache.has(ck)) return res.json(cache.get(ck));
  const checks = { aRecord: { name: 'A Record (IPv4)', passed: false, score: 15, detail: '' }, aaaaRecord: { name: 'AAAA Record (IPv6)', passed: false, score: 10, detail: '' }, mxRecord: { name: 'MX Record (Email)', passed: false, score: 10, detail: '' }, spfRecord: { name: 'SPF Record', passed: false, score: 15, detail: '' }, dmarcRecord: { name: 'DMARC Record', passed: false, score: 15, detail: '' }, dnssec: { name: 'DNSSEC', passed: false, score: 15, detail: '' }, nsCount: { name: 'Multiple Nameservers', passed: false, score: 10, detail: '' }, wwwRecord: { name: 'WWW Subdomain', passed: false, score: 10, detail: '' } };
  try { try { const a = await dns.resolve4(domain); checks.aRecord.passed = true; checks.aRecord.detail = `${a.length} record(s)`; } catch(e) { checks.aRecord.detail = 'Missing'; } try { const aaaa = await dns.resolve6(domain); checks.aaaaRecord.passed = true; checks.aaaaRecord.detail = `${aaaa.length} record(s)`; } catch(e) { checks.aaaaRecord.detail = 'No IPv6'; } try { const mx = await dns.resolveMx(domain); checks.mxRecord.passed = mx.length > 0; checks.mxRecord.detail = mx.length ? `${mx.length} server(s)` : 'No email'; } catch(e) { checks.mxRecord.detail = 'No MX'; } try { const txt = await dns.resolveTxt(domain); const spf = txt.flat().find(r => r.includes('v=spf1')); checks.spfRecord.passed = !!spf; checks.spfRecord.detail = spf ? 'Present' : 'Missing'; } catch(e) {} try { const dmarc = await dns.resolveTxt(`_dmarc.${domain}`).catch(() => []); checks.dmarcRecord.passed = dmarc.length > 0; checks.dmarcRecord.detail = dmarc.length ? 'Present' : 'Missing'; } catch(e) {} try { await dns.resolve(domain, 'DS'); checks.dnssec.passed = true; checks.dnssec.detail = 'Enabled'; } catch(e) { checks.dnssec.detail = 'Not enabled'; } try { const ns = await dns.resolveNs(domain); checks.nsCount.passed = ns.length >= 2; checks.nsCount.detail = `${ns.length} NS`; } catch(e) {} try { await dns.resolve4(`www.${domain}`); checks.wwwRecord.passed = true; checks.wwwRecord.detail = 'Working'; } catch(e) { checks.wwwRecord.detail = 'Not configured'; } } catch(e) {}
  const totalScore = Object.values(checks).reduce((s, c) => s + (c.passed ? c.score : 0), 0);
  const maxScore = Object.values(checks).reduce((s, c) => s + c.score, 0);
  const pct = Math.round((totalScore / maxScore) * 100);
  const grade = pct >= 80 ? 'A' : pct >= 60 ? 'B' : pct >= 40 ? 'C' : pct >= 20 ? 'D' : 'F';
  const gradeColors = { A: '#10B981', B: '#6366F1', C: '#F59E0B', D: '#EF4444', F: '#DC2626' };
  res.json({ domain, checks, totalScore, maxScore, grade, gradeColor: gradeColors[grade], percentage: pct, recommendations: Object.values(checks).filter(c => !c.passed).map(c => `${c.name}: ${c.detail}`) });
});

app.get('/api/bank-scorecard', async (req, res) => {
  const ck = 'banks:scorecard'; if(cache.has(ck)) return res.json(cache.get(ck));
  const banks = [
    { name: 'Himalayan Bank', domain: 'himalayanbank.com.np' }, { name: 'Nabil Bank', domain: 'nabilbank.com.np' },
    { name: 'NIC Asia Bank', domain: 'nicasiabank.com.np' }, { name: 'Global IME Bank', domain: 'globalimebank.com.np' },
    { name: 'Prabhu Bank', domain: 'prabhubank.com.np' }, { name: 'Kumari Bank', domain: 'kumaribank.com.np' },
    { name: 'NMB Bank', domain: 'nmbbank.com.np' }, { name: 'Sanima Bank', domain: 'sanimabank.com.np' },
    { name: 'Siddhartha Bank', domain: 'siddharthabank.com.np' }, { name: 'Everest Bank', domain: 'everestbank.com.np' },
    { name: 'Nepal Bank', domain: 'nepalbank.com.np' }, { name: 'Rastriya Banijya Bank', domain: 'rbb.com.np' },
    { name: 'Agriculture Development Bank', domain: 'adbl.com.np' }, { name: 'Laxmi Bank', domain: 'laxmibank.com.np' },
    { name: 'Citizens Bank', domain: 'ctznbank.com.np' },
  ];
  const results = [];
  for (const bank of banks) {
    let sslValid = false, dnssecEnabled = false, hasSPF = false, hasDMARC = false;
    try { const cert = await new Promise((resolve) => { const s = tls.connect({ host: bank.domain, port: 443, servername: bank.domain, rejectUnauthorized: false, timeout: 5000 }, () => { const c = s.getPeerCertificate(); resolve(c); s.destroy(); }); s.on('error', () => resolve(null)); s.on('timeout', () => { s.destroy(); resolve(null); }); }); if (cert?.valid_to) sslValid = new Date(cert.valid_to) > new Date(); } catch(e) {}
    try { await dns.resolve(bank.domain, 'DS'); dnssecEnabled = true; } catch(e) {}
    try { const txt = await dns.resolveTxt(bank.domain); hasSPF = txt.flat().some(r => r.includes('v=spf1')); } catch(e) {}
    try { const dmarc = await dns.resolveTxt(`_dmarc.${bank.domain}`).catch(() => []); hasDMARC = dmarc.length > 0; } catch(e) {}
    results.push({ name: bank.name, domain: bank.domain, ssl: sslValid ? '✅' : '❌', dnssec: dnssecEnabled ? '✅' : '❌', spf: hasSPF ? '✅' : '❌', dmarc: hasDMARC ? '✅' : '❌', score: (sslValid ? 30 : 0) + (dnssecEnabled ? 25 : 0) + (hasSPF ? 25 : 0) + (hasDMARC ? 20 : 0), grade: (sslValid ? 30 : 0) + (dnssecEnabled ? 25 : 0) + (hasSPF ? 25 : 0) + (hasDMARC ? 20 : 0) >= 80 ? 'A' : (sslValid ? 30 : 0) + (dnssecEnabled ? 25 : 0) + (hasSPF ? 25 : 0) + (hasDMARC ? 20 : 0) >= 60 ? 'B' : (sslValid ? 30 : 0) + (dnssecEnabled ? 25 : 0) + (hasSPF ? 25 : 0) + (hasDMARC ? 20 : 0) >= 40 ? 'C' : (sslValid ? 30 : 0) + (dnssecEnabled ? 25 : 0) + (hasSPF ? 25 : 0) + (hasDMARC ? 20 : 0) >= 20 ? 'D' : 'F' });
  }
  res.json({ banks: results.sort((a, b) => b.score - a.score), totalBanks: results.length, avgScore: Math.round(results.reduce((s, b) => s + b.score, 0) / results.length), lastChecked: new Date().toISOString() });
});

app.get('/api/domain-generate', async (req, res) => {
  const keyword = (req.query.keyword || '').toLowerCase().trim().replace(/[^a-z0-9]/g, '');
  if (!keyword || keyword.length < 2) return res.status(400).json({ error: 'Min 2 characters' });
  const extensions = ['.com.np', '.org.np', '.net.np', '.info.np'];
  const suggestions = [];
  const combos = [keyword, 'the' + keyword, keyword + 'nepal', 'nepal' + keyword, keyword + 'online', keyword + 'hub', 'my' + keyword, keyword + 'web'];
  for (const c of combos) for (const ext of extensions) suggestions.push({ domain: c + ext, available: null });
  
  // Check availability in parallel for first 10 suggestions
  const toCheck = suggestions.slice(0, 10);
  const checkPromises = toCheck.map(async (s) => {
    try {
      await dns.resolve4(s.domain);
      s.available = false;
      s.status = 'Taken';
    } catch(e) {
      s.available = true;
      s.status = 'Available ✅';
    }
  });
  await Promise.allSettled(checkPromises);
  
  res.json({ keyword, suggestions: toCheck.sort((a,b) => (a.available===true?-1:1) - (b.available===true?-1:1)) });
});

app.get('/api/compare', async (req, res) => {
  const d1 = validateDomain(req.query.domain1), d2 = validateDomain(req.query.domain2);
  if (!d1 || !d2) return res.status(400).json({ error: 'Need two domains' });
  async function quickInfo(domain) {
    const info = { domain, dns: {}, ssl: null, dnssec: false };
    try { info.dns.a = (await dns.resolve4(domain))[0] || null; } catch(e) { info.dns.a = null; }
    try { info.dns.ns = await dns.resolveNs(domain); } catch(e) { info.dns.ns = []; }
    try { const cert = await new Promise((resolve) => { const s = tls.connect({ host: domain, port: 443, servername: domain, rejectUnauthorized: false, timeout: 5000 }, () => { const c = s.getPeerCertificate(); resolve(c); s.destroy(); }); s.on('error', () => resolve(null)); }); if (cert?.valid_to) { const vt = new Date(cert.valid_to); info.ssl = { valid: vt > new Date(), daysLeft: Math.floor((vt - Date.now()) / 86400000) }; } } catch(e) {}
    try { await dns.resolve(domain, 'DS'); info.dnssec = true; } catch(e) {}
    return info;
  }
  const [i1, i2] = await Promise.all([quickInfo(d1), quickInfo(d2)]);
  res.json({ domain1: i1, domain2: i2, checkedAt: new Date().toISOString() });
});

app.get('/api/availability', async (req, res) => {
  const domain = validateDomain(req.query.domain);
  if (!domain) return res.status(400).json({ error: 'Invalid domain' });
  let available = null, method = null;
  try { await dns.resolve4(domain); available = false; method = 'dns'; } catch(_) { try { const r = await httpGet(`https://rdap.org/domain/${domain}`); available = r.status === 404; method = 'rdap'; } catch(_2) { method = 'unknown'; } }
  res.json({ domain, available, method, checkedAt: new Date().toISOString() });
});

// ═══════════════════════════════════════════════════════
// HEALTH + STATIC + 404 + ERROR HANDLING
// ═══════════════════════════════════════════════════════

app.get('/health', (_, res) => {
  res.json({
    status: 'ok',
    version: '5.1.0',
    environment: NODE_ENV,
    uptime: process.uptime(),
    memory: process.memoryUsage().heapUsed / 1024 / 1024,
    timestamp: new Date().toISOString(),
  });
});

app.get('/', (_, res) => res.sendFile(path.join(__dirname, 'index.html')));

// 404 handler
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Endpoint not found' });
  }
  res.status(404).sendFile(path.join(__dirname, 'index.html'));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(`[ERROR] ${err.message}`);
  res.status(500).json({ error: isProduction ? 'Internal server error' : err.message });
});

// ═══════════════════════════════════════════════════════
// GRACEFUL SHUTDOWN
// ═══════════════════════════════════════════════════════

const server = app.listen(PORT, () => {
  console.log('═══════════════════════════════════════════');
  console.log(`  ✅ NP Radar v5.1 — Port ${PORT}`);
  console.log(`  🌐 http://localhost:${PORT}`);
  console.log(`  🏭 Mode: ${NODE_ENV}`);
  console.log(`  🛡️ Helmet: Enabled`);
  console.log(`  📦 Compression: Enabled`);
  console.log(`  ⏱️ Rate Limit: ${isProduction ? 60 : 200}/min`);
  console.log('═══════════════════════════════════════════');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[SHUTDOWN] SIGTERM received. Closing gracefully...');
  server.close(() => {
    console.log('[SHUTDOWN] Server closed. Process exiting.');
    process.exit(0);
  });
  setTimeout(() => {
    console.log('[SHUTDOWN] Forced exit after timeout.');
    process.exit(1);
  }, 10000);
});

process.on('SIGINT', () => {
  console.log('[SHUTDOWN] SIGINT received. Closing gracefully...');
  server.close(() => process.exit(0));
});

module.exports = app;