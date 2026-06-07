/* ═══════════════════════════════════════════════════════
   NP RADAR — Dashboard Logic v2.0
   Fixed for updated dashboard.html
   ═══════════════════════════════════════════════════════ */

let currentDomain = '';
let scores = { dns: 0, ssl: 0, cloudflare: 0, geo: 0, isp: 0, dnssec: 0, headers: 0 };

document.addEventListener('DOMContentLoaded', () => {
  checkUrlParams();
  initTabs();
  initSearchListeners();
});

// ═══════════════════════════════════════════
//  URL PARAMETERS
// ═══════════════════════════════════════════
function checkUrlParams() {
  const params = new URLSearchParams(window.location.search);
  const domain = params.get('domain');
  const tool = params.get('tool');
  
  if (tool) {
    loadTool(tool);
  } else if (domain) {
    const input = document.getElementById('domainInput');
    if (input) input.value = domain;
    setTimeout(() => runLookup(), 100);
  }
}

// ═══════════════════════════════════════════
//  SEARCH LISTENERS
// ═══════════════════════════════════════════
function initSearchListeners() {
  const input = document.getElementById('domainInput');
  const btn = document.getElementById('lookupBtn');
  
  if (input) {
    input.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') runLookup();
    });
  }
  
  if (btn) {
    btn.addEventListener('click', runLookup);
  }
}

// ═══════════════════════════════════════════
//  TAB SYSTEM
// ═══════════════════════════════════════════
function initTabs() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', function() {
      const tabName = this.dataset.tab;
      
      // Update active state
      document.querySelectorAll('.tab-btn').forEach(b => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      this.classList.add('active');
      this.setAttribute('aria-selected', 'true');
      
      // Show tab content
      document.querySelectorAll('.tab-content').forEach(t => t.classList.add('hidden'));
      const target = document.getElementById(`tab-${tabName}`);
      if (target) {
        target.classList.remove('hidden');
        target.classList.add('page-enter');
      }
      
      // Save preference
      try { localStorage.setItem('npradar_tab', tabName); } catch(e) {}
    });
  });
  
  // Restore last tab
  try {
    const lastTab = localStorage.getItem('npradar_tab');
    if (lastTab) {
      const tab = document.querySelector(`.tab-btn[data-tab="${lastTab}"]`);
      if (tab) setTimeout(() => tab.click(), 200);
    }
  } catch(e) {}
}

// ═══════════════════════════════════════════
//  DOMAIN CLEANING
// ═══════════════════════════════════════════
function cleanDomain(input) {
  if (!input || typeof input !== 'string') return '';
  return input.trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/^www\./, '');
}

// ═══════════════════════════════════════════
//  MAIN LOOKUP
// ═══════════════════════════════════════════
async function runLookup() {
  const input = document.getElementById('domainInput');
  if (!input) return;
  
  const domain = cleanDomain(input.value);
  
  if (!domain) {
    showToast('Please enter a valid domain name', 'warning');
    return;
  }
  
  currentDomain = domain;
  scores = { dns: 0, ssl: 0, cloudflare: 0, geo: 0, isp: 0, dnssec: 0, headers: 0 };
  
  // Update URL
  window.history.replaceState(null, '', `?domain=${encodeURIComponent(domain)}`);
  
  // Show loading, hide others
  const emptyState = document.getElementById('emptyState');
  const loadingState = document.getElementById('loadingState');
  const resultsState = document.getElementById('resultsState');
  
  if (emptyState) emptyState.classList.add('hidden');
  if (loadingState) loadingState.classList.remove('hidden');
  if (resultsState) resultsState.classList.add('hidden');
  
  // Update button
  const btn = document.getElementById('lookupBtn');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" style="width:16px;height:16px;border:2px solid rgba(255,255,255,0.2);border-top-color:white;border-radius:50%;animation:spin 0.6s linear infinite;display:inline-block;margin-right:6px;"></span> Scanning…';
  }
  
  try {
    // Fetch all data in parallel
    const [dnsRes, whoisRes, sslRes, headersRes, geoRes, ispRes, dnssecRes, techRes] = await Promise.allSettled([
      apiCall('dns'),
      apiCall('whois'),
      apiCall('ssl'),
      apiCall('headers'),
      apiCall('geo'),
      apiCall('isp'),
      apiCall('dnssec'),
      apiCall('tech'),
    ]);
    
    const getVal = (r) => r.status === 'fulfilled' ? r.value : null;
    
    const data = {
      dns: getVal(dnsRes),
      whois: getVal(whoisRes),
      ssl: getVal(sslRes),
      headers: getVal(headersRes),
      geo: getVal(geoRes),
      isp: getVal(ispRes),
      dnssec: getVal(dnssecRes),
      tech: getVal(techRes),
    };
    
    // Calculate scores
    if (data.dns?.records) scores.dns = Object.keys(data.dns.records).length > 2 ? 30 : 15;
    scores.cloudflare = data.dns?.cloudflare ? 15 : 5;
    scores.ssl = data.ssl?.valid ? 25 : 5;
    scores.geo = data.geo?.isNepal ? 15 : 10;
    scores.isp = data.isp?.isNepaliISP ? 15 : 5;
    scores.dnssec = data.dnssec?.score || 0;
    if (data.headers?.score) scores.headers = Math.round((data.headers.score / (data.headers.maxScore || 6)) * 10);
    
    // Render results
    if (loadingState) loadingState.classList.add('hidden');
    if (resultsState) resultsState.classList.remove('hidden');
    
    renderDomainHeader(data);
    renderOverview(data);
    renderDNS(data);
    renderSSL(data);
    renderSecurity(data);
    renderTechStack(data);
    renderSidebar(data);
    updateScore();
    
    // Show bottom nav on mobile
    showBottomNavIfNeeded();
    
  } catch (error) {
    console.error('Lookup error:', error);
    if (loadingState) loadingState.classList.add('hidden');
    showError('Lookup Failed', error.message || 'An unexpected error occurred. Please try again.');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fas fa-search"></i> Lookup';
    }
  }
}

// ═══════════════════════════════════════════
//  API CALL
// ═══════════════════════════════════════════
async function apiCall(endpoint) {
  const baseUrl = window.CONFIG?.API_BASE || window.location.origin;
  const url = `${baseUrl}/api/${endpoint}?domain=${encodeURIComponent(currentDomain)}`;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

// ═══════════════════════════════════════════
//  ERROR HANDLING
// ═══════════════════════════════════════════
function showError(title, message) {
  const loadingState = document.getElementById('loadingState');
  const resultsState = document.getElementById('resultsState');
  
  if (loadingState) loadingState.classList.add('hidden');
  if (resultsState) resultsState.classList.add('hidden');
  
  // Create error banner in results area or show alert
  const emptyState = document.getElementById('emptyState');
  if (emptyState) {
    emptyState.classList.remove('hidden');
    emptyState.innerHTML = `
      <div class="text-5xl md:text-6xl mb-4 md:mb-6 text-slate-600">
        <i class="fas fa-exclamation-triangle"></i>
      </div>
      <h2 class="font-display text-xl md:text-2xl font-bold mb-2 md:mb-3">${title}</h2>
      <p class="text-slate-400 max-w-md mx-auto text-sm md:text-base mb-5">${message}</p>
      <button onclick="window.location.reload()" class="px-5 py-2.5 bg-primary hover:bg-primary/90 rounded-xl text-white font-semibold text-sm transition-all">
        <i class="fas fa-redo mr-2"></i> Try Again
      </button>
    `;
  }
}

// ═══════════════════════════════════════════
//  RENDER FUNCTIONS
// ═══════════════════════════════════════════

function renderDomainHeader(data) {
  const w = data.whois?.parsed || {};
  const g = data.geo || {};
  const status = data.whois?.available === false ? 'ACTIVE' : data.whois?.available === true ? 'AVAILABLE' : 'ACTIVE';
  const statusClass = status === 'AVAILABLE' ? 'status-available' : 'status-active';
  
  const header = document.getElementById('domainHeader');
  if (!header) return;
  
  header.innerHTML = `
    <div class="flex flex-wrap items-center gap-3 md:gap-4 mb-2">
      <h1 class="font-display text-2xl md:text-4xl font-bold font-mono tracking-tight break-all">${currentDomain}</h1>
      <span class="status-badge ${statusClass}">${status}</span>
      ${data.whois?.source ? `<span class="text-xs text-slate-500 font-mono hidden sm:inline">via ${data.whois.source}</span>` : ''}
    </div>
    <div class="flex flex-wrap items-center gap-3 text-xs md:text-sm text-slate-500">
      ${w['Registrar'] ? `<span>${w['Registrar'].substring(0, 40)}</span><span class="text-slate-700">·</span>` : ''}
      ${data.whois?.created ? `<span>Registered: ${data.whois.created.substring(0, 10)}</span><span class="text-slate-700">·</span>` : ''}
      ${w['Registration Date'] ? `<span>Registered: ${w['Registration Date'].substring(0, 10)}</span><span class="text-slate-700">·</span>` : ''}
      ${g.primaryIp ? `<span class="font-mono">${g.primaryIp}</span>` : ''}
    </div>
    ${data.whois?.daysLeft !== null && data.whois?.daysLeft > 0 ? `
      <div class="mt-4 max-w-md">
        <div class="flex justify-between text-xs text-slate-500 mb-1.5">
          <span>Domain Expiry</span>
          <span class="${data.whois.daysLeft < 90 ? 'text-warning' : 'text-success'} font-semibold">${data.whois.daysLeft} days remaining</span>
        </div>
        <div class="h-1.5 bg-white/5 rounded-full overflow-hidden">
          <div class="h-full rounded-full transition-all duration-1000" style="width:${Math.max(5, Math.min(95, 100 - (data.whois.daysLeft / 365) * 100))}%;background:${data.whois.daysLeft < 90 ? '#F59E0B' : '#10B981'}"></div>
        </div>
      </div>
    ` : ''}
  `;
}

function renderOverview(data) {
  const w = data.whois?.parsed || {};
  const g = data.geo || {};
  const dnsData = data.dns?.records || {};
  
  const container = document.getElementById('tab-overview');
  if (!container) return;
  
  container.innerHTML = `
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div class="bg-surface rounded-xl p-5 border border-white/5">
        <div class="text-xs text-slate-500 font-mono mb-3 uppercase tracking-wider">WHOIS Summary</div>
        <div class="space-y-2.5">
          ${dataRow('Registrar', w['Registrar'] || 'N/A')}
          ${dataRow('Registered', data.whois?.created || w['Registration Date'] || 'N/A')}
          ${dataRow('Updated', w['Updated Date'] || data.whois?.updated || 'N/A')}
          ${dataRow('Expires', data.whois?.expiry || 'N/A', data.whois?.daysLeft < 90 ? 'text-warning' : 'text-success')}
          ${w['Status'] ? dataRow('Status', w['Status']) : ''}
        </div>
      </div>

      <div class="bg-surface rounded-xl p-5 border border-white/5">
        <div class="text-xs text-slate-500 font-mono mb-3 uppercase tracking-wider">Nameservers</div>
        <div class="space-y-2">
          ${(dnsData.NS || []).length > 0 
            ? dnsData.NS.map(ns => `<div class="flex items-center gap-2"><div class="w-1.5 h-1.5 rounded-full bg-primary/50"></div><span class="text-slate-200 font-mono text-xs">${ns}</span></div>`).join('')
            : w['Name Server'] 
              ? w['Name Server'].split(',').map(ns => `<div class="flex items-center gap-2"><div class="w-1.5 h-1.5 rounded-full bg-primary/50"></div><span class="text-slate-200 font-mono text-xs">${ns.trim()}</span></div>`).join('')
              : '<span class="text-slate-600 text-xs">No nameservers found</span>'
          }
        </div>
      </div>

      <div class="bg-surface rounded-xl p-5 border border-white/5">
        <div class="text-xs text-slate-500 font-mono mb-3 uppercase tracking-wider">IP & Location</div>
        <div class="space-y-2.5">
          ${dataRow('IPv4', g.primaryIp || 'N/A')}
          ${dataRow('ASN', g.asn || 'N/A')}
          ${dataRow('ISP', g.isp || 'N/A')}
          ${dataRow('Location', g.city ? `${g.city}, ${g.country || ''}` : 'N/A')}
          ${dataRow('In Nepal', g.isNepal ? 'Yes 🇳🇵' : 'No', g.isNepal ? 'text-success' : 'text-warning')}
        </div>
      </div>

      <div class="bg-surface rounded-xl p-5 border border-white/5">
        <div class="text-xs text-slate-500 font-mono mb-3 uppercase tracking-wider">Registrant Details</div>
        <div class="space-y-2.5">
          ${dataRow('Name', w['Registrant Name'] || w['Registrant'] || 'N/A')}
          ${dataRow('Email', w['Registrant Email'] || 'N/A')}
          ${dataRow('Phone', w['Phone'] ? w['Phone'] + ' <span class="text-[10px] text-slate-500">(masked)</span>' : 'N/A')}
          ${dataRow('Address', w['Address'] || 'N/A')}
        </div>
      </div>
    </div>
  `;
}

function renderDNS(data) {
  const records = data.dns?.records || {};
  const allRecords = [];
  const typeColors = { 
    A: 'text-blue-400', AAAA: 'text-indigo-400', NS: 'text-purple-400', 
    MX: 'text-orange-400', TXT: 'text-yellow-400', CNAME: 'text-teal-400', 
    SOA: 'text-pink-400', CAA: 'text-cyan-400', SRV: 'text-rose-400' 
  };
  
  for (const [type, values] of Object.entries(records)) {
    if (!Array.isArray(values) && type !== 'SOA') continue;
    
    if (type === 'MX' && Array.isArray(values)) {
      values.sort((a, b) => a.priority - b.priority);
      values.forEach(v => allRecords.push({ type, name: currentDomain, value: `Priority ${v.priority} → ${v.exchange}` }));
    } else if (type === 'SOA' && values && typeof values === 'object') {
      allRecords.push({ type, name: currentDomain, value: `Primary: ${values.nsname}, Admin: ${values.hostmaster}, Serial: ${values.serial}` });
    } else if (Array.isArray(values)) {
      values.forEach(v => allRecords.push({ type, name: currentDomain, value: String(v) }));
    }
  }
  
  const container = document.getElementById('tab-dns');
  if (!container) return;
  
  container.innerHTML = `
    <div class="bg-surface rounded-xl border border-white/5 overflow-hidden">
      <div class="px-5 py-3 border-b border-white/5 flex items-center justify-between">
        <span class="text-sm font-medium">DNS Records</span>
        <span class="text-xs text-slate-500 font-mono">${allRecords.length} records</span>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full">
          <thead>
            <tr class="border-b border-white/5">
              <th class="text-left px-4 py-3 text-xs text-slate-500 uppercase tracking-wider w-16">Type</th>
              <th class="text-left px-4 py-3 text-xs text-slate-500 uppercase tracking-wider">Name</th>
              <th class="text-left px-4 py-3 text-xs text-slate-500 uppercase tracking-wider">Value</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-white/3">
            ${allRecords.length > 0 ? allRecords.map(r => `
              <tr class="dns-row">
                <td class="px-4 py-3"><span class="font-mono text-[10px] font-semibold px-2 py-1 rounded ${typeColors[r.type] || 'text-slate-400'}" style="background:rgba(255,255,255,0.05)">${r.type}</span></td>
                <td class="px-4 py-3 font-mono text-xs text-slate-400 max-w-[120px] truncate">${r.name}</td>
                <td class="px-4 py-3 font-mono text-xs text-slate-200 break-all">${r.value}</td>
              </tr>
            `).join('') : '<tr><td colspan="3" class="px-4 py-8 text-center text-slate-600 text-sm">No DNS records found</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function renderSSL(data) {
  const ssl = data.ssl || {};
  const gradeColor = ssl.valid ? (ssl.daysLeft > 90 ? '#10B981' : ssl.daysLeft > 30 ? '#F59E0B' : '#EF4444') : '#EF4444';
  const grade = ssl.valid ? (ssl.daysLeft > 90 ? 'A' : ssl.daysLeft > 30 ? 'B' : 'C') : 'F';
  
  const container = document.getElementById('tab-ssl');
  if (!container) return;
  
  container.innerHTML = `
    <div class="space-y-4">
      <div class="bg-surface rounded-xl p-5 md:p-6 border border-white/5 flex flex-col sm:flex-row items-start sm:items-center gap-5">
        <div class="w-20 h-20 rounded-2xl flex items-center justify-center font-display text-3xl font-bold flex-shrink-0" style="background:${gradeColor}15;border:2px solid ${gradeColor}30;color:${gradeColor}">
          ${grade}
        </div>
        <div class="flex-1 min-w-0">
          <div class="font-semibold text-lg mb-1">${ssl.valid ? 'Valid & Secure' : 'Invalid or Expired'}</div>
          <div class="text-slate-400 text-sm truncate">${ssl.source === 'crt.sh' ? 'Via crt.sh · ' : ''}Issued by ${ssl.issuer?.O || ssl.issuer || 'Unknown'}</div>
          <div class="flex flex-wrap gap-4 mt-3">
            <div class="text-xs"><div class="text-slate-500">Valid From</div><div class="text-slate-200 font-mono">${ssl.validFrom || 'N/A'}</div></div>
            <div class="text-xs"><div class="text-slate-500">Expires</div><div class="font-mono ${ssl.daysLeft < 30 ? 'text-danger' : ssl.daysLeft < 90 ? 'text-warning' : 'text-success'}">${ssl.validTo || 'N/A'}</div></div>
            <div class="text-xs"><div class="text-slate-500">Days Left</div><div class="font-mono font-semibold">${ssl.daysLeft !== null ? ssl.daysLeft : 'N/A'}</div></div>
          </div>
        </div>
      </div>
      ${ssl.sans?.length ? `
        <div class="bg-surface rounded-xl p-5 border border-white/5">
          <div class="text-xs text-slate-500 font-mono mb-3 uppercase tracking-wider">Subject Alternative Names (${ssl.sans.length})</div>
          <div class="flex flex-wrap gap-2">${ssl.sans.slice(0, 10).map(s => `<span class="px-2.5 py-1 rounded-lg text-xs font-mono" style="background:rgba(99,102,241,0.08);border:1px solid rgba(99,102,241,0.15);color:#A5B4FC">${s}</span>`).join('')}${ssl.sans.length > 10 ? `<span class="text-xs text-slate-500 self-center">+${ssl.sans.length - 10} more</span>` : ''}</div>
        </div>
      ` : ''}
    </div>
  `;
}

function renderSecurity(data) {
  const sec = data.headers?.securityHeaders || {};
  const checks = [
    { name: 'HTTPS', pass: data.ssl?.valid || false, detail: data.ssl?.valid ? 'Active' : 'Missing or invalid' },
    { name: 'DNSSEC', pass: data.dnssec?.enabled || false, detail: data.dnssec?.enabled ? 'Enabled' : 'Not configured' },
    { name: 'HSTS', pass: sec['strict-transport-security']?.present || false, detail: sec['strict-transport-security']?.present ? 'Enabled' : 'Not configured' },
    { name: 'CSP', pass: sec['content-security-policy']?.present || false, detail: sec['content-security-policy']?.present ? 'Enabled' : 'Not configured' },
    { name: 'X-Frame-Options', pass: sec['x-frame-options']?.present || false, detail: sec['x-frame-options']?.present ? 'Enabled' : 'Not configured' },
    { name: 'X-Content-Type', pass: sec['x-content-type-options']?.present || false, detail: sec['x-content-type-options']?.present ? 'Enabled' : 'Not configured' },
    { name: 'Referrer-Policy', pass: sec['referrer-policy']?.present || false, detail: sec['referrer-policy']?.present ? 'Enabled' : 'Not configured' },
  ];
  
  const passed = checks.filter(c => c.pass).length;
  
  const container = document.getElementById('tab-security');
  if (!container) return;
  
  container.innerHTML = `
    <div class="space-y-4">
      <div class="bg-surface rounded-xl p-5 border border-white/5">
        <div class="text-xs text-slate-500 font-mono mb-4 uppercase tracking-wider">Security Checks (${passed}/${checks.length} passed)</div>
        <div class="space-y-2">
          ${checks.map(c => `
            <div class="flex items-start gap-3 p-3 rounded-lg ${c.pass ? 'bg-success/5 border border-success/10' : 'bg-danger/5 border border-danger/10'}">
              <div class="text-sm mt-0.5 ${c.pass ? 'text-success' : 'text-danger'}">${c.pass ? '<i class="fas fa-check-circle"></i>' : '<i class="fas fa-times-circle"></i>'}</div>
              <div class="flex-1 min-w-0">
                <div class="text-sm font-medium ${c.pass ? 'text-success' : 'text-slate-300'}">${c.name}</div>
                <div class="text-xs text-slate-500 mt-0.5">${c.detail}</div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;
}

function renderTechStack(data) {
  const tech = data.tech?.tech || [];
  const catIcons = {
    'CDN': 'fa-cloud', 'Web Server': 'fa-server', 'CMS': 'fa-file-lines',
    'Framework': 'fa-code', 'Library': 'fa-code', 'Analytics': 'fa-chart-line',
    'Security': 'fa-shield-halved', 'CSS': 'fa-paint-brush', 'Database': 'fa-database',
    'Language': 'fa-code', 'Hosting': 'fa-server', 'Builder': 'fa-pen-ruler',
    'E-commerce': 'fa-cart-shopping',
  };
  
  const container = document.getElementById('tab-tech');
  if (!container) return;
  
  container.innerHTML = `
    <div class="space-y-4">
      <div class="bg-surface rounded-xl p-5 border border-white/5">
        <div class="text-xs text-slate-500 font-mono mb-4 uppercase tracking-wider">
          Detected Technologies (${data.tech?.totalTechnologies || tech.reduce((s, g) => s + g.items.length, 0)} found)
        </div>
        ${tech.length > 0 ? tech.map(group => `
          <div class="mb-4 last:mb-0">
            <div class="text-xs text-slate-500 font-mono mb-2 flex items-center gap-2">
              <i class="fas ${catIcons[group.category] || 'fa-circle'} text-primary text-[10px]"></i>
              ${group.category}
            </div>
            <div class="flex flex-wrap gap-2">
              ${group.items.map(item => `
                <span class="px-2.5 py-1 rounded-lg text-xs font-medium" style="background:rgba(99,102,241,0.08);border:1px solid rgba(99,102,241,0.15);color:#A5B4FC">${item.name}</span>
              `).join('')}
            </div>
          </div>
        `).join('') : '<p class="text-slate-500 text-sm">No technologies detected. The website may use custom or minimal setup.</p>'}
      </div>
    </div>
  `;
}

function renderSidebar(data) {
  const sidebar = document.getElementById('sidebar');
  if (!sidebar) return;
  
  const isp = data.isp?.detectedISP;
  const geo = data.geo || {};
  const dnssec = data.dnssec || {};
  
  sidebar.innerHTML = `
    <!-- Score Card -->
    <div class="glass rounded-2xl p-6 text-center">
      <div class="text-xs text-slate-500 font-mono uppercase tracking-wider mb-4">NP Radar Score</div>
      <div class="relative inline-flex items-center justify-center mb-4">
        <svg width="120" height="120" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="50" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="8"/>
          <circle id="scoreCircle" cx="60" cy="60" r="50" fill="none" stroke="#6366F1" stroke-width="8"
            stroke-linecap="round" class="score-ring score-circle"
            stroke-dasharray="314" stroke-dashoffset="314"/>
        </svg>
        <div class="absolute text-center">
          <div class="font-display text-3xl font-bold" id="scoreNumber">0</div>
          <div class="text-slate-500 text-xs">/100</div>
        </div>
      </div>
      <div class="text-sm font-medium" id="scoreLabel">Calculating…</div>
    </div>

    <!-- ISP Detection -->
    <div class="rounded-2xl p-5" style="background:linear-gradient(135deg,rgba(99,102,241,0.08),rgba(236,72,153,0.04));border:1px solid rgba(99,102,241,0.15)">
      <div class="text-xs text-slate-500 font-mono uppercase tracking-wider mb-3">Hosting Intelligence</div>
      <div class="flex items-center gap-3 mb-3">
        <div class="w-10 h-10 rounded-xl bg-white/5 flex items-center justify-center">
          <i class="fas ${isp ? 'fa-server text-success' : 'fa-globe text-slate-400'}"></i>
        </div>
        <div>
          <div class="font-semibold text-sm">${isp?.name || geo.isp || 'Unknown'}</div>
          <div class="text-slate-500 text-xs">${isp?.nameNepali || ''} ${isp?.category ? '· ' + isp.category : ''}</div>
        </div>
      </div>
      ${isp ? `
        <div class="space-y-1.5 text-xs mt-3 pt-3 border-t border-white/5">
          <div class="flex justify-between"><span class="text-slate-500">Detection</span><span class="text-slate-300 font-mono">${isp.detectionMethod}</span></div>
          <div class="flex justify-between"><span class="text-slate-500">Confidence</span><span class="text-success font-mono">${isp.confidence}</span></div>
          <div class="flex justify-between"><span class="text-slate-500">ASN</span><span class="text-slate-300 font-mono">${isp.asn?.join(', ') || 'N/A'}</span></div>
        </div>
      ` : ''}
    </div>

    <!-- Quick Facts -->
    <div class="bg-surface rounded-2xl p-5 border border-white/5">
      <div class="text-xs text-slate-500 font-mono uppercase tracking-wider mb-3">Quick Facts</div>
      <div class="space-y-2.5">
        <div class="flex justify-between text-xs"><span class="text-slate-500">Country</span><span class="text-slate-300 font-mono">${geo.country || 'N/A'}</span></div>
        <div class="flex justify-between text-xs"><span class="text-slate-500">City</span><span class="text-slate-300 font-mono">${geo.city || 'N/A'}</span></div>
        <div class="flex justify-between text-xs"><span class="text-slate-500">ASN</span><span class="text-slate-300 font-mono">${geo.asn || 'N/A'}</span></div>
        <div class="flex justify-between text-xs"><span class="text-slate-500">DNSSEC</span><span class="font-mono ${dnssec.enabled ? 'text-success' : 'text-slate-400'}">${dnssec.enabled ? 'Enabled' : 'Disabled'}</span></div>
        <div class="flex justify-between text-xs"><span class="text-slate-500">Cloudflare</span><span class="font-mono ${data.dns?.cloudflare ? 'text-success' : 'text-slate-400'}">${data.dns?.cloudflare ? 'Yes' : 'No'}</span></div>
      </div>
    </div>
  `;
}

function updateScore() {
  const total = scores.dns + scores.ssl + scores.cloudflare + scores.geo + scores.isp + scores.dnssec + scores.headers;
  const max = (window.CONFIG?.SCORE_MAX) || 110;
  const pct = Math.round((total / max) * 100);
  const color = pct >= 70 ? '#10B981' : pct >= 40 ? '#F59E0B' : '#EF4444';
  
  setTimeout(() => {
    const circle = document.getElementById('scoreCircle');
    const number = document.getElementById('scoreNumber');
    const label = document.getElementById('scoreLabel');
    
    if (circle) {
      circle.style.stroke = color;
      const offset = 314 - (314 * pct / 100);
      circle.style.strokeDashoffset = offset;
    }
    if (number) {
      number.textContent = pct;
      number.style.color = color;
    }
    if (label) {
      label.textContent = pct >= 70 ? 'Strong Security' : pct >= 40 ? 'Needs Improvement' : 'Critical Issues';
      label.style.color = color;
    }
  }, 300);
}

// ═══════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════

function dataRow(key, value, valueClass = '') {
  if (!value || value === 'N/A' && key === 'Updated') return '';
  return `<div class="data-row"><span class="data-key">${key}</span><span class="data-val ${valueClass}">${value}</span></div>`;
}

function showToast(message, type = 'info') {
  const colors = {
    info: { bg: 'rgba(2,132,199,0.1)', border: '#0284C7', color: '#38BDF8' },
    warning: { bg: 'rgba(245,158,11,0.1)', border: '#F59E0B', color: '#FBBF24' },
    success: { bg: 'rgba(16,185,129,0.1)', border: '#10B981', color: '#34D399' },
    error: { bg: 'rgba(239,68,68,0.1)', border: '#EF4444', color: '#F87171' },
  };
  const c = colors[type] || colors.info;
  
  const toast = document.createElement('div');
  toast.style.cssText = `
    position: fixed; bottom: 24px; right: 24px; z-index: 9999;
    padding: 12px 20px; background: ${c.bg}; border: 1px solid ${c.border};
    color: ${c.color}; border-radius: 8px; font-size: 0.875rem;
    font-weight: 500; max-width: 380px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    animation: fadeSlideIn 0.3s ease;
  `;
  toast.textContent = message;
  document.body.appendChild(toast);
  
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function showBottomNavIfNeeded() {
  if (window.innerWidth < 1024) {
    const bottomNav = document.getElementById('mobileBottomNav');
    if (bottomNav) {
      bottomNav.classList.add('visible');
      document.body.classList.add('has-bottom-nav');
    }
  }
}

// ═══════════════════════════════════════════
//  TOOL LOADING (for tool pages)
// ═══════════════════════════════════════════
function loadTool(toolName) {
  // Redirect to tool page
  window.location.href = `tools/${toolName}.html`;
}