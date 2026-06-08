/* ═══════════════════════════════════════════════════════
   NP RADAR — Configuration
   ═══════════════════════════════════════════════════════ */

const CONFIG = {
  API_BASE: window.location.origin,
  APP_NAME: 'NP Radar',
  APP_VERSION: '2.0.0',
  
  SCORE_MAX: 110,
  
  EXAMPLES: ['ncell.com.np', 'ku.edu.np', 'worldlink.com.np', 'nic.np'],
  
  TOOLS: {
    'reverse-ip': {
      title: 'Reverse IP Lookup',
      desc: 'Find all domains hosted on the same IP address.',
      icon: 'fa-network-wired',
      endpoint: 'reverse-ip',
      inputType: 'domain',
      inputPlaceholder: 'Enter domain to find co-hosted sites...',
    },
    'dns-checker': {
      title: 'DNS Configuration Checker',
      desc: 'Grade your DNS setup — SPF, DMARC, DKIM, DNSSEC, IPv6.',
      icon: 'fa-clipboard-check',
      endpoint: 'dns-check',
      inputType: 'domain',
      inputPlaceholder: 'Enter domain to check DNS config...',
    },
    'bank-scorecard': {
      title: 'Nepali Bank Security Scorecard',
      desc: 'Compare SSL, DNSSEC, and email security across all Nepali banks.',
      icon: 'fa-building-columns',
      endpoint: 'bank-scorecard',
      inputType: 'none',
      autoLoad: true,
    },
    'domain-generator': {
      title: 'Domain Name Generator',
      desc: 'Generate available .np domain suggestions from keywords.',
      icon: 'fa-lightbulb',
      endpoint: 'domain-generate',
      inputType: 'keyword',
      inputPlaceholder: 'Enter a keyword (e.g., "tech")...',
    },
    'domain-compare': {
      title: 'Domain Comparison',
      desc: 'Compare two domains side by side.',
      icon: 'fa-code-compare',
      endpoint: 'compare',
      inputType: 'dual',
      inputPlaceholder1: 'First domain...',
      inputPlaceholder2: 'Second domain...',
    },
    'nepal-stats': {
      title: 'Nepal Domain Statistics',
      desc: 'Live stats: TLD distribution, ISP shares, DNSSEC adoption.',
      icon: 'fa-chart-pie',
      endpoint: 'stats',
      inputType: 'none',
      autoLoad: true,
    },
  },
};

Object.freeze(CONFIG);