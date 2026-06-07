/* ═══════════════════════════════════════════════════════
   NP RADAR — Landing Page
   ═══════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
  initMobileMenu();
  initSearch();
  initScrollReveal();
  initParticles();
  initStatAnimation();
});

function initMobileMenu() {
  const btn = document.getElementById('mobileMenuBtn');
  const menu = document.getElementById('mobileMenu');
  if (!btn || !menu) return;

  btn.addEventListener('click', () => {
    menu.classList.toggle('hidden');
    const icon = btn.querySelector('i');
    if (icon) {
      icon.className = menu.classList.contains('hidden') ? 'fas fa-bars text-lg' : 'fas fa-times text-lg';
    }
  });

  menu.querySelectorAll('.mobile-link').forEach(link => {
    link.addEventListener('click', () => {
      menu.classList.add('hidden');
      const icon = btn.querySelector('i');
      if (icon) icon.className = 'fas fa-bars text-lg';
    });
  });
}

function initSearch() {
  const input = document.getElementById('searchInput');
  const btn = document.getElementById('searchBtn');
  
  if (!input || !btn) return;
  
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') goToDashboard(input.value);
  });
  
  btn.addEventListener('click', () => goToDashboard(input.value));
}

function goToDashboard(domain) {
  const clean = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!clean) {
    showToast('Please enter a valid domain', 'warning');
    return;
  }
  window.location.href = `dashboard.html?domain=${encodeURIComponent(clean)}`;
}

function quickSearch(domain) {
  window.location.href = `dashboard.html?domain=${encodeURIComponent(domain)}`;
}

function ctaLookup() {
  const input = document.getElementById('ctaInput');
  if (input && input.value.trim()) {
    goToDashboard(input.value);
  }
}

function initScrollReveal() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
      }
    });
  }, { threshold: 0.1, rootMargin: '0px 0px -50px 0px' });

  document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
}

function initParticles() {
  const canvas = document.getElementById('particleCanvas');
  if (!canvas) return;
  
  const ctx = canvas.getContext('2d');
  let particles = [];
  let animId;

  function resize() {
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
  }

  function createParticles() {
    particles = [];
    const count = Math.floor((canvas.width * canvas.height) / 20000);
    for (let i = 0; i < count; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        r: Math.random() * 1.5 + 0.5,
        dx: (Math.random() - 0.5) * 0.3,
        dy: (Math.random() - 0.5) * 0.3,
        alpha: Math.random() * 0.4 + 0.1,
      });
    }
  }

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          ctx.beginPath();
          ctx.strokeStyle = `rgba(99,102,241,${0.06 * (1 - dist / 120)})`;
          ctx.lineWidth = 0.5;
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }
    particles.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(99,102,241,${p.alpha})`;
      ctx.fill();
      p.x += p.dx;
      p.y += p.dy;
      if (p.x < 0 || p.x > canvas.width) p.dx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.dy *= -1;
    });
    animId = requestAnimationFrame(draw);
  }

  window.addEventListener('resize', () => { resize(); createParticles(); });
  resize();
  createParticles();
  draw();
}

function initStatAnimation() {
  const statEl = document.getElementById('statDomains');
  if (!statEl) return;
  
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        animateCount(statEl, 85000);
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.5 });
  
  observer.observe(statEl);
}

function animateCount(el, target) {
  const duration = 2000;
  const start = performance.now();
  
  function update(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.floor(eased * target);
    el.textContent = current.toLocaleString() + '+';
    if (progress < 1) requestAnimationFrame(update);
  }
  
  requestAnimationFrame(update);
}

function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  const colors = {
    info: { bg: 'rgba(2,132,199,0.1)', border: '#0284C7', color: '#38BDF8' },
    warning: { bg: 'rgba(245,158,11,0.1)', border: '#F59E0B', color: '#FBBF24' },
    success: { bg: 'rgba(16,185,129,0.1)', border: '#10B981', color: '#34D399' },
  };
  const c = colors[type] || colors.info;
  toast.style.cssText = `
    position: fixed; bottom: 24px; right: 24px; z-index: 9999;
    padding: 12px 20px; background: ${c.bg}; border: 1px solid ${c.border};
    color: ${c.color}; border-radius: 8px; font-size: 0.875rem;
    font-weight: 500; max-width: 400px;
    animation: fadeIn 0.3s ease;
  `;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transition = 'opacity 0.3s'; setTimeout(() => toast.remove(), 300); }, 3000);
}