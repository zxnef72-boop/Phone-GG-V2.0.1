// PhoneGG — Frontend logic
(function() {
  'use strict';

  // ── Mobile sidebar toggle ──
  function initSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.querySelector('.sidebar-overlay');
    const toggle = document.querySelector('.menu-toggle');
    if (!sidebar || !toggle) return;

    toggle.addEventListener('click', function() {
      sidebar.classList.toggle('open');
      if (overlay) overlay.classList.toggle('show');
    });

    if (overlay) {
      overlay.addEventListener('click', function() {
        sidebar.classList.remove('open');
        overlay.classList.remove('show');
      });
    }

    // Close on nav click (mobile)
    sidebar.querySelectorAll('.nav-item').forEach(function(item) {
      item.addEventListener('click', function() {
        if (window.innerWidth <= 768) {
          sidebar.classList.remove('open');
          if (overlay) overlay.classList.remove('show');
        }
      });
    });
  }

  // ── Auto-resize textarea ──
  function initTextarea() {
    document.querySelectorAll('textarea.form-textarea').forEach(function(t) {
      t.addEventListener('input', function() {
        this.style.height = 'auto';
        this.style.height = Math.max(100, this.scrollHeight) + 'px';
      });
    });
  }

  // ── Copy to clipboard ──
  function initCopy() {
    document.querySelectorAll('[data-copy]').forEach(function(el) {
      el.addEventListener('click', function(e) {
        e.preventDefault();
        const text = this.getAttribute('data-copy');
        navigator.clipboard.writeText(text).then(function() {
          const orig = el.textContent;
          el.textContent = '✓ Copied!';
          setTimeout(function() { el.textContent = orig; }, 1500);
        });
      });
    });
  }

  // ── Terminal-style loading overlay ──
  function buildTerminalOverlay() {
    const overlay = document.createElement('div');
    overlay.className = 'terminal-overlay';
    overlay.innerHTML =
      '<div class="terminal-window">' +
        '<div class="terminal-titlebar">' +
          '<span class="terminal-dot red"></span>' +
          '<span class="terminal-dot yellow"></span>' +
          '<span class="terminal-dot green"></span>' +
          '<span class="term-name">phonegg — scanning</span>' +
        '</div>' +
        '<div class="terminal-body" id="termBody"></div>' +
      '</div>';
    document.body.appendChild(overlay);
    return overlay;
  }

  function runTerminalOverlay(overlay, targetValue) {
    const body = overlay.querySelector('#termBody');
    body.innerHTML = '';
    overlay.classList.add('show');

    const steps = [
      targetValue
        ? '<span class="term-prompt">$</span> phonegg scan --target <span class="term-target">"' + targetValue + '"</span>'
        : '<span class="term-prompt">$</span> phonegg scan',
      '<span class="term-ok">[*]</span> Menginisialisasi modul...',
      '<span class="term-ok">[*]</span> Menghubungkan ke target...',
      '<span class="term-ok">[*]</span> Mengirim request...',
      '<span class="term-ok">[*]</span> Menganalisis respons...',
      '<span class="term-ok">[*]</span> Menyusun laporan...'
    ];
    let i = 0;
    function nextLine() {
      if (i >= steps.length) {
        const waitLine = document.createElement('div');
        waitLine.className = 'terminal-line';
        waitLine.innerHTML = '<span class="term-ok">[*]</span> Menunggu respons server<span class="terminal-cursor"></span>';
        body.appendChild(waitLine);
        return;
      }
      const line = document.createElement('div');
      line.className = 'terminal-line';
      line.innerHTML = steps[i];
      body.appendChild(line);
      body.scrollTop = body.scrollHeight;
      i++;
      setTimeout(nextLine, i === 1 ? 220 : 340 + Math.random() * 220);
    }
    nextLine();
  }

  // ── Form submit loading state ──
  function initForms() {
    const terminalOverlay = buildTerminalOverlay();
    document.querySelectorAll('form[method="POST"]').forEach(function(form) {
      form.addEventListener('submit', function() {
        const btn = form.querySelector('button[type="submit"]');
        if (btn) {
          btn.disabled = true;
          btn.innerHTML = '<span class="scanning"></span> Processing...';
          // Re-enable after 30s timeout
          setTimeout(function() {
            btn.disabled = false;
            btn.innerHTML = btn.getAttribute('data-original-text') || 'Submit';
          }, 30000);
        }
        const firstField = form.querySelector('input[type="text"], input[type="email"], input:not([type]), textarea');
        runTerminalOverlay(terminalOverlay, firstField ? firstField.value.slice(0, 60) : '');
      });
    });
  }

  // ── Active nav highlight ──
  function initActiveNav() {
    const path = window.location.pathname;
    document.querySelectorAll('.nav-item').forEach(function(item) {
      const href = item.getAttribute('href');
      if (href === path || (path !== '/' && href && path.startsWith(href))) {
        item.classList.add('active');
      }
    });
  }

  // ── JSON syntax highlight ──
  function syntaxHighlight(json) {
    if (typeof json !== 'string') {
      json = JSON.stringify(json, null, 2);
    }
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+\.?\d*([eE][+-]?\d+)?)/g, function(match) {
      let cls = 'json-number';
      if (/^"/.test(match)) {
        cls = /:$/.test(match) ? 'json-key' : 'json-string';
      } else if (/true|false/.test(match)) {
        cls = 'json-boolean';
      } else if (/null/.test(match)) {
        cls = 'json-null';
      }
      return '<span class="' + cls + '">' + match + '</span>';
    });
  }

  function initJsonHighlight() {
    document.querySelectorAll('.json-view').forEach(function(el) {
      if (el.dataset.highlighted) return;
      try {
        const raw = el.textContent.trim();
        if (raw.startsWith('{') || raw.startsWith('[')) {
          el.innerHTML = syntaxHighlight(JSON.parse(raw));
          el.dataset.highlighted = '1';
        }
      } catch(e) {}
    });
  }

  // ── Init all ──
  document.addEventListener('DOMContentLoaded', function() {
    initSidebar();
    initTextarea();
    initCopy();
    initForms();
    initActiveNav();
    initJsonHighlight();
  });
})();

// ── Service Worker registration (PWA) ──
if ('serviceWorker' in navigator) {
  window.addEventListener('load', function() {
    navigator.serviceWorker.register('/sw.js').catch(function() {});
  });
}
