// ============================================================
// SECTION 1 — API CONFIG
// Real backend IP from Person A
// ============================================================
const API_BASE = "http://10.30.50.7:8000";


// ============================================================
// SECTION 2 — DATA
// Fake data used as fallback if backend is offline.
// In real version, all this comes from Person A's API.
// ============================================================
const modules = [
  {
    name: "Reconnaissance",
    subtitle: "DNS, subdomains, tech stack",
    icon: "🔎",
    findings: 3
  },
  {
    name: "SSL/TLS Analysis",
    subtitle: "Certificates, protocols, ciphers",
    icon: "🔒",
    findings: 3
  },
  {
    name: "Security Headers",
    subtitle: "OWASP security headers",
    icon: "🛡️",
    findings: 5
  },
  {
    name: "Login Security",
    subtitle: "Auth flaws, brute force",
    icon: "🔑",
    findings: 4
  },
  {
    name: "Phishing Detection",
    subtitle: "SPF, DKIM, DMARC",
    icon: "🎣",
    findings: 3
  },
  {
    name: "OWASP ZAP",
    subtitle: "XSS, SQL injection, vulnerabilities",
    icon: "⚠️",
    findings: 5
  }
];

const complianceItems = [
  { name: "Patch Applications",           level: 1 },
  { name: "Patch Operating System",       level: 2 },
  { name: "Multi-factor Authentication",  level: 0 },
  { name: "Restrict Admin Privileges",    level: 1 },
  { name: "Application Control",          level: 2 },
  { name: "User Application Hardening",   level: 1 },
  { name: "Regular Backups",              level: 2 },
  { name: "MS Office Macro Restrictions", level: 0 }
];


// ============================================================
// SECTION 3 — PAGE SWITCHING
// Called when user clicks a nav button.
// ============================================================
function showPage(name, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  if (btn) btn.classList.add('active');
}


// ============================================================
// SECTION 4 — START SCAN
// Sends POST to Person A's backend at 10.30.50.7:8000
// Then opens WebSocket for real-time module updates.
// Falls back to fake data if backend is unreachable.
// ============================================================
async function startScan() {

  // Get what user typed
  const url = document.getElementById('urlInput').value;
  const email = document.getElementById('emailInput').value;

  // Stop if URL is empty
  if (!url) {
    alert('Please enter a website URL to scan!');
    return;
  }

  // Show scanning page immediately
  document.getElementById('scanningUrl').textContent = 'Analysing: ' + url;
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById('page-scanning').classList.add('active');
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('nav button')[1].classList.add('active');

  // Build module rows — all starting as Waiting
  const list = document.getElementById('moduleList');
  list.innerHTML = '';
  modules.forEach(m => {
    list.innerHTML += `
      <div class="module-row" id="mod-${m.name}">
        <div style="display:flex; align-items:center; gap:12px;">
          <span style="font-size:20px;">${m.icon}</span>
          <div>
            <div class="module-name">${m.name}</div>
            <div style="font-size:12px; color:var(--gray-mid); margin-top:2px;">
              ${m.subtitle}
            </div>
          </div>
        </div>
        <span id="status-${m.name}" style="color:var(--gray-mid); font-size:14px;">
          ⏸ Waiting
        </span>
      </div>`;
  });

  // ---- STEP 1: POST request to Person A's backend ----
  try {

    // Mark first module as scanning while we wait
    updateStatus(modules[0].name, 'scanning');

    // Send the URL and email to the backend
    const response = await fetch(`${API_BASE}/scan-result/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        url: url,
        email: email
      })
    });

    // If server returns an error code, throw it
    if (!response.ok) {
      throw new Error(`Server error: ${response.status}`);
    }

    // Get the JSON response back from backend
    const data = await response.json();

    // Log to console so you can see what came back
    console.log("✅ Response from backend:", data);

    // ---- STEP 2: Open WebSocket for real-time updates ----
    // scan_id comes from the POST response
    // If Person A sends it back, use it — otherwise skip WebSocket
    if (data.scan_id) {

      // Open WebSocket connection using the scan_id
      const wsUrl = `ws://10.30.50.7:8000/ws/scan/${data.scan_id}`;
      console.log("🔌 Connecting to WebSocket:", wsUrl);

      const socket = new WebSocket(wsUrl);

      // Fires every time Person A sends a module update
      socket.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        console.log("📨 WebSocket message:", msg);

        // Update the module row based on status
        if (msg.status === 'scanning') {
          updateStatus(msg.module, 'scanning');
        }
        if (msg.status === 'complete') {
          updateStatus(msg.module, 'complete');
        }
      };

      // Fires when all modules done and Person A closes connection
      socket.onclose = () => {
        console.log("✅ Scan complete — loading results");
        setTimeout(() => {
          buildResults(data);
          goToResults();
        }, 1000);
      };

      // Fires if WebSocket fails
      socket.onerror = (error) => {
        console.error("❌ WebSocket error:", error);
        // Fall back to showing results from POST response
        buildResults(data);
        goToResults();
      };

    } else {

      // No scan_id — Person A returns all results directly in POST response
      // Mark all modules complete one by one then show results
      console.log("ℹ️ No scan_id — using POST response directly");
      markAllComplete(data);

    }

  } catch (error) {

    // ---- BACKEND UNREACHABLE — use fake data ----
    console.error("❌ Backend error:", error);
    alert("Could not reach backend at 10.30.50.7:8000 — showing demo data instead.");
    runFakeScan();

  }
}


// ============================================================
// SECTION 5 — HELPER FUNCTIONS
// ============================================================

// Update a single module row status
function updateStatus(moduleName, state) {
  const el  = document.getElementById(`status-${moduleName}`);
  const row = document.getElementById(`mod-${moduleName}`);
  if (!el) return;

  if (state === 'scanning') {
    el.innerHTML = '<span style="color:var(--warning);">⏳ Scanning...</span>';
  } else if (state === 'complete') {
    el.innerHTML = '<span style="color:var(--success); font-weight:600;">✅ Complete</span>';
    if (row) row.style.borderColor = '#86efac';
  }
}

// Switch to results page and highlight nav button
function goToResults() {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById('page-results').classList.add('active');
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('nav button')[2].classList.add('active');
}

// Mark all modules complete one by one using real data
function markAllComplete(data) {
  let i = 0;
  const interval = setInterval(() => {
    if (i >= modules.length) {
      clearInterval(interval);
      setTimeout(() => {
        buildResults(data);
        goToResults();
      }, 1000);
      return;
    }
    updateStatus(modules[i].name, 'scanning');
    const current = i;
    setTimeout(() => updateStatus(modules[current].name, 'complete'), 800);
    i++;
  }, 1500);
}

// Fake scan — used when backend is offline
function runFakeScan() {
  let i = 0;
  const interval = setInterval(() => {
    if (i >= modules.length) {
      clearInterval(interval);
      setTimeout(() => {
        buildResults(null);
        goToResults();
      }, 1000);
      return;
    }
    updateStatus(modules[i].name, 'scanning');
    const current = i;
    setTimeout(() => updateStatus(modules[current].name, 'complete'), 800);
    i++;
  }, 1500);
}


// ============================================================
// SECTION 6 — BUILD RESULTS
// data = real response from backend
// null = use fake module data
// ============================================================
function buildResults(data) {

  const container = document.getElementById('moduleFindings');
  container.innerHTML = '';

  // Use real modules from backend if available, else fake
  const displayModules = (data && data.modules) ? data.modules : modules;

  // Update stat cards with real numbers if available
  if (data && data.severity) {
    document.querySelector('.stat-card:nth-child(1) .stat-number').textContent =
      data.severity.critical || 0;
    document.querySelector('.stat-card:nth-child(2) .stat-number').textContent =
      data.severity.high || 0;
    document.querySelector('.stat-card:nth-child(3) .stat-number').textContent =
      data.severity.medium || 0;
    document.querySelector('.stat-card:nth-child(4) .stat-number').textContent =
      data.severity.low || 0;
    document.querySelector('.stat-card:nth-child(5) .stat-number').textContent =
      data.total_findings || 0;
  }

  // Update risk score with real number if available
  if (data && data.risk_score) {
    const riskEl = document.querySelector('#page-results .card div[style*="72px"]');
    if (riskEl) riskEl.textContent = data.risk_score;
  }

  // Build findings bar chart
  const max = Math.max(...displayModules.map(m => m.findings));

  displayModules.forEach(m => {
    const pct   = (m.findings / max) * 100;
    const color = m.findings >= 5 ? 'var(--danger)'
                : m.findings >= 4 ? '#ea580c'
                : m.findings >= 3 ? 'var(--warning)'
                :                   'var(--success)';

    // Match icon and subtitle from local modules array
    const local    = modules.find(lm => lm.name === m.name) || {};
    const icon     = local.icon     || '🔍';
    const subtitle = local.subtitle || '';

    container.innerHTML += `
      <div style="display:flex; align-items:center; gap:12px; margin-bottom:16px;">
        <span style="font-size:18px; min-width:24px;">${icon}</span>
        <div style="min-width:180px;">
          <div style="font-size:13px; font-weight:600; color:var(--gray-dark);">
            ${m.name}
          </div>
          <div style="font-size:11px; color:var(--gray-mid);">
            ${subtitle}
          </div>
        </div>
        <div class="bar-track">
          <div class="bar-fill" style="width:${pct}%; background:${color};"></div>
        </div>
        <span style="min-width:24px; text-align:right; font-weight:600;
                     font-family:'DM Mono',monospace; color:${color};">
          ${m.findings}
        </span>
      </div>`;
  });
}


// ============================================================
// SECTION 7 — BUILD COMPLIANCE
// Essential Eight maturity bars
// ============================================================
function buildCompliance() {

  const container = document.getElementById('complianceBars');
  container.innerHTML = '';

  complianceItems.forEach(item => {
    const pct   = (item.level / 3) * 100;
    const color = item.level === 0 ? 'var(--danger)'
                : item.level === 3 ? 'var(--success)'
                :                    'var(--warning)';
    const label = item.level === 0 ? 'Not Implemented'
                : item.level === 1 ? 'Partially Implemented'
                : item.level === 2 ? 'Largely Implemented'
                :                    'Fully Implemented';

    container.innerHTML += `
      <div style="margin-bottom:20px;">
        <div style="display:flex; justify-content:space-between;
                    align-items:center; margin-bottom:8px;">
          <span style="font-size:14px; font-weight:500;">${item.name}</span>
          <span style="font-size:12px; font-weight:600; color:${color};
                       background:${color}22; padding:3px 10px; border-radius:99px;">
            L${item.level} — ${label}
          </span>
        </div>
        <div class="bar-track">
          <div class="bar-fill" style="width:${pct}%; background:${color};"></div>
        </div>
      </div>`;
  });
}


// ============================================================
// SECTION 8 — RUN ON PAGE LOAD
// Pre-build compliance and results pages immediately.
// ============================================================
buildCompliance();
buildResults(null);