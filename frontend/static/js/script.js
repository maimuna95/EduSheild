// ============================================================
// EDUSHIELD — script.js
// ============================================================
// ALL dummy data removed.
// All metrics start at 0 / empty.
// Every chart and table populates ONLY from the scanned URL.
// No cross-URL comparisons anywhere.
// ============================================================


// ── SECTION 1: API CONFIG ────────────────────────────────────
const API_BASE = "/api/v1";


// ── SECTION 2: MODULE DEFINITIONS ────────────────────────────
// Module metadata only — NO findings/severity values here.
// Those come from the real API response.
const MODULE_DEFS = [
  { name:"Reconnaissance",     subtitle:"DNS, subdomains, tech stack",         icon:"🔎" },
  { name:"SSL/TLS Analysis",   subtitle:"Certificates, protocols, ciphers",    icon:"🔒" },
  { name:"Security Headers",   subtitle:"OWASP security headers",              icon:"🛡️" },
  { name:"Login Security",     subtitle:"Auth flaws, brute force",              icon:"🔑" },
  { name:"Phishing Detection", subtitle:"SPF, DKIM, DMARC",                    icon:"🎣" },
  { name:"OWASP ZAP",          subtitle:"XSS, SQL injection, vulnerabilities", icon:"⚠️" },
];

// Compliance items — NO levels pre-set. All start at 0.
const COMPLIANCE_NAMES = [
  "Patch Applications",
  "Patch Operating System",
  "Multi-factor Authentication",
  "Restrict Admin Privileges",
  "Application Control",
  "User Application Hardening",
  "Regular Backups",
  "MS Office Macro Restrictions",
];

// Page title map
const PG_TITLES = {
  scan:            "New Scan",
  results:         "Scan Results",
  threats:         "Threat Analysis",
  recommendations: "Recommendations",
  compliance:      "AU Compliance",
  history:         "Scan History",
};

// Chart colour palette
const GBR = "rgba(80,100,180,.1)";
const TC  = "#6878A8";

// Scan history — populated only by real scans in this session
const scanHistory = [];

// Chart instance references — so we can destroy and rebuild on new data
const chartInstances = {};

// Current scan URL — used for labelling charts
let currentScanUrl = "";


// ── SECTION 3: PAGE SWITCHING ─────────────────────────────────
function goPage(id, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('on'));
  document.querySelectorAll('.nb').forEach(b => b.classList.remove('on'));
  document.getElementById('pg-' + id).classList.add('on');
  if (btn) btn.classList.add('on');
  document.getElementById('pgTitle').textContent = PG_TITLES[id] || id;

  // Resize charts on the page to prevent 0x0 hidden rendering issues in Chart.js
  Object.values(chartInstances).forEach(chart => {
    if (chart) {
      chart.resize();
      chart.update('none');
    }
  });
}


// ── SECTION 4: START SCAN ─────────────────────────────────────
async function startScan() {
  const url   = document.getElementById('urlInput').value.trim();
  const email = document.getElementById('emailInput').value.trim();

  if (!url) {
    alert('Please enter a website URL to scan!');
    return;
  }

  currentScanUrl = url;

  // Hide form, show inline progress
  document.getElementById('scanForm').style.display = 'none';
  document.getElementById('scanProgress').style.display = 'block';
  document.getElementById('scanningUrl').textContent = 'Analysing: ' + url;

  // Build module progress rows — all Waiting
  const list = document.getElementById('moduleList');
  list.innerHTML = '';
  MODULE_DEFS.forEach(m => {
    list.innerHTML += `
      <div class="prow" id="pr-${m.name}">
        <span class="prow-icon">${m.icon}</span>
        <div class="prow-info">
          <div class="prow-name">${m.name}</div>
          <div class="prow-sub">${m.subtitle}</div>
        </div>
        <div class="prow-stat" id="ps-${m.name}" style="color:var(--ink4);">⏸ Waiting</div>
      </div>`;
  });

  // ── Try real backend ────────────────────────────────────────
  try {
    updateStatus(MODULE_DEFS[0].name, 'scanning');

    const response = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, email })
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    console.log("✅ Backend response:", data);

    if (data.scan_id) {
      // Real WebSocket connection
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${wsProtocol}//${window.location.host}${API_BASE}/ws/scan/${data.scan_id}`;
      console.log("🔌 Connecting WebSocket:", wsUrl);
      const socket = new WebSocket(wsUrl);

      socket.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.status === 'scanning') updateStatus(msg.module, 'scanning');
        if (msg.status === 'complete')  updateStatus(msg.module, 'complete');
      };

      socket.onclose = () => {
        setTimeout(() => {
          populateAll(data, url);
          goPage('results', document.querySelectorAll('.nb')[1]);
          resetScanPage();
        }, 1000);
      };

      socket.onerror = () => {
        populateAll(data, url);
        goPage('results', document.querySelectorAll('.nb')[1]);
        resetScanPage();
      };

    } else {
      // No scan_id — results all in POST response
      markAllComplete(data, url);
    }

  } catch (error) {
    // Backend unreachable
    console.warn("Backend unreachable:", error);
    alert("Could not reach backend. Please ensure the backend is running.");
    resetScanPage();
  }
}


// ── SECTION 5: HELPER FUNCTIONS ──────────────────────────────

function updateStatus(name, state) {
  const el  = document.getElementById('ps-' + name);
  const row = document.getElementById('pr-' + name);
  if (!el) return;
  if (state === 'scanning') {
    el.innerHTML = `<span style="color:var(--amber);">⏳ Scanning...</span>`;
  }
  if (state === 'complete') {
    el.innerHTML = `<span style="color:var(--green);font-weight:700;">✅ Complete</span>`;
    if (row) row.classList.add('done');
  }
}

function resetScanPage() {
  document.getElementById('scanForm').style.display = 'block';
  document.getElementById('scanProgress').style.display = 'none';
  document.getElementById('urlInput').value = '';
}

function markAllComplete(data, url) {
  let i = 0;
  const iv = setInterval(() => {
    if (i >= MODULE_DEFS.length) {
      clearInterval(iv);
      setTimeout(() => {
        populateAll(data, url);
        goPage('results', document.querySelectorAll('.nb')[1]);
        resetScanPage();
      }, 1000);
      return;
    }
    updateStatus(MODULE_DEFS[i].name, 'scanning');
    const c = i;
    setTimeout(() => updateStatus(MODULE_DEFS[c].name, 'complete'), 800);
    i++;
  }, 1500);
}


// ── SECTION 6: POPULATE ALL PAGES FROM REAL DATA ─────────────
// Called once when a scan completes with real API data.
// data = real API response. url = the scanned URL.

function populateAll(data, url) {
  // Save to session history
  scanHistory.push({ url, date: new Date().toLocaleDateString('en-AU'), data });

  // Populate every page
  populateScanSummary(data, url);
  populateResults(data, url);
  populateThreats(data, url);
  populateRecommendations(data);
  populateCompliance(data);
  populateHistory();
}


// ── SECTION 7: SCAN PAGE SUMMARY ─────────────────────────────
function populateScanSummary(data, url) {
  const risk = data.risk_score || 0;
  const total = data.total_findings || 0;

  document.getElementById('summaryRisk').textContent = risk;
  document.getElementById('summaryScans').textContent = scanHistory.length;
  document.getElementById('summaryFindings').textContent = total;

  // Update trend label to show current URL only
  document.getElementById('trendLabel').textContent = url;
  document.getElementById('trendChip').textContent =
    risk >= 80 ? 'Critical' : risk >= 60 ? 'High' : risk >= 40 ? 'Medium' : 'Low';

  // Trend chart — shows severity breakdown for this URL only (as a bar)
  const crit = data.severity?.critical || 0;
  const high = data.severity?.high     || 0;
  const med  = data.severity?.medium   || 0;
  const low  = data.severity?.low      || 0;

  updateChartData('trendChart', {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      label: 'Findings',
      data: [crit, high, med, low],
      backgroundColor: ['#E03131', '#F59F00', '#E67700', '#0CA678'],
      borderRadius: 5,
      borderWidth: 0,
    }]
  });
}


// ── SECTION 8: RESULTS PAGE ───────────────────────────────────
function populateResults(data, url) {
  const crit  = data.severity?.critical || 0;
  const high  = data.severity?.high     || 0;
  const med   = data.severity?.medium   || 0;
  const low   = data.severity?.low      || 0;
  const total = data.total_findings     || 0;
  const risk  = data.risk_score         || 0;

  // Stat cards
  document.getElementById('sCrit').textContent  = crit;
  document.getElementById('sHigh').textContent  = high;
  document.getElementById('sMed').textContent   = med;
  document.getElementById('sLow').textContent   = low;
  document.getElementById('sTotal').textContent = total;

  // Risk gauge
  const gaugeOffset = 173 - (risk / 100) * 173;
  document.getElementById('gaugePath').style.strokeDashoffset = gaugeOffset;
  const riskColor = risk >= 80 ? '#E03131' : risk >= 60 ? '#F59F00' : risk >= 40 ? '#E67700' : '#0CA678';
  document.getElementById('gaugePath').style.stroke = riskColor;
  document.getElementById('riskNum').textContent = risk;
  document.getElementById('riskNum').style.color  = riskColor;
  const riskLabel = risk >= 80 ? 'Critical' : risk >= 60 ? 'High' : risk >= 40 ? 'Medium' : 'Low';
  document.getElementById('riskLbl').textContent = riskLabel;
  document.getElementById('riskLbl').style.color  = riskColor;
  document.getElementById('riskChip').textContent = riskLabel.toUpperCase();
  document.getElementById('riskChip').className = 'chip chip-' + (risk >= 80 ? 'red' : risk >= 60 ? 'amber' : risk >= 40 ? 'yellow' : 'green');

  const riskDescEl = document.getElementById('riskDesc');
  if (riskDescEl) {
    if (risk >= 80) {
      riskDescEl.textContent = 'Critical security vulnerabilities detected. Immediate action required.';
    } else if (risk >= 60) {
      riskDescEl.textContent = 'Significant security vulnerabilities detected. Prompt action required.';
    } else if (risk >= 40) {
      riskDescEl.textContent = 'Moderate security issues identified. Schedule remediation.';
    } else {
      riskDescEl.textContent = 'Strong security posture. Maintain current configuration.';
    }
  }

  // Update donut legend values
  document.getElementById('legCrit').textContent = crit;
  document.getElementById('legHigh').textContent = high;
  document.getElementById('legMed').textContent  = med;
  document.getElementById('legLow').textContent  = low;

  // Severity donut
  updateChartData('sevPie', {
    labels: ['Critical','High','Medium','Low'],
    datasets: [{
      data: [crit, high, med, low],
      backgroundColor: ['#E03131','#F59F00','#E67700','#0CA678'],
      borderWidth: 0, hoverOffset: 4
    }]
  });

  // Module findings bar
  const displayModules = (data.modules && data.modules.length) ? data.modules : MODULE_DEFS.map(m => ({...m, findings:0, crit:0, high:0, med:0, low:0}));
  buildModBars(displayModules);

  // Stacked bar — per module
  updateChartData('stackChart', {
    labels: displayModules.map(m => m.name.split(' ')[0]),
    datasets: [
      { label:'Critical', data:displayModules.map(m=>m.crit||0), backgroundColor:'#E03131', stack:'s', borderRadius:0 },
      { label:'High',     data:displayModules.map(m=>m.high||0), backgroundColor:'#F59F00', stack:'s', borderRadius:0 },
      { label:'Medium',   data:displayModules.map(m=>m.med||0),  backgroundColor:'#E67700', stack:'s', borderRadius:0 },
      { label:'Low',      data:displayModules.map(m=>m.low||0),  backgroundColor:'#0CA678', stack:'s', borderRadius:0 },
    ]
  });

  // Security posture radar — derived from module findings (inverted: fewer findings = higher score)
  const maxFindings = Math.max(...displayModules.map(m => m.findings || 0), 1);
  const radarScores = displayModules.map(m => Math.round((1 - (m.findings || 0) / maxFindings) * 100));
  updateChartData('radarChart', {
    labels: displayModules.map(m => m.name.split(' ')[0]),
    datasets: [{
      label: 'Posture score',
      data: radarScores,
      borderColor: '#3B5BDB', backgroundColor:'rgba(59,91,219,.1)',
      pointBackgroundColor:'#3B5BDB', borderWidth:2,
    }]
  });
}


// ── SECTION 9: MODULE BAR CHART ────────────────────────────────
function buildModBars(displayModules) {
  const container = document.getElementById('modBars');
  container.innerHTML = '';

  const findings = displayModules.map(m => m.findings || 0);
  const max = Math.max(...findings, 1);

  if (findings.every(f => f === 0)) {
    container.innerHTML = '<div class="empty-state">No findings returned from scan</div>';
    return;
  }

  displayModules.forEach(m => {
    const pct   = Math.round(((m.findings || 0) / max) * 100);
    const def   = MODULE_DEFS.find(d => d.name === m.name) || {};
    const color = (m.findings||0) >= 5 ? 'var(--red)'
                : (m.findings||0) >= 4 ? 'var(--amber)'
                : (m.findings||0) >= 3 ? 'var(--yellow)'
                :                        'var(--green)';
    container.innerHTML += `
      <div class="mb">
        <span class="mb-icon">${def.icon || '🔍'}</span>
        <div class="mb-info">
          <div class="mb-name">${m.name}</div>
          <div class="mb-sub">${def.subtitle || ''}</div>
        </div>
        <div class="mb-track">
          <div class="mb-fill" style="width:${pct}%;background:${color}"></div>
        </div>
        <div class="mb-num" style="color:${color}">${m.findings || 0}</div>
      </div>`;
  });
}


// ── SECTION 10: THREATS PAGE ──────────────────────────────────
function populateThreats(data, url) {
  const crit  = data.severity?.critical || 0;
  const high  = data.severity?.high     || 0;
  const med   = data.severity?.medium   || 0;
  const low   = data.severity?.low      || 0;
  const total = data.total_findings     || 0;
  const displayModules = (data.modules && data.modules.length)
    ? data.modules
    : MODULE_DEFS.map(m => ({...m, findings:0}));

  document.getElementById('findingsChip').textContent = `${total} total`;
  document.getElementById('threatLineLabel').textContent = url;

  // Threat type pie — derived from severity counts
  updateChartData('threatTypePie', {
    labels: ['Critical','High','Medium','Low'],
    datasets: [{
      data: [crit, high, med, low],
      backgroundColor: ['#E03131','#F59F00','#E67700','#0CA678'],
      borderWidth: 0, hoverOffset: 4
    }]
  });

  // Update threat type legend
  document.getElementById('threatTypeLeg').innerHTML = `
    <div class="leg-item"><div class="leg-dot" style="background:#E03131"></div><span class="leg-lbl">Critical</span><span class="leg-val">${crit}</span></div>
    <div class="leg-item"><div class="leg-dot" style="background:#F59F00"></div><span class="leg-lbl">High</span><span class="leg-val">${high}</span></div>
    <div class="leg-item"><div class="leg-dot" style="background:#E67700"></div><span class="leg-lbl">Medium</span><span class="leg-val">${med}</span></div>
    <div class="leg-item"><div class="leg-dot" style="background:#0CA678"></div><span class="leg-lbl">Low</span><span class="leg-val">${low}</span></div>`;

  // Module findings pie
  const modColors = ['#E03131','#F59F00','#7048E8','#1971C2','#0CA678','#E67700'];
  updateChartData('modPie', {
    labels: displayModules.map(m => m.name),
    datasets: [{
      data: displayModules.map(m => m.findings || 0),
      backgroundColor: modColors,
      borderWidth: 0, hoverOffset: 4
    }]
  });

  // Update module pie legend
  document.getElementById('modPieLeg').innerHTML = displayModules.map((m, i) =>
    `<div class="leg-item"><div class="leg-dot" style="background:${modColors[i]}"></div><span class="leg-lbl">${m.name}</span><span class="leg-val">${m.findings||0}</span></div>`
  ).join('');

  // Threat breakdown bar for this URL
  updateChartData('threatLine', {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      label: 'Findings',
      data: [crit, high, med, low],
      backgroundColor: ['rgba(224,49,49,.8)','rgba(245,159,0,.8)','rgba(230,119,0,.8)','rgba(12,166,120,.8)'],
      borderRadius: 4, borderWidth: 0,
    }]
  });

  // Findings table — built from data.findings if available, else from module data
  buildFindingsTable(data);
}

function buildFindingsTable(data) {
  const container = document.getElementById('findingsTable');

  // If backend returns a findings array, use it
  if (data.findings && data.findings.length > 0) {
    let rows = data.findings.map(f => `
      <tr>
        <td>${f.module || '—'}</td>
        <td>${f.title || f.name || f.finding || '—'}</td>
        <td>${severityChip(f.severity)}</td>
        <td>${f.detail || f.description || '—'}</td>
      </tr>`).join('');
    container.innerHTML = `<table class="dtbl"><thead><tr><th>Module</th><th>Finding</th><th>Severity</th><th>Description</th></tr></thead><tbody>${rows}</tbody></table>`;
  } else if (data.modules && data.modules.length > 0) {
    // Build from module-level data
    let rows = data.modules.filter(m => (m.findings||0) > 0).map(m => `
      <tr>
        <td class="rfind">${m.name}</td>
        <td>${m.findings || 0} finding${(m.findings||0) !== 1 ? 's' : ''} detected</td>
        <td>${m.crit ? `<span class="chip chip-red">${m.crit} Critical</span>` : ''}${m.high ? ` <span class="chip chip-amber">${m.high} High</span>` : ''}${m.med ? ` <span class="chip chip-yellow">${m.med} Med</span>` : ''}${m.low ? ` <span class="chip chip-green">${m.low} Low</span>` : ''}</td>
        <td style="color:var(--ink3)">See PDF report for details</td>
      </tr>`).join('');
    if (!rows) {
      container.innerHTML = '<div class="empty-state">No findings to display</div>';
    } else {
      container.innerHTML = `<table class="dtbl"><thead><tr><th>Module</th><th>Summary</th><th>Severity</th><th>Details</th></tr></thead><tbody>${rows}</tbody></table>`;
    }
  } else {
    container.innerHTML = '<div class="empty-state">No detailed findings returned by backend</div>';
  }
}

function severityChip(level) {
  const l = (level || '').toLowerCase();
  if (l === 'critical') return '<span class="chip chip-red">Critical</span>';
  if (l === 'high')     return '<span class="chip chip-amber">High</span>';
  if (l === 'medium')   return '<span class="chip chip-yellow">Medium</span>';
  if (l === 'low')      return '<span class="chip chip-green">Low</span>';
  return `<span class="chip chip-indigo">${level || '—'}</span>`;
}


// ── SECTION 11: RECOMMENDATIONS PAGE ─────────────────────────
function populateRecommendations(data) {
  const crit  = data.severity?.critical || 0;
  const high  = data.severity?.high     || 0;
  const med   = data.severity?.medium   || 0;
  const total = data.total_findings     || 0;

  document.getElementById('recImmediate').textContent = crit;
  document.getElementById('recWeek').textContent      = high;
  document.getElementById('recScheduled').textContent = med;
  document.getElementById('recTotal').textContent     = total;
  document.getElementById('recChip').textContent      = `${total} actions`;
  document.getElementById('recSubtitle').textContent  = currentScanUrl;

  // Effort pie based on real severity counts
  const quick   = Math.max(0, med + (data.severity?.low || 0));
  const moderate = Math.max(0, high);
  const complex  = Math.max(0, crit);

  updateChartData('effortPie', {
    labels: ['Quick fix','Moderate','Complex'],
    datasets: [{
      data: [quick, moderate, complex],
      backgroundColor: ['#0CA678','#F59F00','#E03131'],
      borderWidth: 0, hoverOffset: 4
    }]
  });

  document.getElementById('effortLeg').innerHTML = `
    <div class="leg-item"><div class="leg-dot" style="background:#0CA678"></div><span class="leg-lbl">Quick fix (&lt; 1 day)</span><span class="leg-val">${quick}</span></div>
    <div class="leg-item"><div class="leg-dot" style="background:#F59F00"></div><span class="leg-lbl">Moderate (1–3 days)</span><span class="leg-val">${moderate}</span></div>
    <div class="leg-item"><div class="leg-dot" style="background:#E03131"></div><span class="leg-lbl">Complex (&gt; 3 days)</span><span class="leg-val">${complex}</span></div>`;

  // Bubble chart based on real data
  updateChartData('bubbleChart', {
    datasets: [
      { label:'Critical', data: Array.from({length:crit},  (_,i) => ({x:8+i%2,y:7+i%3,r:Math.max(6,12-i)})), backgroundColor:'rgba(224,49,49,.7)' },
      { label:'High',     data: Array.from({length:high},  (_,i) => ({x:6+i%3,y:5+i%3,r:Math.max(5,10-i)})), backgroundColor:'rgba(245,159,0,.7)' },
      { label:'Medium',   data: Array.from({length:med},   (_,i) => ({x:3+i%3,y:4+i%3,r:Math.max(4, 8-i)})), backgroundColor:'rgba(59,91,219,.6)' },
    ]
  });

  // Recommendations table — from backend or built from module data
  buildRecTable(data);
}

function buildRecTable(data) {
  const container = document.getElementById('recTable');

  if (data.recommendations && data.recommendations.length > 0) {
    // Use backend-provided recommendations
    let rows = data.recommendations.map((r, i) => `
      <tr>
        <td class="rn">${String(i+1).padStart(2,'0')}</td>
        <td>${r.module || '—'}</td>
        <td style="font-weight:600;color:var(--ink)">${r.vulnerability || r.title || '—'}</td>
        <td>${severityChip(r.severity)}</td>
        <td style="line-height:1.5">${r.recommendation || r.description || '—'}</td>
        <td>${priorityBadge(r.priority || r.severity)}</td>
        <td><span class="chip chip-indigo">${r.compliance || '—'}</span></td>
      </tr>`).join('');
    container.innerHTML = `<div style="overflow-x:auto"><table class="rec-tbl"><thead><tr><th>#</th><th>Module</th><th>Vulnerability</th><th>Severity</th><th>Recommendation</th><th>Priority</th><th>Compliance</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  } else {
    // Build generic recommendations from module findings
    const displayModules = (data.modules && data.modules.length) ? data.modules : [];
    if (!displayModules.length || displayModules.every(m => !(m.findings||0))) {
      container.innerHTML = '<div class="empty-state">No recommendations — no findings detected</div>';
      return;
    }
    let n = 1;
    let rows = displayModules
      .filter(m => (m.findings||0) > 0)
      .map(m => `
        <tr>
          <td class="rn">${String(n++).padStart(2,'0')}</td>
          <td><span class="chip chip-indigo">${m.name.split(' ')[0]}</span></td>
          <td style="font-weight:600;color:var(--ink)">${m.findings} finding${m.findings!==1?'s':''} in ${m.name}</td>
          <td>${m.crit>0 ? '<span class="chip chip-red">Critical</span>' : m.high>0 ? '<span class="chip chip-amber">High</span>' : '<span class="chip chip-yellow">Medium</span>'}</td>
          <td style="line-height:1.5">Review ${m.name} findings in the detailed PDF report and address all issues above Medium severity as a priority.</td>
          <td>${m.crit>0 ? '<span class="pri-high">IMMEDIATE</span>' : m.high>0 ? '<span class="pri-med">THIS WEEK</span>' : '<span class="pri-low">SCHEDULED</span>'}</td>
          <td><span class="chip chip-purple">Essential 8</span></td>
        </tr>`).join('');
    container.innerHTML = `<div style="overflow-x:auto"><table class="rec-tbl"><thead><tr><th>#</th><th>Module</th><th>Vulnerability</th><th>Severity</th><th>Recommendation</th><th>Priority</th><th>Compliance</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }
}

function priorityBadge(level) {
  const l = (level||'').toLowerCase();
  if (l === 'critical' || l === 'immediate') return '<span class="pri-high">IMMEDIATE</span>';
  if (l === 'high' || l === 'this week')     return '<span class="pri-med">THIS WEEK</span>';
  return '<span class="pri-low">SCHEDULED</span>';
}


// ── SECTION 12: COMPLIANCE PAGE ───────────────────────────────
function populateCompliance(data) {
  // Get compliance scores from API if available, else derive from risk
  const risk   = data.risk_score || 0;
  const e8     = data.compliance?.essential_eight_score ?? Math.max(0, Math.round(100 - risk * 0.4));
  const priv   = data.compliance?.privacy_act_score     ?? Math.max(0, Math.round(100 - risk * 0.3));
  const cyber  = data.compliance?.cyber_act_score       ?? Math.max(0, Math.round(100 - risk * 0.5));

  // Score cards
  const e8El    = document.getElementById('compE8Score');
  const privEl  = document.getElementById('compPrivScore');
  const cyberEl = document.getElementById('compCyberScore');

  e8El.textContent    = `${e8}%`;
  privEl.textContent  = `${priv}%`;
  cyberEl.textContent = `${cyber}%`;
  e8El.style.color    = scoreColor(e8);
  privEl.style.color  = scoreColor(priv);
  cyberEl.style.color = scoreColor(cyber);

  const e8SubEl = document.getElementById('compE8Sub');
  if (e8SubEl) e8SubEl.textContent = "Maturity Score";

  const e8Status = document.getElementById('compE8Status');
  const privStatus = document.getElementById('compPrivStatus');
  const cyberStatus = document.getElementById('compCyberStatus');

  if (e8Status) {
    const e8Level = Math.min(3, Math.floor(e8 / 33));
    const e8Label = ['Level 0 (Low)', 'Level 1 (Medium)', 'Level 2 (High)', 'Level 3 (Full)'][e8Level];
    e8Status.textContent = e8Label;
    e8Status.className = 'chip ' + (e8Level === 3 ? 'chip-green' : e8Level === 2 ? 'chip-yellow' : e8Level === 1 ? 'chip-amber' : 'chip-red');
  }
  if (privStatus) {
    const privLabel = priv >= 75 ? 'Compliant' : priv >= 50 ? 'Partial Compliance' : 'Non-compliant';
    privStatus.textContent = privLabel;
    privStatus.className = 'chip ' + (priv >= 75 ? 'chip-green' : priv >= 50 ? 'chip-amber' : 'chip-red');
  }
  if (cyberStatus) {
    const cyberLabel = cyber >= 75 ? 'Compliant' : cyber >= 50 ? 'Partial Compliance' : 'Non-compliant';
    cyberStatus.textContent = cyberLabel;
    cyberStatus.className = 'chip ' + (cyber >= 75 ? 'chip-green' : cyber >= 50 ? 'chip-amber' : 'chip-red');
  }

  document.getElementById('legE8').textContent    = `${e8}%`;
  document.getElementById('legPriv').textContent  = `${priv}%`;
  document.getElementById('legCyber').textContent = `${cyber}%`;

  // Compliance polar
  updateChartData('compPolar', {
    labels: ['Cyber Act 2024','Privacy Act 1988','Essential Eight'],
    datasets: [{
      data: [cyber, priv, e8],
      backgroundColor: ['rgba(224,49,49,.7)','rgba(245,159,0,.7)','rgba(59,91,219,.7)'],
      borderWidth: 0
    }]
  });

  // Essential Eight bars — from API if available, else derive from risk
  const e8Items = data.compliance?.essential_eight || COMPLIANCE_NAMES.map(name => ({
    name,
    level: deriveLevel(risk),
  }));

  buildCompBars(e8Items);

  // E8 radar
  updateChartData('e8Radar', {
    labels: e8Items.map(c => (c.name||'').split(' ').slice(0,2).join(' ')),
    datasets: [
      {
        label: 'Current',
        data: e8Items.map(c => Math.round((c.level||0)/3*100)),
        borderColor:'#E03131', backgroundColor:'rgba(224,49,49,.1)',
        pointBackgroundColor:'#E03131', borderWidth:2
      },
      {
        label: 'Target L2',
        data: e8Items.map(() => 67),
        borderColor:'#3B5BDB', backgroundColor:'transparent',
        borderDash:[4,4], pointRadius:0, borderWidth:1.5
      },
    ]
  });
}

function scoreColor(score) {
  if (score >= 70) return 'var(--green)';
  if (score >= 50) return 'var(--amber)';
  return 'var(--red)';
}

function deriveLevel(risk) {
  if (risk >= 80) return 0;
  if (risk >= 60) return 1;
  if (risk >= 40) return 2;
  return 3;
}

function buildCompBars(items) {
  const container = document.getElementById('compBars');
  container.innerHTML = '';
  if (!items || !items.length) {
    container.innerHTML = '<div class="empty-state">No compliance data available</div>';
    return;
  }
  items.forEach(item => {
    const level = item.level || 0;
    const pct   = Math.round((level / 3) * 100);
    const color = level === 0 ? 'var(--red)' : level === 3 ? 'var(--green)' : 'var(--amber)';
    const bg    = level === 0 ? 'var(--red-lt)' : level === 3 ? 'var(--green-lt)' : 'var(--amber-lt)';
    const tx    = level === 0 ? 'var(--red-d)'  : level === 3 ? 'var(--green-d)'  : 'var(--yellow)';
    const label = ['Not Implemented','Partially Implemented','Largely Implemented','Fully Implemented'][level];
    container.innerHTML += `
      <div class="cb">
        <div class="cb-hdr">
          <span class="cb-name">${item.name}</span>
          <span class="lchip" style="background:${bg};color:${tx}">L${level} · ${label}</span>
        </div>
        <div class="mb-track" style="height:8px">
          <div class="mb-fill" style="width:${pct}%;background:${color};height:8px"></div>
        </div>
      </div>`;
  });
}


// ── SECTION 13: HISTORY PAGE ──────────────────────────────────
function populateHistory() {
  if (!scanHistory.length) return;

  // Risk score line chart — scans in this session only
  const labels = scanHistory.map(s => s.url.replace('https://','').replace('http://',''));
  const risks  = scanHistory.map(s => s.data.risk_score || 0);
  const finds  = scanHistory.map(s => s.data.total_findings || 0);

  updateChartData('histLine', {
    labels,
    datasets: [{
      label: 'Risk score',
      data: risks,
      borderColor: '#E03131', backgroundColor:'rgba(224,49,49,.07)',
      fill:true, tension:.4, pointBackgroundColor:'#E03131', pointRadius:5
    }]
  });

  // Findings bar
  updateChartData('histBar', {
    labels,
    datasets: [{
      label: 'Findings',
      data: finds,
      backgroundColor: risks.map(r => r>=80?'#E03131':r>=60?'#F59F00':r>=40?'#E67700':'#0CA678'),
      borderRadius: 4
    }]
  });

  // History table
  const rows = scanHistory.map(s => {
    const r = s.data.risk_score || 0;
    const f = s.data.total_findings || 0;
    const label = r>=80?'Critical':r>=60?'High':r>=40?'Medium':'Low';
    const chipClass = r>=80?'chip-red':r>=60?'chip-amber':r>=40?'chip-yellow':'chip-green';
    return `<tr>
      <td class="rfind">${s.url}</td>
      <td>${s.date}</td>
      <td><span style="font-family:var(--font-mono);font-weight:600">${r}</span> <span class="chip ${chipClass}">${label}</span></td>
      <td style="font-family:var(--font-mono);font-weight:600">${f}</td>
      <td style="font-family:var(--font-mono)">6/6</td>
      <td><span class="chip chip-green">Complete</span></td>
    </tr>`;
  }).join('');

  document.getElementById('histTable').innerHTML = `
    <table class="dtbl">
      <thead><tr><th>URL Scanned</th><th>Date</th><th>Risk Score</th><th>Findings</th><th>Modules</th><th>Status</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}


// ── SECTION 14: CHART HELPERS ─────────────────────────────────

// Destroy a chart instance before rebuilding it (No longer used directly during scan updates, but kept for interface cleanup)
function destroyChart(id) {
  if (chartInstances[id]) {
    chartInstances[id].destroy();
    delete chartInstances[id];
  }
}

// Update an existing chart's data instead of destroying it (prevents "Canvas is already in use" errors)
function updateChartData(id, data, options) {
  try {
    const chart = chartInstances[id];
    if (chart) {
      chart.data = data;
      if (options) {
        chart.options = {
          ...chart.options,
          ...options
        };
      }
      chart.update();
    } else {
      console.warn(`[updateChartData] Chart instance not found for ID: ${id}`);
    }
  } catch (error) {
    console.error(`[updateChartData] Failed to update chart ${id}:`, error);
  }
}

// Create a Chart.js chart
function mkChart(id, type, data, options) {
  try {
    const el = document.getElementById(id);
    if (!el) return null;
    return new Chart(el, {
      type,
      data,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        ...options
      }
    });
  } catch (error) {
    console.error(`[mkChart] Failed to create chart ${id}:`, error);
    return null;
  }
}


// ── SECTION 15: INIT ──────────────────────────────────────────
// Nothing pre-populated on load — all pages start empty.
// Charts are built only when a real scan completes.
// Empty state messages shown until first scan.

// Initialise empty chart canvases so they render cleanly
(function initEmptyCharts() {
  // Trend chart — empty on load
  chartInstances['trendChart'] = mkChart('trendChart', 'bar', {
    labels: ['Critical','High','Medium','Low'],
    datasets: [{ data:[0,0,0,0], backgroundColor:['#E03131','#F59F00','#E67700','#0CA678'], borderRadius:5, borderWidth:0 }]
  }, {
    scales: {
      x: { grid:{color:GBR}, ticks:{color:TC, font:{size:11, family:'Inter'}} },
      y: { grid:{color:GBR}, ticks:{color:TC, font:{size:10, family:'Inter'}, stepSize:1}, beginAtZero:true }
    }
  });

  // Severity pie — empty
  chartInstances['sevPie'] = mkChart('sevPie', 'doughnut', {
    labels: ['Critical','High','Medium','Low'],
    datasets: [{ data:[1,1,1,1], backgroundColor:['#F1F3F9','#E8EBF5','#DDE3F4','#D4DAEE'], borderWidth:0 }]
  }, { cutout:'62%' });

  // Stacked bar — empty
  chartInstances['stackChart'] = mkChart('stackChart', 'bar', {
    labels: MODULE_DEFS.map(m => m.name.split(' ')[0]),
    datasets: [
      { label:'Critical', data:[0,0,0,0,0,0], backgroundColor:'#E03131', stack:'s' },
      { label:'High',     data:[0,0,0,0,0,0], backgroundColor:'#F59F00', stack:'s' },
      { label:'Medium',   data:[0,0,0,0,0,0], backgroundColor:'#E67700', stack:'s' },
      { label:'Low',      data:[0,0,0,0,0,0], backgroundColor:'#0CA678', stack:'s' },
    ]
  }, {
    scales: {
      x: { stacked:true, grid:{color:GBR}, ticks:{color:TC, font:{size:9, family:'Inter'}, autoSkip:false} },
      y: { stacked:true, grid:{color:GBR}, ticks:{color:TC, font:{size:9, family:'Inter'}, stepSize:1} }
    }
  });

  // Radar — empty
  chartInstances['radarChart'] = mkChart('radarChart', 'radar', {
    labels: MODULE_DEFS.map(m => m.name.split(' ')[0]),
    datasets: [{ label:'Score', data:[0,0,0,0,0,0], borderColor:'#3B5BDB', backgroundColor:'rgba(59,91,219,.05)', borderWidth:1.5, pointRadius:3 }]
  }, {
    scales: { r: { min:0, max:100, ticks:{display:false}, grid:{color:GBR}, pointLabels:{color:TC, font:{size:10, family:'Inter'}} } }
  });

  // Threat type — empty
  chartInstances['threatTypePie'] = mkChart('threatTypePie', 'doughnut', {
    labels: ['Critical','High','Medium','Low'],
    datasets: [{ data:[1,1,1,1], backgroundColor:['#F1F3F9','#E8EBF5','#DDE3F4','#D4DAEE'], borderWidth:0 }]
  }, { cutout:'55%' });

  // Module pie — empty
  chartInstances['modPie'] = mkChart('modPie', 'doughnut', {
    labels: MODULE_DEFS.map(m => m.name),
    datasets: [{ data:[1,1,1,1,1,1], backgroundColor:['#F1F3F9','#E8EBF5','#DDE3F4','#D4DAEE','#CBD3E8','#C4CEEA'], borderWidth:0 }]
  }, { cutout:'55%' });

  // Threat line — empty
  chartInstances['threatLine'] = mkChart('threatLine', 'bar', {
    labels: ['Critical','High','Medium','Low'],
    datasets: [{ data:[0,0,0,0], backgroundColor:['rgba(224,49,49,.3)','rgba(245,159,0,.3)','rgba(230,119,0,.3)','rgba(12,166,120,.3)'], borderRadius:4 }]
  }, {
    scales: {
      x: { grid:{color:GBR}, ticks:{color:TC, font:{size:11, family:'Inter'}} },
      y: { grid:{color:GBR}, ticks:{color:TC, font:{size:10, family:'Inter'}, stepSize:1}, beginAtZero:true }
    }
  });

  // Bubble — empty
  chartInstances['bubbleChart'] = mkChart('bubbleChart', 'bubble', {
    datasets: [{ label:'No data', data:[], backgroundColor:'transparent' }]
  }, {
    scales: {
      x: { min:0, max:11, title:{display:true, text:'Priority', color:TC, font:{size:10}}, grid:{color:GBR}, ticks:{color:TC, font:{size:10}} },
      y: { min:0, max:11, title:{display:true, text:'Effort',   color:TC, font:{size:10}}, grid:{color:GBR}, ticks:{color:TC, font:{size:10}} }
    }
  });

  // Effort pie — empty
  chartInstances['effortPie'] = mkChart('effortPie', 'doughnut', {
    labels: ['Quick','Moderate','Complex'],
    datasets: [{ data:[1,1,1], backgroundColor:['#EBF9F4','#FFFAEB','#FFF5F5'], borderWidth:0 }]
  }, { cutout:'55%' });

  // Compliance polar — empty
  chartInstances['compPolar'] = mkChart('compPolar', 'polarArea', {
    labels: ['Cyber Act','Privacy Act','Essential Eight'],
    datasets: [{ data:[33,33,33], backgroundColor:['rgba(224,49,49,.15)','rgba(245,159,0,.15)','rgba(59,91,219,.15)'], borderWidth:0 }]
  }, { scales: { r: { ticks:{display:false, backdropColor:'transparent'}, grid:{color:GBR} } } });

  // E8 radar — empty
  chartInstances['e8Radar'] = mkChart('e8Radar', 'radar', {
    labels: COMPLIANCE_NAMES.map(n => n.split(' ').slice(0,2).join(' ')),
    datasets: [
      { label:'Current', data:COMPLIANCE_NAMES.map(()=>0), borderColor:'#E03131', backgroundColor:'rgba(224,49,49,.05)', borderWidth:1.5, pointRadius:2 },
      { label:'Target',  data:COMPLIANCE_NAMES.map(()=>67), borderColor:'#3B5BDB', backgroundColor:'transparent', borderDash:[4,4], pointRadius:0, borderWidth:1.5 },
    ]
  }, { scales: { r: { min:0, max:100, ticks:{display:false}, grid:{color:GBR}, pointLabels:{color:TC, font:{size:9, family:'Inter'}} } } });

  // History charts — empty
  chartInstances['histLine'] = mkChart('histLine', 'line', {
    labels: [],
    datasets: [{ label:'Risk score', data:[], borderColor:'#E03131', backgroundColor:'rgba(224,49,49,.07)', fill:true, tension:.4, pointRadius:5 }]
  }, {
    scales: {
      x: { grid:{color:GBR}, ticks:{color:TC, font:{size:10, family:'Inter'}} },
      y: { min:0, max:110, grid:{color:GBR}, ticks:{color:TC, font:{size:10, family:'Inter'}, stepSize:20} }
    }
  });

  chartInstances['histBar'] = mkChart('histBar', 'bar', {
    labels: [],
    datasets: [{ label:'Findings', data:[], backgroundColor:[], borderRadius:4 }]
  }, {
    scales: {
      x: { grid:{color:GBR}, ticks:{color:TC, font:{size:10, family:'Inter'}, autoSkip:false} },
      y: { grid:{color:GBR}, ticks:{color:TC, font:{size:10, family:'Inter'}, stepSize:5}, beginAtZero:true }
    }
  });
})();