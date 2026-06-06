const IS_DEV = window.location.protocol === 'file:' || ['5500', '5501', '3000'].includes(window.location.port);
const API_ENDPOINT        = IS_DEV ? 'http://localhost:8000/api/analyze'    : '/api/analyze';
const STATUS_ENDPOINT     = IS_DEV ? 'http://localhost:8000/api/status'     : '/api/status';
const COMPLIANCE_ENDPOINT = IS_DEV ? 'http://localhost:8000/api/compliance' : '/api/compliance';
let scanHistory = [];
let lastResult  = null;
let stepTimer   = null;

const CHECK_LABELS = {
  'A01_Broken_Access_Control':    'A01',
  'A02_Cryptographic_Failures':   'A02',
  'A03_Injection':                'A03',
  'A05_Security_Misconfiguration':'A05',
  'A07_Auth_Failures':            'A07',
};

// Time-based phases that match the actual backend flow
// at = ms after scan starts, text = what's actually happening
const SCAN_PHASES = [
  { at: 0,     text: 'Resolving domain...' },
  { at: 2000,  text: 'Scanning open ports...' },
  { at: 10000, text: 'Detecting service versions...' },
  { at: 22000, text: 'Checking CVE databases...' },
  { at: 34000, text: 'Running AI threat analysis...' },
  { at: 50000, text: 'Finalizing results...' },
];

function el(id) { return document.getElementById(id); }

function isValidUrl(str) {
  try { const u = new URL(str); return u.protocol === 'http:' || u.protocol === 'https:'; }
  catch { return false; }
}

// ── STATUS INDICATORS ─────────────────────────────────────────────────
function setDot(key, state) {
  const dot = el(`dot-${key}`);
  if (!dot) return;
  dot.classList.remove('checking', 'online', 'offline');
  dot.classList.add(state);
}

async function checkStatus() {
  try {
    const r = await fetch(STATUS_ENDPOINT);
    if (!r.ok) throw new Error();
    const s = await r.json();
    setDot('api',    s.api       ? 'online' : 'offline');
    setDot('threat', s.threat_db ? 'online' : 'offline');
    setDot('ai',     s.ai_engine ? 'online' : 'offline');
  } catch {
    setDot('api', 'offline'); setDot('threat', 'offline'); setDot('ai', 'offline');
  }
}
checkStatus();
setInterval(checkStatus, 60000);

// ── OWASP COMPLIANCE ──────────────────────────────────────────────────
async function fetchCompliance(url) {
  const section  = el('compliance-section');
  const scoreEl  = el('compliance-score');
  const checksEl = el('compliance-checks');
  if (!section) return;

  section.style.display = 'flex';
  if (scoreEl) { scoreEl.textContent = '—'; scoreEl.style.color = '#333'; }
  if (checksEl) checksEl.innerHTML = Object.values(CHECK_LABELS).map(
    l => `<span class="compliance-check loading">${l}</span>`
  ).join('');

  try {
    const r = await fetch(`${COMPLIANCE_ENDPOINT}?url=${encodeURIComponent(url)}`);
    if (!r.ok) throw new Error();
    const data = await r.json();

    if (scoreEl) {
      scoreEl.textContent = data.score;
      scoreEl.style.color = data.score >= 80 ? '#22c55e' : data.score >= 60 ? '#eab308' : '#ef4444';
    }
    if (checksEl && data.results) {
      checksEl.innerHTML = Object.entries(data.results).map(([key, val]) =>
        `<span class="compliance-check ${val.pass ? 'pass' : 'fail'}" title="${val.details}">${CHECK_LABELS[key] || key} ${val.pass ? '✓' : '✗'}</span>`
      ).join('');
    }
  } catch {
    if (scoreEl) scoreEl.textContent = '—';
    if (checksEl) checksEl.innerHTML = '<span style="font-size:0.75rem;color:#2a2a2a">Unavailable</span>';
  }
}

// ── SCAN STEP ANIMATION — time-based, reflects actual backend phases ──
function startScanSteps() {
  const stepEl = el('scan-step');
  if (!stepEl) return;
  if (stepTimer) clearTimeout(stepTimer);

  const start = performance.now();

  function tick() {
    const elapsed = performance.now() - start;
    // Find the most recent phase that has started
    let current = SCAN_PHASES[0];
    for (const phase of SCAN_PHASES) {
      if (elapsed >= phase.at) current = phase;
      else break;
    }
    stepEl.textContent = current.text;
    // Schedule next check at the next phase boundary
    const next = SCAN_PHASES.find(p => p.at > elapsed);
    if (next) stepTimer = setTimeout(tick, next.at - elapsed);
  }

  tick();
}

function stopScanSteps(finalText) {
  if (stepTimer) { clearTimeout(stepTimer); stepTimer = null; }
  const stepEl = el('scan-step');
  if (stepEl && finalText) stepEl.textContent = finalText;
}

// ── FRIENDLY ERROR MESSAGES ───────────────────────────────────────────
function friendlyError(status, msg) {
  if (status === 504 || msg.includes('504')) return 'This site is blocking port scans — try a well-known domain like a news site or company.';
  if (status === 429 || msg.includes('429')) return 'Rate limit reached — wait a minute and try again.';
  if (status === 400 || msg.includes('400')) return 'Invalid URL — make sure it starts with http:// or https://';
  if (status === 500 || msg.includes('500')) return 'Server error during scan — try again in a moment.';
  if (msg.includes('Failed to fetch') || msg.includes('NetworkError')) return 'Cannot reach Sentinel AI — check your connection.';
  return `Scan failed: ${msg}`;
}

// ── ANALYZE ───────────────────────────────────────────────────────────
async function analyzeLink() {
  const input = el('url-input');
  const errEl = el('url-error');
  const btn   = el('analyze-btn');
  const url   = input ? input.value.trim() : '';

  if (errEl) errEl.style.display = 'none';
  el('scan-state')?.classList.remove('visible');
  el('result-card')?.classList.remove('visible');
  const compSection = el('compliance-section');
  if (compSection) compSection.style.display = 'none';

  if (!isValidUrl(url)) {
    if (errEl) { errEl.textContent = 'Please enter a valid URL starting with http:// or https://'; errEl.style.display = 'block'; }
    return;
  }

  if (btn) btn.disabled = true;
  el('scan-state')?.classList.add('visible');

  // Start fetch immediately, kick off time-based step animation in parallel
  const fetchPromise = fetch(API_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  });
  startScanSteps();

  try {
    const response = await fetchPromise;
    if (!response.ok) { throw new Error(friendlyError(response.status, `${response.status}`)); }
    stopScanSteps();
    showResult(url, await response.json());
  } catch (err) {
    stopScanSteps();
    showError(err.message);
  } finally {
    if (btn) btn.disabled = false;
    el('scan-state')?.classList.remove('visible');
  }
}

// ── SHOW RESULT ───────────────────────────────────────────────────────
function showResult(url, data) {
  if (!data) { showError('Empty response from server'); return; }
  const safe      = data.safe       ?? true;
  const riskLevel = data.riskLevel  ?? 'UNKNOWN';
  const confidence= data.confidence ?? 0;
  const summary   = data.summary    ?? 'No summary available.';

  lastResult = { url, ...data, timestamp: new Date() };
  const safeClass = safe ? 'safe' : riskLevel === 'MEDIUM' ? 'medium' : 'unsafe';

  const iconEl = el('result-icon');
  if (iconEl) { iconEl.className = `status-icon ${safeClass}`; iconEl.textContent = safe ? '✓' : '✕'; }
  const labelEl = el('result-label');
  if (labelEl) { labelEl.className = `status-label ${safeClass}`; labelEl.textContent = safe ? 'Safe' : 'Threat Detected'; }
  const urlDisplay = el('result-url-display');
  if (urlDisplay) urlDisplay.textContent = url.length > 55 ? url.slice(0, 55) + '…' : url;
  const pill = el('risk-pill');
  if (pill) { pill.className = `risk-pill ${riskLevel}`; pill.textContent = riskLevel; }
  const confFill = el('confidence-fill');
  if (confFill) confFill.style.width = `${confidence}%`;
  const confNum = el('confidence-num');
  if (confNum) confNum.textContent = `${confidence}%`;
  const riskEl = el('result-risk');
  if (riskEl) riskEl.textContent = riskLevel;
  const safeEl = el('result-safe');
  if (safeEl) safeEl.textContent = safe ? 'SAFE' : 'UNSAFE';
  const summaryEl = el('result-summary');
  if (summaryEl) summaryEl.innerHTML = summary;
  const ts = el('scan-timestamp');
  if (ts) ts.textContent = 'Scanned at ' + new Date().toLocaleTimeString();

  el('result-card')?.classList.add('visible');
  addToHistory(url, riskLevel, safe);
  fetchCompliance(url);
}

function showError(msg) {
  el('result-card')?.classList.remove('visible');
  const errEl = el('url-error');
  if (errEl) { errEl.textContent = msg; errEl.style.display = 'block'; }
}

// ── DOWNLOAD RESULT ───────────────────────────────────────────────────
function downloadResult() {
  if (!lastResult) return;
  const { url, safe, riskLevel, confidence, summary, cveCount, timestamp } = lastResult;
  const scoreEl = el('compliance-score');
  const owaspScore = scoreEl ? scoreEl.textContent : '—';
  const text = [
    '═══════════════════════════════════════',
    '        SENTINEL AI — SCAN REPORT',
    '═══════════════════════════════════════',
    `URL:            ${url}`,
    `Scanned:        ${new Date(timestamp).toLocaleString()}`,
    `Status:         ${safe ? 'SAFE' : 'THREAT DETECTED'}`,
    `Risk Level:     ${riskLevel}`,
    `Confidence:     ${confidence}%`,
    `CVEs Found:     ${cveCount ?? 0}`,
    `OWASP Score:    ${owaspScore}/100`,
    '───────────────────────────────────────',
    'SUMMARY',
    '───────────────────────────────────────',
    summary,
    '═══════════════════════════════════════',
    'sentinel-a-i.com',
  ].join('\n');

  const blob = new Blob([text], { type: 'text/plain' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `sentinel-scan-${new URL(url).hostname}-${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── COPY RESULT ───────────────────────────────────────────────────────
function copyResult() {
  if (!lastResult) return;
  navigator.clipboard.writeText(JSON.stringify(lastResult, null, 2));
}

// ── HISTORY ───────────────────────────────────────────────────────────
function addToHistory(url, riskLevel, safe) {
  scanHistory.unshift({ url, riskLevel, safe, time: new Date() });
  if (scanHistory.length > 10) scanHistory.pop();
  renderHistory();
}

function renderHistory() {
  const list  = el('history-list');
  const empty = el('history-empty');
  if (!list) return;
  if (scanHistory.length === 0) { if (empty) empty.style.display = 'block'; return; }
  if (empty) empty.style.display = 'none';
  list.innerHTML = '';
  scanHistory.forEach(item => {
    const div = document.createElement('div');
    div.className = 'history-item';
    div.innerHTML = `<div class="history-left"><div><div class="history-url">${item.url}</div><div class="history-time">${item.time.toLocaleTimeString()}</div></div></div><span class="risk-pill ${item.riskLevel}" style="font-size:0.7rem;padding:2px 10px">${item.riskLevel}</span>`;
    list.appendChild(div);
  });
}

const urlInput = el('url-input');
if (urlInput) urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') analyzeLink(); });
