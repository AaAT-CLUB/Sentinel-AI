// ── CONFIG ──────────────────────────────────────────────────────
const API_ENDPOINT = '/api/analyze';

// ── STATE ───────────────────────────────────────────────────────
let scanHistory = [];
let lastResult = null;

// ── SCAN STEP LABELS ────────────────────────────────────────────
const scanSteps = [
  'Resolving domain...',
  'Checking threat databases...',
  'Running AI analysis...',
  'Generating report...'
];

// ── URL VALIDATION ──────────────────────────────────────────────
function isValidUrl(str) {
  try {
    const u = new URL(str);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

// ── SCAN STEP ANIMATION ─────────────────────────────────────────
function runScanSteps(callback) {
  let i = 0;
  const el = document.getElementById('scan-step');
  el.textContent = scanSteps[0];
  const interval = setInterval(() => {
    i++;
    if (i < scanSteps.length) {
      el.textContent = scanSteps[i];
    } else {
      clearInterval(interval);
      callback();
    }
  }, 600);
}

// ── MAIN ANALYZE FUNCTION ────────────────────────────────────────
async function analyzeLink() {
  const input  = document.getElementById('url-input');
  const errEl  = document.getElementById('url-error');
  const btn    = document.getElementById('analyze-btn');
  const url    = input.value.trim();

  errEl.style.display = 'none';
  document.getElementById('scan-state').classList.remove('visible');
  document.getElementById('result-card').classList.remove('visible');

  if (!isValidUrl(url)) {
    errEl.style.display = 'block';
    return;
  }

  btn.disabled = true;
  document.getElementById('scan-state').classList.add('visible');

  runScanSteps(async () => {
    try {
      const response = await fetch(API_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      if (!response.ok) throw new Error(`Server error: ${response.status}`);
      const data = await response.json();
      showResult(url, data);
    } catch (err) {
      showError(err.message);
    } finally {
      btn.disabled = false;
      document.getElementById('scan-state').classList.remove('visible');
    }
  });
}

// ── DISPLAY RESULT ───────────────────────────────────────────────
function showResult(url, data) {
  const { safe, riskLevel, confidence, summary } = data;
  lastResult = { url, ...data, timestamp: new Date() };

  const safeClass = safe ? 'safe' : riskLevel === 'MEDIUM' ? 'medium' : 'unsafe';
  const icon      = safe ? '✓' : '✕';
  const label     = safe ? 'Safe' : 'Threat Detected';

  document.getElementById('result-icon').className    = `status-icon ${safeClass}`;
  document.getElementById('result-icon').textContent  = icon;
  document.getElementById('result-label').className   = `status-label ${safeClass}`;
  document.getElementById('result-label').textContent = label;
  document.getElementById('result-url-display').textContent = url.length > 55 ? url.slice(0, 55) + '…' : url;

  const pill = document.getElementById('risk-pill');
  pill.className   = `risk-pill ${riskLevel}`;
  pill.textContent = riskLevel;

  document.getElementById('confidence-fill').style.width = `${confidence}%`;
  document.getElementById('confidence-num').textContent  = `${confidence}%`;
  document.getElementById('result-risk').textContent     = riskLevel;
  document.getElementById('result-safe').textContent     = safe ? 'SAFE' : 'UNSAFE';
  document.getElementById('result-summary').textContent  = summary;
  document.getElementById('scan-timestamp').textContent  = 'Scanned at ' + new Date().toLocaleTimeString();

  document.getElementById('result-card').classList.add('visible');
  addToHistory(url, riskLevel, safe);
}

// ── ERROR STATE ──────────────────────────────────────────────────
function showError(msg) {
  document.getElementById('result-card').classList.remove('visible');
  const errEl = document.getElementById('url-error');
  errEl.textContent = `Error: ${msg} — make sure your backend is running.`;
  errEl.style.display = 'block';
}

// ── SCAN HISTORY ─────────────────────────────────────────────────
function addToHistory(url, riskLevel, safe) {
  scanHistory.unshift({ url, riskLevel, safe, time: new Date() });
  if (scanHistory.length > 10) scanHistory.pop();
  renderHistory();
}

function renderHistory() {
  const list  = document.getElementById('history-list');
  const empty = document.getElementById('history-empty');
  if (scanHistory.length === 0) { empty.style.display = 'block'; return; }
  empty.style.display = 'none';
  list.innerHTML = '';
  scanHistory.forEach(item => {
    const div = document.createElement('div');
    div.className = 'history-item';
    div.innerHTML = `
      <div class="history-left">
        <div>
          <div class="history-url">${item.url}</div>
          <div class="history-time">${item.time.toLocaleTimeString()}</div>
        </div>
      </div>
      <span class="risk-pill ${item.riskLevel}" style="font-size:0.7rem;padding:2px 10px">${item.riskLevel}</span>`;
    list.appendChild(div);
  });
}

// ── COPY RESULT ───────────────────────────────────────────────────
function copyResult() {
  if (!lastResult) return;
  navigator.clipboard.writeText(JSON.stringify(lastResult, null, 2));
}

// ── ENTER KEY SUPPORT ─────────────────────────────────────────────
document.getElementById('url-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') analyzeLink();
});