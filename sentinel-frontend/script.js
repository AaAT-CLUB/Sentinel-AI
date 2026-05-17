// ── CONFIG ──────────────────────────────────────────────────────
// TODO: Change this to your backend server URL when it's running
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
// Checks that the user entered a real http/https URL
function isValidUrl(str) {
  try {
    const u = new URL(str);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

// ── SCAN STEP ANIMATION ─────────────────────────────────────────
// Cycles through the scan step labels every 600ms, then calls callback
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
// Called when user clicks "Analyze Link" or presses Enter
async function analyzeLink() {
  const input  = document.getElementById('url-input');
  const errEl  = document.getElementById('url-error');
  const btn    = document.getElementById('analyze-btn');
  const url    = input.value.trim();

  // Reset previous state
  errEl.style.display = 'none';
  document.getElementById('scan-state').classList.remove('visible');
  document.getElementById('result-card').classList.remove('visible');

  // Validate URL format
  if (!isValidUrl(url)) {
    errEl.style.display = 'block';
    return;
  }

  // Show loading state
  btn.disabled = true;
  document.getElementById('scan-state').classList.add('visible');

  runScanSteps(async () => {
    try {
      // ── API CALL ─────────────────────────────────────────────
      // Sends the URL to the backend and expects:
      // { safe: bool, riskLevel: "HIGH"|"MEDIUM"|"LOW", confidence: 0-100, summary: string }
      const response = await fetch(API_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      if (!response.ok) throw new Error(`Server error: ${response.status}`);
      const data = await response.json();
      showResult(url, data);

    } catch (err) {
      // Shows a clean error if the backend isn't connected yet
      showError(err.message);
    } finally {
      btn.disabled = false;
      document.getElementById('scan-state').classList.remove('visible');
    }
  });
}

// ── DISPLAY RESULT ───────────────────────────────────────────────
// Takes the API response and populates the result card
function showResult(url, data) {
  const { safe, riskLevel, confidence, summary } = data;
  lastResult = { url, ...data, timestamp: new Date() };

  const safeClass = safe ? 'safe' : riskLevel === 'MEDIUM' ? 'medium' : 'unsafe';
  const icon      = safe ? '✓' : '✕';
  const label     = safe ? 'Safe' : 'Threat Detected';

  // Status icon and label
  document.getElementById('result-icon').className   = `status-icon ${safeClass}`;
  document.getElementById('result-icon').textContent = icon;
  document.getElementById('result-label').className  = `status-label ${safeClass}`;
  document.getElementById('result-label').textContent = label;
  document.getElementById('result-url-display').textContent = url.length > 55 ? url.slice(0, 55) + '…' : url;

  // Risk pill badge
  const pill = document.getElementById('risk-pill');
  pill.className   = `risk-pill ${riskLevel}`;
  pill.textContent = riskLevel;

  // Confidence bar animation
  document.getElementById('confidence-fill').style.width = `${confidence}%`;
  document.getElementById('confidence-num').textContent  = `${confidence}%`;

  // Text fields
  document.getElementById('result-risk').textContent    = riskLevel;
  document.getElementById('result-safe').textContent    = safe ? 'SAFE' : 'UNSAFE';
  document.getElementById('result-summary').textContent = summary;
  document.getElementById('scan-timestamp').textContent = 'Scanned at ' + new Date().toLocaleTimeString();

  // Show the card
  document.getElementById('result-card').classList.add('visible');

  // Log to history
  addToHistory(url, riskLevel, safe);
}

// ── ERROR STATE ──────────────────────────────────────────────────
// Shown when the backend returns an error or isn't running
function showError(msg) {
  document.getElementById('result-card').classList.remove('visible');
  const errEl = document.getElementById('url-error');
  errEl.textContent = `Error: ${msg} — make sure your backend is running.`;
  errEl.style.display = 'block';
}

// ── SCAN HISTORY ─────────────────────────────────────────────────
// Keeps the last 10 scans in memory and renders them as a list
function addToHistory(url, riskLevel, safe) {
  scanHistory.unshift({ url, riskLevel, safe, time: new Date() });
  if (scanHistory.length > 10) scanHistory.pop();
  renderHistory();
}

function renderHistory() {
  const list  = document.getElementById('history-list');
  const empty = document.getElementById('history-empty');

  if (scanHistory.length === 0) {
    empty.style.display = 'block';
    return;
  }
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
// Copies the last scan result as formatted JSON to clipboard
function copyResult() {
  if (!lastResult) return;
  navigator.clipboard.writeText(JSON.stringify(lastResult, null, 2));
}

// ── ENTER KEY SUPPORT ─────────────────────────────────────────────
// Lets users press Enter instead of clicking the button
document.getElementById('url-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') analyzeLink();
});
