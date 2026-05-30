const IS_DEV = window.location.protocol === 'file:' || ['5500', '5501', '3000'].includes(window.location.port);
const API_ENDPOINT = IS_DEV ? 'http://localhost:8000/api/analyze' : '/api/analyze';
let scanHistory = [];
let lastResult = null;
const scanSteps = ['Resolving domain...', 'Checking threat databases...', 'Running AI analysis...', 'Generating report...'];

// Safe element getter — never throws, returns null gracefully
function el(id) { return document.getElementById(id); }

function isValidUrl(str) {
  try { const u = new URL(str); return u.protocol === 'http:' || u.protocol === 'https:'; }
  catch { return false; }
}

// Animate scan step labels — runs independently, doesn't block the fetch
function animateScanSteps() {
  const stepEl = el('scan-step');
  if (!stepEl) return;
  let i = 0;
  stepEl.textContent = scanSteps[0];
  const iv = setInterval(() => {
    i++;
    if (i < scanSteps.length) { stepEl.textContent = scanSteps[i]; }
    else { stepEl.textContent = 'Finalizing results...'; clearInterval(iv); }
  }, 600);
}

async function analyzeLink() {
  const input = el('url-input');
  const errEl = el('url-error');
  const btn   = el('analyze-btn');
  const url   = input ? input.value.trim() : '';

  if (errEl) errEl.style.display = 'none';
  el('scan-state')?.classList.remove('visible');
  el('result-card')?.classList.remove('visible');

  if (!isValidUrl(url)) { if (errEl) { errEl.textContent = 'Please enter a valid URL starting with http:// or https://'; errEl.style.display = 'block'; } return; }

  if (btn) btn.disabled = true;
  el('scan-state')?.classList.add('visible');

  // Start fetch immediately — animation runs in parallel, not before
  const fetchPromise = fetch(API_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  });
  animateScanSteps();

  try {
    const response = await fetchPromise;
    if (!response.ok) throw new Error(`Server returned ${response.status} — try again`);
    const data = await response.json();
    showResult(url, data);
  } catch (err) {
    showError(err.message);
  } finally {
    if (btn) btn.disabled = false;
    el('scan-state')?.classList.remove('visible');
  }
}

function showResult(url, data) {
  if (!data) { showError('Empty response from server'); return; }
  const safe            = data.safe ?? true;
  const riskLevel       = data.riskLevel ?? 'UNKNOWN';
  const confidence      = data.confidence ?? 0;
  const summary         = data.summary ?? 'No summary available.';
  const vulnerabilityTable = data.vulnerability_table ?? null;

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
  if (summaryEl) {
    summaryEl.innerHTML = summary;
    if (vulnerabilityTable && vulnerabilityTable.length > 0) {
      summaryEl.innerHTML += `
        <div style="margin-top:20px;padding:15px;background:#1a1a1a;border:1px solid #444;border-radius:8px;">
          <h4 style="color:#ff4d4d;margin-top:0;">Infrastructure Vulnerability Data</h4>
          <pre style="font-family:monospace;white-space:pre-wrap;color:#ddd;font-size:13px;">${vulnerabilityTable}</pre>
        </div>`;
    }
  }

  const ts = el('scan-timestamp');
  if (ts) ts.textContent = 'Scanned at ' + new Date().toLocaleTimeString();

  el('result-card')?.classList.add('visible');
  addToHistory(url, riskLevel, safe);
}

function showError(msg) {
  el('result-card')?.classList.remove('visible');
  const errEl = el('url-error');
  if (errEl) {
    errEl.textContent = `Scan failed: ${msg}`;
    errEl.style.display = 'block';
  }
}

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

function copyResult() {
  if (!lastResult) return;
  navigator.clipboard.writeText(JSON.stringify(lastResult, null, 2));
}

const urlInput = el('url-input');
if (urlInput) urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') analyzeLink(); });
