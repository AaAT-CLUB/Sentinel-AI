const IS_DEV = window.location.protocol === 'file:' || ['5500', '5501', '3000'].includes(window.location.port);
const API_ENDPOINT = IS_DEV ? 'http://localhost:8000/api/analyze' : '/api/analyze';
let scanHistory = [];
let lastResult = null;
const scanSteps = ['Resolving domain...', 'Checking threat databases...', 'Running AI analysis...', 'Generating report...'];

function isValidUrl(str) {
  try { const u = new URL(str); return u.protocol === 'http:' || u.protocol === 'https:'; }
  catch { return false; }
}

function runScanSteps(callback) {
  let i = 0;
  const el = document.getElementById('scan-step');
  el.textContent = scanSteps[0];
  const interval = setInterval(() => {
    i++;
    if (i < scanSteps.length) { el.textContent = scanSteps[i]; }
    else { clearInterval(interval); callback(); }
  }, 600);
}

async function analyzeLink() {
  const input = document.getElementById('url-input');
  const errEl = document.getElementById('url-error');
  const btn   = document.getElementById('analyze-btn');
  const url   = input.value.trim();
  errEl.style.display = 'none';
  document.getElementById('scan-state').classList.remove('visible');
  document.getElementById('result-card').classList.remove('visible');
  if (!isValidUrl(url)) { errEl.style.display = 'block'; return; }
  btn.disabled = true;
  document.getElementById('scan-state').classList.add('visible');
  runScanSteps(async () => {
    try {
      const response = await fetch(API_ENDPOINT, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
      if (!response.ok) throw new Error(`Server error: ${response.status}`);
      showResult(url, await response.json());
    } catch (err) { showError(err.message); }
    finally { btn.disabled = false; document.getElementById('scan-state').classList.remove('visible'); }
  });
}

function showResult(url, data) {
  const { safe, riskLevel, confidence, summary, vulnerability_table } = data;
  lastResult = { url, ...data, timestamp: new Date() };
  const safeClass = safe ? 'safe' : riskLevel === 'MEDIUM' ? 'medium' : 'unsafe';
  
  document.getElementById('result-icon').className = `status-icon ${safeClass}`;
  document.getElementById('result-icon').textContent = safe ? '✓' : '✕';
  document.getElementById('result-label').className = `status-label ${safeClass}`;
  document.getElementById('result-label').textContent = safe ? 'Safe' : 'Threat Detected';
  document.getElementById('result-url-display').textContent = url.length > 55 ? url.slice(0, 55) + '…' : url;
  
  const pill = document.getElementById('risk-pill');
  pill.className = `risk-pill ${riskLevel}`; pill.textContent = riskLevel;
  
  document.getElementById('confidence-fill').style.width = `${confidence}%`;
  document.getElementById('confidence-num').textContent = `${confidence}%`;
  document.getElementById('result-risk').textContent = riskLevel;
  document.getElementById('result-safe').textContent = safe ? 'SAFE' : 'UNSAFE';
  
  // Render summary and inject technical table
  const summaryEl = document.getElementById('result-summary');
  summaryEl.innerHTML = summary; 
  
  if (vulnerability_table && vulnerability_table.length > 0) {
    summaryEl.innerHTML += `
      <div style="margin-top:20px; padding:15px; background:#1a1a1a; border:1px solid #444; border-radius:8px;">
        <h4 style="color:#ff4d4d; margin-top:0;">Infrastructure Vulnerability Data</h4>
        <pre style="font-family:monospace; white-space:pre-wrap; color:#ddd; font-size:13px;">${vulnerability_table}</pre>
      </div>`;
  }
  
  document.getElementById('scan-timestamp').textContent = 'Scanned at ' + new Date().toLocaleTimeString();
  document.getElementById('result-card').classList.add('visible');
  addToHistory(url, riskLevel, safe);
}

function showError(msg) {
  document.getElementById('result-card').classList.remove('visible');
  const errEl = document.getElementById('url-error');
  errEl.textContent = `Error: ${msg} — make sure your backend is running.`;
  errEl.style.display = 'block';
}

function addToHistory(url, riskLevel, safe) {
  scanHistory.unshift({ url, riskLevel, safe, time: new Date() });
  if (scanHistory.length > 10) scanHistory.pop();
  renderHistory();
}

function renderHistory() {
  const list = document.getElementById('history-list');
  const empty = document.getElementById('history-empty');
  if (scanHistory.length === 0) { if (empty) empty.style.display = 'block'; return; }
  if (empty) empty.style.display = 'none'; list.innerHTML = '';
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

document.getElementById('url-input').addEventListener('keydown', e => { if (e.key === 'Enter') analyzeLink(); });