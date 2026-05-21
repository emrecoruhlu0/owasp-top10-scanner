'use strict';

const MODULE_LABELS = {
  A01: 'Broken Access Control',
  A02: 'Cryptographic Failures',
  A03: 'Injection (SQLi + XSS)',
  A04: 'Insecure Design',
  A05: 'Security Misconfiguration',
  A06: 'Vulnerable Components',
  A07: 'Auth Failures',
  A08: 'Data Integrity',
  A09: 'Logging & Monitoring',
  A10: 'SSRF',
};

const ALL_MODULES = Object.keys(MODULE_LABELS);

const SEVERITY_ORDER = ['Kritik', 'Yüksek', 'Orta', 'Düşük', 'Bilgilendirici'];

let currentScanId = null;
let ws = null;
let liveFindings = [];

// ---------- Sayfa başlatma ----------

function initPage() {
  buildModuleGrid();
  loadQuickTargets();
}

function buildModuleGrid() {
  const grid = document.getElementById('moduleGrid');
  if (!grid) return;
  grid.innerHTML = ALL_MODULES.map(id => `
    <label class="module-chip checked" id="chip-${id}">
      <input type="checkbox" value="${id}" checked onchange="updateChip('${id}')" />
      <span>${id}</span>
      <span style="color:var(--color-muted);font-size:11px">${MODULE_LABELS[id]}</span>
    </label>
  `).join('');
}

function updateChip(id) {
  const chip = document.getElementById(`chip-${id}`);
  const cb = chip.querySelector('input');
  chip.classList.toggle('checked', cb.checked);
}

function selectAllModules(val) {
  document.querySelectorAll('#moduleGrid input[type=checkbox]').forEach(cb => {
    cb.checked = val;
    updateChip(cb.value);
  });
}

async function loadQuickTargets() {
  const el = document.getElementById('quickTargets');
  if (!el) return;
  try {
    const res = await fetch('/api/targets');
    const targets = await res.json();
    el.innerHTML = targets.map(t => `
      <button class="target-btn" onclick="selectTarget(${JSON.stringify(t.url)}, ${JSON.stringify(t.note)})">
        ${t.name}
      </button>
    `).join('');
  } catch {
    el.innerHTML = '<span style="color:var(--color-muted);font-size:12px">Test ortamı yüklenmedi</span>';
  }
}

function selectTarget(url, note) {
  document.getElementById('targetUrl').value = url;
  if (note) document.getElementById('cookieInput').value = note.replace('Cookie gerekli: ', '');
}

// ---------- Tarama ----------

function getSelectedModules() {
  return [...document.querySelectorAll('#moduleGrid input:checked')].map(c => c.value);
}

async function startScan() {
  const target = document.getElementById('targetUrl').value.trim();
  if (!target) { alert('Hedef URL giriniz.'); return; }

  const modules = getSelectedModules();
  if (!modules.length) { alert('En az bir modül seçiniz.'); return; }

  const body = {
    target,
    modules,
    no_llm: !document.getElementById('llmToggle').checked,
    cookie: document.getElementById('cookieInput').value.trim() || null,
    timeout: parseInt(document.getElementById('timeoutInput').value) || 5,
  };

  try {
    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (res.status === 429) { alert('Maksimum tarama limitine ulaşıldı. Lütfen bekleyin.'); return; }
    if (!res.ok) { alert('Tarama başlatılamadı.'); return; }
    const data = await res.json();
    connectWS(data.scan_id, modules);
  } catch (e) {
    alert('Sunucuya bağlanılamadı: ' + e.message);
  }
}

async function cancelScan() {
  if (!currentScanId) return;
  await fetch(`/api/scan/${currentScanId}`, { method: 'DELETE' });
}

// ---------- WebSocket ----------

function connectWS(scanId, modules) {
  currentScanId = scanId;
  liveFindings = [];

  document.getElementById('startBtn').disabled = true;
  document.getElementById('cancelBtn').style.display = 'inline-flex';
  document.getElementById('progressCard').style.display = 'block';
  document.getElementById('findingsCard').style.display = 'block';
  document.getElementById('findingList').innerHTML = '<div class="empty">Bulgular bekleniyor...</div>';
  document.getElementById('findingCount').textContent = '';
  document.getElementById('logPanel').innerHTML = '';
  document.getElementById('statusText').textContent = 'Bağlanıyor...';

  buildProgressBar(modules);

  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws/${scanId}`);

  ws.onopen = () => setStatus('Taranıyor...');

  ws.onmessage = e => {
    try { handleEvent(JSON.parse(e.data), modules); } catch {}
  };

  ws.onclose = () => {
    document.getElementById('startBtn').disabled = false;
    document.getElementById('cancelBtn').style.display = 'none';
  };

  ws.onerror = () => setStatus('Bağlantı hatası');
}

function handleEvent(evt, modules) {
  switch (evt.type) {
    case 'scan_started':
      setStatus(`Tarama başladı → ${evt.target}`);
      break;

    case 'module_begin':
      setStatus(evt.description || `${evt.module} taranıyor...`);
      markProgress(modules, evt.module, 'active');
      appendLog(`[${evt.module}] ${evt.description || ''}`, 'module');
      break;

    case 'module_done':
      markProgress(modules, evt.module, 'done');
      appendLog(`[${evt.module}] Tamamlandı — ${evt.finding_count} bulgu`);
      break;

    case 'log':
      appendLog(evt.message, evt.level);
      break;

    case 'scan_complete':
      setStatus(`Tamamlandı — ${evt.total_findings} bulgu (${evt.duration}s)`);
      markProgress(modules, null, 'done');
      if (evt.report && evt.report.findings) {
        renderFindings(evt.report.findings);
      }
      if (evt.report_id) {
        const link = document.createElement('a');
        link.href = `/report/${evt.report_id}`;
        link.textContent = 'Detaylı Raporu Gör →';
        link.style.cssText = 'display:block;margin-top:12px;font-size:13px';
        document.getElementById('progressCard').appendChild(link);
      }
      break;

    case 'scan_cancelled':
      setStatus('Tarama iptal edildi.');
      break;

    case 'scan_error':
      setStatus('Hata: ' + evt.message);
      appendLog('HATA: ' + evt.message, 'ERROR');
      break;
  }
}

// ---------- Progress bar ----------

function buildProgressBar(modules) {
  const bar = document.getElementById('progressBar');
  bar.innerHTML = modules.map(m => `<div class="progress-segment" id="seg-${m}" title="${m}: ${MODULE_LABELS[m]}"></div>`).join('');
}

function markProgress(modules, activeModule, state) {
  if (state === 'done' && !activeModule) {
    modules.forEach(m => {
      const seg = document.getElementById(`seg-${m}`);
      if (seg && !seg.classList.contains('done')) seg.classList.add('done');
    });
    return;
  }
  const seg = document.getElementById(`seg-${activeModule}`);
  if (!seg) return;
  seg.className = 'progress-segment ' + state;
  document.getElementById('activeModule').textContent =
    state === 'active' ? `${activeModule}: ${MODULE_LABELS[activeModule] || ''}` : '';
}

// ---------- Log ----------

function appendLog(msg, level) {
  const panel = document.getElementById('logPanel');
  const div = document.createElement('div');
  div.className = 'log-line' + (level ? ' ' + level : '');
  div.textContent = msg;
  panel.appendChild(div);
  panel.scrollTop = panel.scrollHeight;
}

// ---------- Findings ----------

function renderFindings(findings) {
  const list = document.getElementById('findingList');
  liveFindings = findings;
  list.innerHTML = '';

  if (!findings.length) {
    list.innerHTML = '<div class="empty">Bulgu bulunamadı.</div>';
    document.getElementById('findingCount').textContent = '(0)';
    return;
  }

  document.getElementById('findingCount').textContent = `(${findings.length})`;
  findings.forEach((f, i) => list.appendChild(buildFindingCard(f, i)));
}

function buildFindingCard(f, idx) {
  const card = document.createElement('div');
  card.className = 'finding-card';
  card.innerHTML = `
    <div class="finding-header" onclick="toggleCard(this)">
      <span class="owasp-id">${f.owasp_id}</span>
      <span class="title">${escHtml(f.title)}</span>
      <span class="badge badge-${f.severity}">${f.severity}</span>
      <span class="badge badge-${f.confidence}">${f.confidence}</span>
      <span class="chevron">▶</span>
    </div>
    <div class="finding-body">
      <div class="detail-grid">
        <span class="detail-label">URL</span>
        <span class="detail-value">${escHtml(f.url)}</span>
        <span class="detail-label">Parametre</span>
        <span class="detail-value">${escHtml(f.parameter || '—')}</span>
        <span class="detail-label">Metod</span>
        <span class="detail-value">${escHtml(f.method || 'GET')}</span>
        <span class="detail-label">Payload</span>
        <span class="detail-value">${escHtml(f.payload || '—')}</span>
        ${f.response_snippet ? `
        <span class="detail-label">Yanıt</span>
        <span class="detail-value">${escHtml(f.response_snippet.substring(0, 300))}</span>
        ` : ''}
      </div>
      ${buildLLMPanel(f.llm_analysis)}
    </div>
  `;
  return card;
}

function buildLLMPanel(llm) {
  if (!llm || llm.llm_hatasi) return '';
  const onlemler = (llm.genel_onlemler || []).map(o => `<li>${escHtml(o)}</li>`).join('');
  return `
    <div class="llm-panel">
      <h4>🤖 AI Analizi</h4>
      <div class="llm-field"><strong>Risk:</strong> ${escHtml(llm.risk_seviyesi || '')} &nbsp; <strong>Güven:</strong> ${escHtml(llm.llm_guven || '')}</div>
      <div class="llm-field"><strong>Açıklama:</strong> ${escHtml(llm.teknik_aciklama || '')}</div>
      <div class="llm-field"><strong>Düzeltme:</strong> ${escHtml(llm.kod_duzeltme || '')}</div>
      ${onlemler ? `<div class="llm-field"><strong>Önlemler:</strong><ul style="margin:4px 0 0 16px;font-size:12px">${onlemler}</ul></div>` : ''}
    </div>
  `;
}

function toggleCard(header) {
  header.closest('.finding-card').classList.toggle('open');
}

// ---------- Yardımcılar ----------

function setStatus(msg) {
  document.getElementById('statusText').textContent = msg;
}

function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
