const DEFAULT_API_URL = 'http://127.0.0.1:8765/analyze';

const apiUrlInput = document.getElementById('apiUrl');
const saveBtn = document.getElementById('saveBtn');
const testBtn = document.getElementById('testBtn');
const statusEl = document.getElementById('status');

init();

async function init() {
  const data = await chrome.storage.local.get(['mailshieldApiUrl']);
  apiUrlInput.value = data.mailshieldApiUrl || DEFAULT_API_URL;
}

saveBtn.addEventListener('click', async () => {
  const value = (apiUrlInput.value || '').trim() || DEFAULT_API_URL;
  await chrome.storage.local.set({ mailshieldApiUrl: value });
  setStatus('ok', `저장됨: ${value}`);
});

testBtn.addEventListener('click', async () => {
  const baseUrl = (apiUrlInput.value || '').trim() || DEFAULT_API_URL;
  const healthUrl = baseUrl.replace(/\/analyze\/?$/i, '/health');
  setStatus('idle', '연결 확인 중...');

  try {
    const response = await fetch(healthUrl, { method: 'GET' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    setStatus('ok', `연결 성공 · model=${payload.model || 'unknown'} · ready=${payload.ready}`);
  } catch (error) {
    setStatus('err', `연결 실패: ${String(error.message || error)}`);
  }
});

function setStatus(kind, text) {
  statusEl.className = `status ${kind}`;
  statusEl.textContent = text;
}
