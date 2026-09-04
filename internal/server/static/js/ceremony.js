// This file drives the only page that ever sees the recovery private key. The key and the
// share strings stay in this tab: the only request it makes carries the three fields the
// import endpoint accepts, named one by one below.
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const ready = (async () => {
  const go = new Go();
  const { instance } = await WebAssembly.instantiateStreaming(fetch('/static/wasm/ceremony.wasm'), go.importObject);
  go.run(instance); // main blocks on select{}; kyCeremony is registered by the time this yields
})();

let result = null;

document.getElementById('ceremony-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  await ready;
  const k = Number(document.getElementById('k').value), n = Number(document.getElementById('n').value);
  const r = globalThis.kyCeremony(k, n);
  const err = document.getElementById('error');
  if (r.error) { err.textContent = r.error; err.hidden = false; return; }
  err.hidden = true;
  result = r;
  document.getElementById('key-id').textContent = r.key_id;
  document.getElementById('card-list').innerHTML = r.shares.map((s, i) => `
    <div class="panel card">
      <h3>Custodian card ${i + 1} of ${n} &mdash; ${k} needed</h3>
      <p>Recovery key <code>${esc(r.key_id)}</code></p>
      <p>Share <code class="share">${esc(s)}</code></p>
      <p>Custodian: ____________________ &nbsp; Date: ${new Date().toISOString().slice(0, 10)}</p>
    </div>`).join('');
  document.getElementById('cards').hidden = false;
  document.getElementById('ceremony-form').hidden = true;
});

document.getElementById('print-btn').addEventListener('click', () => window.print());

document.getElementById('import-btn').addEventListener('click', async () => {
  if (!result) return;
  const status = document.getElementById('import-status');
  // Only these three fields are sent. The shares are never in this request.
  const res = await fetch('/api/recovery-key', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ public_key: result.public_key_b64, threshold: result.threshold, total_shares: result.total_shares }),
  });
  const body = await res.json().catch(() => ({}));
  status.textContent = res.ok ? `Imported key ${body.key_id}. Print the cards, then close this tab.` : `Import failed: ${body.error || res.status}`;
});
