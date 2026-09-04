// Every value below comes from the database, and some of it was typed by someone
// who never authenticated. Two contexts, two escapes:
//   esc   — HTML text and ordinary attribute values.
//   escJs — a value that lands inside a JS string literal inside an attribute,
//           i.e. onclick="fn('...')". HTML-escaping alone is not enough there:
//           the browser decodes the entity before parsing the handler as script,
//           so the quote has to be neutralised for JS first and for HTML second.
const esc = v => String(v ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const escJs = v => esc(String(v ?? '').replace(/[\\'"\r\n]/g, c =>
  '\\' + ({ '\r': 'r', '\n': 'n' }[c] || c)));

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  loadAuthUser();
  loadReadiness();
  loadCapsules();
  loadPairing();
  loadCustodians();
  loadRecoveryKey();
  loadReplication();
  loadAudit();

  // Polling for freshness
  setInterval(() => {
    loadReadiness();
    loadReplication();
  }, 10000);
});

// Tab Navigation
function initTabs() {
  const tabs = document.querySelectorAll('.tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      tab.classList.add('active');
      const target = document.getElementById(tab.dataset.tab);
      if (target) target.classList.add('active');
    });
  });
}

// 1. Readiness & System Status
async function loadReadiness() {
  try {
    const res = await fetch('/api/readiness');
    if (!res.ok) return;
    const data = await res.json();

    const capsuleCount = Number(data.capsule_count) || 0;
    document.getElementById('metric-capsules').textContent = capsuleCount;
    document.getElementById('metric-custodians').textContent = Number(data.custodian_count) || 0;

    // The pill states a fact the store can check. It must never imply a verified
    // restore: nothing here can open a capsule.
    const statusPill = document.getElementById('system-status-pill');
    const dot = '<span class="dot"></span> ';
    statusPill.className = capsuleCount > 0 ? 'status-pill ready' : 'status-pill warning';
    statusPill.innerHTML = capsuleCount > 0
      ? dot + capsuleCount + ' CAPSULE' + (capsuleCount === 1 ? '' : 'S') + ' STORED'
      : dot + 'NO CAPSULES STORED';
  } catch (err) {
    console.error('Error fetching readiness:', err);
  }
}

// 2. Capsules List
async function loadCapsules() {
  const tbody = document.getElementById('capsules-table-body');
  if (!tbody) return;

  try {
    const res = await fetch('/api/capsules');
    if (!res.ok) return;
    const capsules = await res.json() || [];

    if (capsules.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color: var(--text-dim);">No capsules deposited yet. A paired product deposits its own sealed capsules.</td></tr>';
      return;
    }

    tbody.innerHTML = capsules.map(c => `
      <tr>
        <td><code>${esc(c.id)}</code></td>
        <td><strong>${esc(c.service_name)}</strong></td>
        <td><span class="status-pill ready">${esc(c.threshold)} of ${esc(c.total_shares)} Shares</span></td>
        <td>${(c.size_bytes / 1024).toFixed(1)} KB</td>
        <td><code title="${esc(c.payload_hash)}">${esc(String(c.payload_hash).substring(0, 12))}...</code></td>
        <td>${new Date(c.created_at).toLocaleString()}</td>
        <td>
          <a class="btn btn-secondary btn-sm" href="/api/capsules/${encodeURIComponent(c.id)}/download" download>Download</a>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Error fetching capsules:', err);
  }
}

// 3. Custodians
async function loadCustodians() {
  const tbody = document.getElementById('custodians-table-body');
  if (!tbody) return;

  try {
    const res = await fetch('/api/custodians');
    if (!res.ok) return;
    const list = await res.json() || [];

    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-dim);">No custodians registered.</td></tr>';
      return;
    }

    tbody.innerHTML = list.map(c => `
      <tr>
        <td><strong>${esc(c.name)}</strong></td>
        <td>${esc(c.email)}</td>
        <td><code>${esc(c.fingerprint)}</code></td>
        <td>${new Date(c.created_at).toLocaleString()}</td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Error fetching custodians:', err);
  }
}

// The public half of the ceremony's keypair, if it has been imported yet. The server
// never has more than this, so this is the whole status the dashboard can show.
async function loadRecoveryKey() {
  const el = document.getElementById('recovery-key-status');
  if (!el) return;
  try {
    const res = await fetch('/api/recovery-key');
    if (res.status === 404) {
      el.textContent = 'No recovery key \u2014 run the ceremony';
      return;
    }
    if (!res.ok) return;
    const k = await res.json();
    el.innerHTML = `Key ID <code>${esc(k.key_id)}</code> &mdash; ${esc(k.threshold)} of ${esc(k.total_shares)} custodian cards, imported by ${esc(k.imported_by)} on ${esc(new Date(k.imported_at).toLocaleString())}`;
  } catch (err) {
    console.error('Error fetching recovery key:', err);
  }
}

// 5. Audit Ledger
async function loadAudit() {
  const tbody = document.getElementById('audit-table-body');
  if (!tbody) return;

  try {
    const res = await fetch('/api/audit');
    if (!res.ok) return;
    const events = await res.json() || [];

    if (events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--text-dim);">No audit records found.</td></tr>';
      return;
    }

    tbody.innerHTML = events.map(e => `
      <tr>
        <td><strong>#${esc(e.sequence_num)}</strong></td>
        <td><code>${esc(e.action)}</code></td>
        <td>${esc(e.actor)}</td>
        <td><code>${esc(e.target_id)}</code></td>
        <td><code title="${esc(e.event_hash)}">${esc(String(e.event_hash).substring(0, 14))}...</code></td>
        <td>${new Date(e.created_at).toLocaleString()}</td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Error fetching audit:', err);
  }
}

// Verify Chain
async function verifyAuditChain() {
  const badge = document.getElementById('chain-verify-status');
  badge.textContent = 'Verifying cryptographic chain...';
  badge.style.color = 'var(--text-muted)';

  try {
    const res = await fetch('/api/audit/verify', { method: 'POST' });
    const data = await res.json();
    if (data.valid) {
      badge.textContent = `✓ Cryptographic Chain Verified (${data.count} events)`;
      badge.style.color = 'var(--accent-green)';
    } else {
      badge.textContent = `✗ Chain Broken: ${data.error || 'verification failed'}`;
      badge.style.color = 'var(--accent-red)';
    }
  } catch (err) {
    badge.textContent = 'Chain verification error';
    badge.style.color = 'var(--accent-red)';
  }
}

// Custodian Add
function openCustodianModal() {
  document.getElementById('custodian-modal').classList.add('open');
}
function closeCustodianModal() {
  document.getElementById('custodian-modal').classList.remove('open');
}
async function submitCustodian(e) {
  e.preventDefault();
  const name = document.getElementById('custodian-name').value;
  const email = document.getElementById('custodian-email').value;

  try {
    const res = await fetch('/api/custodians', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to add custodian');
    closeCustodianModal();
    loadCustodians();
    loadReadiness();
  } catch (err) {
    alert('Error: ' + err.message);
  }
}

// 6. Pairing Management
async function loadPairing() {
  const tbody = document.getElementById('pairing-table-body');
  if (!tbody) return;

  try {
    const res = await fetch('/api/pairing/list');
    if (!res.ok) return;
    const list = await res.json() || [];

    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--text-dim);">No paired products or pending pairing codes. Click "+ Generate Pairing Code" above.</td></tr>';
      return;
    }

    tbody.innerHTML = list.map(p => `
      <tr>
        <td><strong>${esc(p.app_name)}</strong></td>
        <td><code>${esc(p.service_name)}</code></td>
        <td>
          ${p.status === 'pending'
            ? `<span style="color: var(--text-dim); font-size: 12px;">Code shown once, when generated</span>`
            : `<code style="color: var(--text-dim);">${esc(p.id)}</code>`}
        </td>
        <td>
          <span class="status-pill ${p.status === 'paired' ? 'ready' : (p.status === 'pending' ? 'warning' : 'danger')}">
            <span class="dot"></span> ${esc(String(p.status).toUpperCase())}
          </span>
        </td>
        <td>${p.last_backup_at ? new Date(p.last_backup_at).toLocaleString() : '<span style="color: var(--text-dim);">Never</span>'}</td>
        <td>
          <div style="font-size: 12px;">${p.status === 'paired' && p.paired_at ? new Date(p.paired_at).toLocaleString() : 'Expires ' + new Date(p.expires_at).toLocaleTimeString()}</div>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Error fetching pairing list:', err);
  }
}

function openPairingGenModal() {
  document.getElementById('pairing-gen-modal').classList.add('open');
}

function closePairingGenModal() {
  document.getElementById('pairing-gen-modal').classList.remove('open');
}

async function submitGeneratePairing(e) {
  e.preventDefault();
  const serviceName = document.getElementById('pairing-service').value;
  const appName = document.getElementById('pairing-app-name').value;
  const ttl = parseInt(document.getElementById('pairing-ttl').value, 10);

  try {
    const res = await fetch('/api/pairing/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service_name: serviceName, app_name: appName, ttl_minutes: ttl })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed generating pairing code');

    closePairingGenModal();

    // Show display modal
    document.getElementById('display-pairing-code').textContent = data.pairing_code;
    document.getElementById('display-pairing-expires').textContent = `${ttl} minutes (${new Date(data.expires_at).toLocaleTimeString()})`;
    document.getElementById('display-pairing-url').textContent = window.location.origin;
    document.getElementById('pairing-code-display-modal').classList.add('open');

    loadPairing();
    loadAudit();
  } catch (err) {
    alert('Error generating pairing code: ' + err.message);
  }
}

function closePairingDisplayModal() {
  document.getElementById('pairing-code-display-modal').classList.remove('open');
}

// 7. Authentication State Management & SSO Gateway
let currentUser = null;
let ssoConfig = null;

async function loadAuthUser() {
  try {
    const [meRes, ssoRes] = await Promise.all([
      fetch('/api/auth/me'),
      fetch('/api/auth/sso/config')
    ]);

    const data = meRes.ok ? await meRes.json() : { authenticated: false };
    ssoConfig = ssoRes.ok ? await ssoRes.json() : null;

    const nameEl = document.getElementById('user-display-name');
    const roleEl = document.getElementById('user-role-badge');
    const btn = document.getElementById('btn-auth-action');
    const btnSSOPair = document.getElementById('btn-sso-pair-header');
    const btnChangePass = document.getElementById('btn-change-pass-header');
    const loginGateway = document.getElementById('login-gateway-view');
    const dashboardView = document.getElementById('dashboard-view');
    const ssoActiveSection = document.getElementById('sso-active-section');

    // Show SSO sign-in button only if SSO is paired & active
    if (ssoActiveSection) {
      ssoActiveSection.style.display = (ssoConfig && ssoConfig.enabled && ssoConfig.issuer_url) ? 'block' : 'none';
    }

    if (data.authenticated && data.user) {
      currentUser = data.user;
      if (nameEl) nameEl.textContent = data.user.name || data.user.email || data.user.username;
      if (roleEl) {
        roleEl.textContent = (data.user.role || 'operator').toUpperCase();
        roleEl.className = `status-pill ${data.user.role === 'admin' ? 'ready' : 'warning'}`;
      }
      if (btn) {
        btn.textContent = 'Sign Out';
        btn.className = 'btn btn-secondary btn-sm';
      }
      if (btnSSOPair) btnSSOPair.style.display = data.user.role === 'admin' ? 'inline-flex' : 'none';
      if (btnChangePass) btnChangePass.style.display = 'inline-flex';

      if (loginGateway) loginGateway.style.display = 'none';
      if (dashboardView) dashboardView.style.display = 'block';

      // Load protected dashboard data
      loadReadiness();
      loadCapsules();
      loadPairing();
      loadCustodians();
      loadAudit();
      loadReplication();
    } else {
      currentUser = null;
      if (nameEl) nameEl.textContent = 'Unauthenticated';
      if (roleEl) {
        roleEl.textContent = 'GUEST';
        roleEl.className = 'status-pill danger';
      }
      if (btn) {
        btn.textContent = 'Sign In';
        btn.className = 'btn btn-primary btn-sm';
      }
      if (btnSSOPair) btnSSOPair.style.display = 'none';
      if (btnChangePass) btnChangePass.style.display = 'none';

      if (loginGateway) loginGateway.style.display = 'block';
      if (dashboardView) dashboardView.style.display = 'none';
    }
  } catch (err) {
    console.error('Error fetching auth user:', err);
  }
}

async function submitLocalLogin(e) {
  e.preventDefault();
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const errBox = document.getElementById('login-error-box');
  const btn = document.getElementById('btn-local-login-submit');

  errBox.style.display = 'none';
  btn.disabled = true;
  btn.textContent = 'Verifying credentials...';

  try {
    const res = await fetch('/api/auth/login/local', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Authentication failed');
    }

    // Success
    document.getElementById('login-password').value = '';
    await loadAuthUser();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Sign In as Local Admin';
  }
}

function handleLogin() {
  window.location.href = '/api/auth/login';
}

async function handleLogout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
    currentUser = null;
    await loadAuthUser();
  } catch (err) {
    console.error('Logout error:', err);
  }
}

function handleAuthAction() {
  if (currentUser) {
    handleLogout();
  } else {
    const loginGateway = document.getElementById('login-gateway-view');
    if (loginGateway) {
      loginGateway.scrollIntoView({ behavior: 'smooth' });
      document.getElementById('login-password').focus();
    }
  }
}

// 7b. SSO Pairing & Config Modal
async function openSSOConfigModal() {
  const statusBox = document.getElementById('sso-test-status');
  if (statusBox) statusBox.style.display = 'none';

  try {
    const res = await fetch('/api/auth/sso/config');
    if (res.ok) {
      const cfg = await res.json();
      document.getElementById('sso-enabled-check').checked = !!cfg.enabled;
      document.getElementById('sso-issuer-input').value = cfg.issuer_url || '';
      document.getElementById('sso-client-id-input').value = cfg.client_id || 'kyrecovery-server';
      document.getElementById('sso-client-secret-input').value = cfg.client_secret || '';
      document.getElementById('sso-redirect-input').value = cfg.redirect_url || (window.location.origin + '/api/auth/callback');
      document.getElementById('sso-admin-email-input').value = cfg.admin_email || '';
    }
  } catch (err) {
    console.error('Error fetching SSO config:', err);
  }

  document.getElementById('sso-config-modal').classList.add('open');
}

function closeSSOConfigModal() {
  document.getElementById('sso-config-modal').classList.remove('open');
}

async function testSSOConnection() {
  const statusBox = document.getElementById('sso-test-status');
  const issuer = document.getElementById('sso-issuer-input').value.trim();

  if (!issuer) {
    alert('Please enter a KySignOn Issuer URL to test.');
    return;
  }

  statusBox.style.display = 'block';
  statusBox.style.background = 'var(--bg-input)';
  statusBox.style.color = 'var(--accent-cyan)';
  statusBox.textContent = 'Contacting KySignOn authority at ' + issuer + '...';

  try {
    const res = await fetch('/api/auth/sso/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ issuer_url: issuer })
    });
    const data = await res.json();
    if (data.success) {
      statusBox.style.background = 'var(--accent-green-dim)';
      statusBox.style.color = 'var(--accent-green)';
      statusBox.textContent = '✓ ' + data.message;
    } else {
      statusBox.style.background = 'var(--accent-red-dim)';
      statusBox.style.color = 'var(--accent-red)';
      statusBox.textContent = '✗ ' + (data.error || 'Connection failed');
    }
  } catch (err) {
    statusBox.style.background = 'var(--accent-red-dim)';
    statusBox.style.color = 'var(--accent-red)';
    statusBox.textContent = '✗ Network test error: ' + err.message;
  }
}

async function submitSSOConfig(e) {
  e.preventDefault();
  const payload = {
    enabled: document.getElementById('sso-enabled-check').checked,
    issuer_url: document.getElementById('sso-issuer-input').value.trim(),
    client_id: document.getElementById('sso-client-id-input').value.trim(),
    client_secret: document.getElementById('sso-client-secret-input').value.trim(),
    redirect_url: document.getElementById('sso-redirect-input').value.trim(),
    admin_email: document.getElementById('sso-admin-email-input').value.trim()
  };

  try {
    const res = await fetch('/api/auth/sso/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed saving SSO settings');

    closeSSOConfigModal();
    alert('✓ KySignOn SSO configuration saved successfully!');
    await loadAuthUser();
  } catch (err) {
    alert('SSO Config Error: ' + err.message);
  }
}

// 7c. Change Local Password Modal
function openChangePasswordModal() {
  document.getElementById('pass-current').value = '';
  document.getElementById('pass-new').value = '';
  document.getElementById('pass-confirm').value = '';
  document.getElementById('change-pass-error').style.display = 'none';
  document.getElementById('change-password-modal').classList.add('open');
}

function closeChangePasswordModal() {
  document.getElementById('change-password-modal').classList.remove('open');
}

async function submitChangePassword(e) {
  e.preventDefault();
  const oldPassword = document.getElementById('pass-current').value;
  const newPassword = document.getElementById('pass-new').value;
  const confirmPassword = document.getElementById('pass-confirm').value;
  const errBox = document.getElementById('change-pass-error');

  if (newPassword !== confirmPassword) {
    errBox.textContent = 'New password and confirmation do not match.';
    errBox.style.display = 'block';
    return;
  }

  try {
    const res = await fetch('/api/auth/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ old_password: oldPassword, new_password: newPassword })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed changing password');

    closeChangePasswordModal();
    alert('✓ Password updated successfully!');
  } catch (err) {
    errBox.textContent = err.message;
    errBox.style.display = 'block';
  }
}

// 9. Offsite Replication Management
async function loadReplication() {
  await Promise.all([loadReplicationTargets(), loadReplicationLogs()]);
}

async function loadReplicationTargets() {
  const tbody = document.getElementById('replication-targets-table-body');
  if (!tbody) return;

  try {
    const res = await fetch('/api/replication/targets');
    if (!res.ok) return;
    const list = await res.json() || [];

    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color: var(--text-dim);">No offsite replication targets configured. Click "+ Add Replication Target" above to configure Cloudflare R2, AWS S3, MinIO, or local mounts.</td></tr>';
      return;
    }

    tbody.innerHTML = list.map(t => `
      <tr>
        <td><strong>${esc(t.name)}</strong></td>
        <td><span class="pill-badge">${esc(String(t.type).toUpperCase())}</span></td>
        <td>
          <code style="font-size: 12px;">${esc(t.type === 's3' ? (t.bucket + ' (' + t.region + ')') : t.type === 'smb' ? (t.endpoint + '/' + t.bucket) : t.endpoint)}</code>
        </td>
        <td>
          <span class="status-pill ${t.auto_sync ? 'ready' : 'warning'}">
            <span class="dot"></span> ${t.auto_sync ? 'ENABLED' : 'MANUAL'}
          </span>
        </td>
        <td>
          <span class="status-pill ${t.status === 'active' ? 'ready' : (t.status === 'error' ? 'danger' : 'warning')}">
            <span class="dot"></span> ${esc(String(t.status).toUpperCase())}
          </span>
        </td>
        <td>${t.last_sync_at ? new Date(t.last_sync_at).toLocaleString() : '<span style="color: var(--text-dim);">Never</span>'}</td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="syncAllToTarget('${escJs(t.id)}')">Sync All</button>
          <button class="btn btn-sm" style="color: var(--accent-red); margin-left: 4px;" onclick="deleteReplicationTarget('${escJs(t.id)}')">Delete</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Error loading replication targets:', err);
  }
}

async function loadReplicationLogs() {
  const tbody = document.getElementById('replication-logs-table-body');
  if (!tbody) return;

  try {
    const res = await fetch('/api/replication/logs');
    if (!res.ok) return;
    const list = await res.json() || [];

    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--text-dim);">No recent transfer activity.</td></tr>';
      return;
    }

    tbody.innerHTML = list.map(l => `
      <tr>
        <td><span style="font-size: 12px;">${new Date(l.created_at).toLocaleString()}</span></td>
        <td><code>${esc(l.target_id)}</code></td>
        <td><code>${esc(l.capsule_id)}</code></td>
        <td>${(l.bytes_transferred / 1024).toFixed(1)} KB</td>
        <td>${Number(l.duration_ms) || 0} ms</td>
        <td>
          <span class="status-pill ${l.status === 'success' ? 'ready' : 'danger'}">
            <span class="dot"></span> ${esc(String(l.status).toUpperCase())}
          </span>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Error loading replication logs:', err);
  }
}

function openReplicationModal() {
  applyReplicationPreset();
  document.getElementById('repl-test-status').style.display = 'none';
  document.getElementById('replication-modal').classList.add('open');
}

function closeReplicationModal() {
  document.getElementById('replication-modal').classList.remove('open');
}

function applyReplicationPreset() {
  const preset = document.getElementById('repl-preset').value;
  const s3Fields = document.getElementById('repl-s3-fields');
  const endpointLabel = document.getElementById('repl-endpoint-label');
  const endpointInput = document.getElementById('repl-endpoint');
  const show = (id, on) => { document.getElementById(id).style.display = on ? '' : 'none'; };
  const label = (id, text) => { document.getElementById(id).textContent = text; };

  show('repl-host-key-group', preset === 'sftp');
  show('repl-smb-warning', preset === 'smb');
  show('repl-bucket-group', preset !== 'sftp');
  show('repl-region-group', preset !== 'sftp' && preset !== 'smb');
  label('repl-bucket-label', preset === 'smb' ? 'Share Name' : 'Bucket Name');
  label('repl-access-key-label', preset === 'sftp' || preset === 'smb' ? 'Username' : 'Access Key ID');
  label('repl-secret-key-label', preset === 'sftp' ? 'Password or PEM Private Key' : preset === 'smb' ? 'Password' : 'Secret Access Key');
  label('repl-prefix-label', preset === 'sftp' || preset === 'smb' ? 'Remote Directory' : 'Prefix / Subdirectory');
  // The field is prefilled with capsules/, which would override a directory
  // pasted in an SMB path; leave it blank there and say where it comes from.
  const prefixInput = document.getElementById('repl-prefix');
  if (preset === 'smb') {
    if (prefixInput.value === 'capsules/') prefixInput.value = '';
    prefixInput.placeholder = 'from the host path, or a directory in the share';
  } else {
    if (prefixInput.value === '') prefixInput.value = 'capsules/';
    prefixInput.placeholder = 'capsules/';
  }

  if (preset === 'local') {
    s3Fields.style.display = 'none';
    endpointLabel.textContent = 'Destination Local Directory / Mount Path';
    endpointInput.placeholder = '/mnt/cold-storage/kyrecovery-vault';
  } else if (preset === 'sftp') {
    s3Fields.style.display = 'block';
    endpointLabel.textContent = 'SSH Host (host or host:port)';
    endpointInput.placeholder = 'nas.lan:22';
  } else if (preset === 'smb') {
    s3Fields.style.display = 'block';
    endpointLabel.textContent = 'SMB Host (host, host:port, or //host/share/dir)';
    endpointInput.placeholder = 'nas.lan  or  //nas.lan/backups/kyrecovery';
    document.getElementById('repl-bucket').placeholder = 'backups';
    document.getElementById('repl-access-key').placeholder = 'user or DOMAIN\\user';
  } else {
    s3Fields.style.display = 'block';
    endpointLabel.textContent = 'S3 Endpoint URL';
    if (preset === 'r2') {
      endpointInput.placeholder = 'https://<account-id>.r2.cloudflarestorage.com';
      document.getElementById('repl-region').value = 'auto';
    } else if (preset === 'minio') {
      endpointInput.placeholder = 'http://localhost:9000';
      document.getElementById('repl-region').value = 'us-east-1';
    } else {
      endpointInput.placeholder = 'https://s3.us-east-1.amazonaws.com';
      document.getElementById('repl-region').value = 'us-east-1';
    }
  }
}

function getReplicationTargetPayload() {
  const preset = document.getElementById('repl-preset').value;
  const type = ['local', 'sftp', 'smb'].includes(preset) ? preset : 's3';

  return {
    name: document.getElementById('repl-name').value.trim(),
    type: type,
    endpoint: document.getElementById('repl-endpoint').value.trim(),
    bucket: document.getElementById('repl-bucket') ? document.getElementById('repl-bucket').value.trim() : '',
    region: document.getElementById('repl-region') ? document.getElementById('repl-region').value.trim() : 'us-east-1',
    access_key: document.getElementById('repl-access-key') ? document.getElementById('repl-access-key').value.trim() : '',
    secret_key: document.getElementById('repl-secret-key') ? document.getElementById('repl-secret-key').value.trim() : '',
    // For SMB a blank directory lets a pasted //host/share/dir supply it.
    prefix: document.getElementById('repl-prefix').value.trim() || (type === 'smb' ? '' : 'capsules/'),
    host_key: document.getElementById('repl-host-key').value.trim(),
    auto_sync: document.getElementById('repl-auto-sync').checked
  };
}

async function testReplicationConnection() {
  const statusBox = document.getElementById('repl-test-status');
  statusBox.style.display = 'block';
  statusBox.style.background = 'var(--bg-input)';
  statusBox.style.color = 'var(--accent-cyan)';
  statusBox.textContent = 'Testing connection and write permissions...';

  const payload = getReplicationTargetPayload();

  try {
    const res = await fetch('/api/replication/targets/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (data.success) {
      statusBox.style.color = 'var(--accent-green)';
      statusBox.textContent = '✓ ' + data.message;
    } else if (data.host_key) {
      // Not trusted yet: show the fingerprint and let the operator confirm it.
      document.getElementById('repl-host-key').value = data.host_key;
      statusBox.style.color = 'var(--accent-yellow, #e0b040)';
      statusBox.textContent = 'Server host key ' + data.host_key + ' filled in. Check it matches the server (ssh-keygen -lf) and test again.';
    } else {
      statusBox.style.color = 'var(--accent-red)';
      statusBox.textContent = '✗ ' + (data.error || 'Connection failed');
    }
  } catch (err) {
    statusBox.style.color = 'var(--accent-red)';
    statusBox.textContent = '✗ Test failed: ' + err.message;
  }
}

async function submitReplicationTarget(e) {
  e.preventDefault();
  const payload = getReplicationTargetPayload();

  try {
    const res = await fetch('/api/replication/targets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.error || 'Failed saving target');
    }

    closeReplicationModal();
    loadReplication();
    loadAudit();
  } catch (err) {
    alert('Failed adding replication target: ' + err.message);
  }
}

async function deleteReplicationTarget(id) {
  if (!confirm(`Delete replication target ${id}?`)) return;

  try {
    const res = await fetch(`/api/replication/targets/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed deleting target');
    loadReplication();
    loadAudit();
  } catch (err) {
    alert('Delete error: ' + err.message);
  }
}

async function syncAllToTarget(targetId) {
  try {
    const res = await fetch('/api/capsules');
    const capsules = await res.json() || [];
    if (capsules.length === 0) {
      alert('No capsules available to sync.');
      return;
    }

    for (const c of capsules) {
      await fetch('/api/replication/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ capsule_id: c.id, target_id: targetId })
      });
    }

    alert(`✓ Replicated ${capsules.length} capsules to offsite vault.`);
    loadReplication();
    loadAudit();
  } catch (err) {
    alert('Sync error: ' + err.message);
  }
}

// 10. Snapshot Diff Inspector
async function openDiffModal() {
  const baseSelect = document.getElementById('diff-base-select');
  const targetSelect = document.getElementById('diff-target-select');
  baseSelect.innerHTML = '<option value="">Loading...</option>';
  targetSelect.innerHTML = '<option value="">Loading...</option>';

  try {
    const res = await fetch('/api/capsules');
    const capsules = await res.json() || [];
    if (capsules.length < 2) {
      alert('You need at least 2 deposited capsules to run a version diff comparison.');
      return;
    }

    const optionsHTML = capsules.map(c => `
      <option value="${esc(c.id)}">${esc(c.id)} (${esc(c.service_name)}, ${(c.size_bytes / 1024).toFixed(1)} KB, ${new Date(c.created_at).toLocaleTimeString()})</option>
    `).join('');

    baseSelect.innerHTML = optionsHTML;
    targetSelect.innerHTML = optionsHTML;

    // Set defaults: base = older, target = newest
    if (capsules.length >= 2) {
      baseSelect.selectedIndex = 1;
      targetSelect.selectedIndex = 0;
    }

    document.getElementById('diff-results-container').style.display = 'none';
    document.getElementById('diff-modal').classList.add('open');
  } catch (err) {
    alert('Error loading capsules: ' + err.message);
  }
}

function closeDiffModal() {
  document.getElementById('diff-modal').classList.remove('open');
}

async function executeSnapshotDiff() {
  const baseID = document.getElementById('diff-base-select').value;
  const targetID = document.getElementById('diff-target-select').value;

  if (!baseID || !targetID) {
    alert('Please select both a base and target capsule to compare.');
    return;
  }
  if (baseID === targetID) {
    alert('Please select two distinct capsule versions to compare.');
    return;
  }

  try {
    const res = await fetch(`/api/capsules/diff?base=${encodeURIComponent(baseID)}&target=${encodeURIComponent(targetID)}`);
    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.error || 'Failed generating version diff');
    }
    const report = await res.json();

    const driftBadgeEl = document.getElementById('diff-drift-badge');
    driftBadgeEl.textContent = report.identical_payload ? 'IDENTICAL' : 'DRIFT DETECTED';
    driftBadgeEl.style.color = report.identical_payload ? 'var(--accent-green)' : 'var(--accent-amber)';

    const fmt = n => (Number(n) > 0 ? '+' : '') + (Number(n) || 0);
    document.getElementById('diff-quorum-delta').textContent = `${fmt(report.threshold_delta)} of ${fmt(report.total_shares_delta)}`;
    document.getElementById('diff-created-at').textContent = new Date(report.target_created_at).toLocaleString();

    document.getElementById('diff-results-container').style.display = 'block';
  } catch (err) {
    alert('Diff inspection error: ' + err.message);
  }
}



