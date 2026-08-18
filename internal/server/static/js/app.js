document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  loadAuthUser();
  loadReadiness();
  loadCapsules();
  loadPairing();
  loadCustodians();
  loadCeremonies();
  loadReplication();
  loadDrills();
  loadAudit();

  // Polling for freshness
  setInterval(() => {
    loadReadiness();
    loadCeremonies();
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

    document.getElementById('metric-readiness').textContent = data.ready ? '100%' : 'NEEDS DRILL';
    document.getElementById('metric-readiness').style.color = data.ready ? 'var(--accent-green)' : 'var(--accent-amber)';
    
    document.getElementById('metric-rto').textContent = data.last_rto_ms >= 0 ? `${data.last_rto_ms} ms` : 'N/A';
    document.getElementById('metric-capsules').textContent = data.capsules_count || 0;
    document.getElementById('metric-custodians').textContent = data.custodians_count || 0;

    const statusPill = document.getElementById('system-status-pill');
    if (data.ready) {
      statusPill.className = 'status-pill ready';
      statusPill.innerHTML = '<span class="dot"></span> READY';
    } else {
      statusPill.className = 'status-pill warning';
      statusPill.innerHTML = '<span class="dot"></span> VERIFICATION NEEDED';
    }

    if (data.last_drill) {
      document.getElementById('last-drill-time').textContent = new Date(data.last_drill.completed_at).toLocaleString();
      document.getElementById('last-drill-status').textContent = data.last_drill.status.toUpperCase();
      document.getElementById('last-drill-status').style.color = data.last_drill.status === 'passed' ? 'var(--accent-green)' : 'var(--accent-red)';
    }
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
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color: var(--text-dim);">No capsules found. Click "Capture Capsule" to generate one.</td></tr>';
      return;
    }

    tbody.innerHTML = capsules.map(c => `
      <tr>
        <td><code>${c.id}</code></td>
        <td><strong>${c.service_name}</strong></td>
        <td><span class="status-pill ready">${c.threshold} of ${c.total_shares} Shares</span></td>
        <td>${(c.size_bytes / 1024).toFixed(1)} KB</td>
        <td><code title="${c.payload_hash}">${c.payload_hash.substring(0, 12)}...</code></td>
        <td>${new Date(c.created_at).toLocaleString()}</td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="openDrillModal('${c.id}', ${c.threshold})">Run Drill</button>
          <a class="btn btn-secondary btn-sm" href="/api/capsules/${c.id}/export-kit?format=html" target="_blank">Export Kit</a>
          <a class="btn btn-secondary btn-sm" href="/api/capsules/${c.id}/download" download>Download</a>
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
        <td><strong>${c.name}</strong></td>
        <td>${c.email}</td>
        <td><code>${c.fingerprint}</code></td>
        <td>${new Date(c.created_at).toLocaleString()}</td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Error fetching custodians:', err);
  }
}

// 4. Drills History
async function loadDrills() {
  const tbody = document.getElementById('drills-table-body');
  if (!tbody) return;

  try {
    const res = await fetch('/api/drills');
    if (!res.ok) return;
    const drills = await res.json() || [];

    if (drills.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--text-dim);">No restore drills executed yet.</td></tr>';
      return;
    }

    tbody.innerHTML = drills.map(d => `
      <tr>
        <td><code>${d.id}</code></td>
        <td><code>${d.capsule_id}</code></td>
        <td><strong>${d.service_name}</strong></td>
        <td>
          <span class="status-pill ${d.status === 'passed' ? 'ready' : 'warning'}">
            <span class="dot"></span> ${d.status.toUpperCase()}
          </span>
        </td>
        <td><strong>${d.duration_ms} ms</strong></td>
        <td>${new Date(d.completed_at).toLocaleString()}</td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Error fetching drills:', err);
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
        <td><strong>#${e.sequence_num}</strong></td>
        <td><code>${e.action}</code></td>
        <td>${e.actor}</td>
        <td><code>${e.target_id}</code></td>
        <td><code title="${e.event_hash}">${e.event_hash.substring(0, 14)}...</code></td>
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
      badge.textContent = `✗ Chain Broken at Sequence ${data.broken_seq}: ${data.error}`;
      badge.style.color = 'var(--accent-red)';
    }
  } catch (err) {
    badge.textContent = 'Chain verification error';
    badge.style.color = 'var(--accent-red)';
  }
}

// Capture Modal
function openCaptureModal() {
  document.getElementById('capture-modal').classList.add('open');
}

function closeCaptureModal() {
  document.getElementById('capture-modal').classList.remove('open');
}

async function submitCapture(e) {
  e.preventDefault();
  const serviceName = document.getElementById('capture-service').value;
  const threshold = parseInt(document.getElementById('capture-threshold').value, 10);
  const totalShares = parseInt(document.getElementById('capture-shares').value, 10);

  const btn = document.getElementById('btn-capture-submit');
  btn.disabled = true;
  btn.textContent = 'Capturing & Encrypting...';

  try {
    const res = await fetch('/api/capsules/capture', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service_name: serviceName, threshold, total_shares: totalShares })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to capture capsule');

    closeCaptureModal();
    
    // Display generated shares dialog to custodian
    showSharesDialog(data.manifest.capsule_id, data.shares);

    loadCapsules();
    loadReadiness();
    loadAudit();
  } catch (err) {
    alert('Capture error: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Capture Capsule';
  }
}

function showSharesDialog(capsuleId, shares) {
  const modal = document.getElementById('shares-modal');
  const sharesList = document.getElementById('shares-display-list');
  sharesList.value = (shares || []).map(s => `${s.index}-${s.value_hex}`).join('\n');
  document.getElementById('shares-modal-capsule-id').textContent = capsuleId;
  modal.classList.add('open');
}

function closeSharesModal() {
  document.getElementById('shares-modal').classList.remove('open');
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

// Drill Modal
let activeDrillCapsuleId = '';
function openDrillModal(capsuleId, threshold) {
  activeDrillCapsuleId = capsuleId;
  document.getElementById('drill-modal-capsule-id').textContent = capsuleId;
  document.getElementById('drill-threshold-msg').textContent = `Enter at least ${threshold} custodian shares (one per line, format: index-hex)`;
  document.getElementById('drill-shares-input').value = '';
  document.getElementById('drill-result-box').style.display = 'none';
  document.getElementById('drill-modal').classList.add('open');
}

function closeDrillModal() {
  document.getElementById('drill-modal').classList.remove('open');
}

async function submitDrill(e) {
  e.preventDefault();
  const rawShares = document.getElementById('drill-shares-input').value.trim();
  const shares = rawShares.split('\n').map(s => s.trim()).filter(s => s.length > 0);

  const btn = document.getElementById('btn-run-drill-submit');
  btn.disabled = true;
  btn.textContent = 'Executing Ephemeral Drill...';

  try {
    const res = await fetch('/api/drills/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ capsule_id: activeDrillCapsuleId, shares: shares })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Drill execution failed');

    const resultBox = document.getElementById('drill-result-box');
    resultBox.style.display = 'block';

    const checksHtml = (data.checks || []).map(c => `
      <div class="check-item">
        <span class="check-badge ${c.passed ? 'pass' : 'fail'}">${c.passed ? 'PASS' : 'FAIL'}</span>
        <div>
          <strong>${c.name}</strong>: ${c.message}
        </div>
      </div>
    `).join('');

    resultBox.innerHTML = `
      <div style="margin-bottom: 12px; font-weight: bold; color: ${data.passed ? 'var(--accent-green)' : 'var(--accent-red)'}">
        Result: ${data.passed ? 'VERIFICATION PASSED' : 'VERIFICATION FAILED'} (Duration: ${data.duration_ms} ms)
      </div>
      <div>${checksHtml}</div>
    `;

    loadDrills();
    loadReadiness();
    loadAudit();
  } catch (err) {
    alert('Drill Error: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run Isolated Drill';
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
        <td><strong>${p.app_name}</strong></td>
        <td><code>${p.service_name}</code></td>
        <td>
          ${p.status === 'pending' ? `<span style="font-family: var(--font-mono); font-size: 14px; font-weight: bold; color: var(--accent-cyan); background: var(--bg-card); padding: 2px 8px; border-radius: 4px; border: 1px solid var(--border-color);">${p.pairing_code}</span>` : `<code title="${p.api_token}">${p.api_token.substring(0, 16)}...</code>`}
        </td>
        <td>
          <span class="status-pill ${p.status === 'paired' ? 'ready' : (p.status === 'pending' ? 'warning' : 'danger')}">
            <span class="dot"></span> ${p.status.toUpperCase()}
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
      loadDrills();
      loadAudit();
      loadCeremonies();
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

// 8. Quorum Ceremony Management
let activeCeremonySessionId = null;

async function loadCeremonies() {
  const tbody = document.getElementById('ceremonies-table-body');
  if (!tbody) return;

  try {
    const res = await fetch('/api/ceremonies');
    if (!res.ok) return;
    const list = await res.json() || [];

    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color: var(--text-dim);">No active quorum recovery ceremonies. Click "+ Initiate Recovery Ceremony" to begin a multi-party ceremony.</td></tr>';
      return;
    }

    tbody.innerHTML = list.map(s => {
      const pct = Math.min(100, Math.round((s.submitted_count / s.threshold) * 100));
      const isQuorum = s.status === 'quorum_reached';
      const isExecuted = s.status === 'executed';
      const isCancelled = s.status === 'cancelled' || s.status === 'expired';
      const participantsStr = (s.participants || []).map(p => `<span class="pill-badge" title="Share Index ${p.share_index}">👤 ${p.custodian_name}</span>`).join(' ') || '<span style="color: var(--text-dim);">None yet</span>';

      return `
        <tr>
          <td>
            <strong>${s.purpose}</strong><br>
            <code style="font-size: 11px;">${s.id}</code>
          </td>
          <td><code>${s.capsule_id}</code></td>
          <td style="min-width: 140px;">
            <div style="font-size: 12px; font-weight: bold; margin-bottom: 4px;">
              ${s.submitted_count} / ${s.threshold} Shares (${pct}%)
            </div>
            <div style="background: var(--bg-card); height: 8px; border-radius: 4px; overflow: hidden; border: 1px solid var(--border-color);">
              <div style="background: ${isQuorum ? 'var(--accent-green)' : 'var(--accent-cyan)'}; width: ${pct}%; height: 100%; transition: width 0.3s ease;"></div>
            </div>
          </td>
          <td>
            <span class="status-pill ${isExecuted ? 'ready' : (isQuorum ? 'ready' : (isCancelled ? 'danger' : 'warning'))}">
              <span class="dot"></span> ${s.status.toUpperCase().replace('_', ' ')}
            </span>
          </td>
          <td>${participantsStr}</td>
          <td><span style="font-size: 12px;">${new Date(s.expires_at).toLocaleTimeString()}</span></td>
          <td>
            ${s.status === 'gathering' ? `
              <button class="btn btn-secondary btn-sm" onclick="openCeremonySubmitModal('${s.id}')">Contribute Share</button>
              <button class="btn btn-sm" style="color: var(--accent-red); margin-left: 4px;" onclick="cancelCeremony('${s.id}')">Cancel</button>
            ` : (isQuorum ? `
              <button class="btn btn-primary btn-sm" onclick="executeCeremony('${s.id}')">⚡ Execute Drill</button>
            ` : `<span style="color: var(--text-dim); font-size: 12px;">Closed</span>`)}
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Error loading ceremonies:', err);
  }
}

async function openCeremonyCreateModal() {
  const select = document.getElementById('ceremony-capsule-select');
  select.innerHTML = '<option value="">Loading capsules...</option>';

  try {
    const res = await fetch('/api/capsules');
    const capsules = await res.json() || [];
    if (capsules.length === 0) {
      select.innerHTML = '<option value="">No capsules available</option>';
    } else {
      select.innerHTML = capsules.map(c => `
        <option value="${c.id}">${c.id} (${c.service_name}, Quorum: ${c.threshold}/${c.total_shares})</option>
      `).join('');
    }
  } catch (err) {
    select.innerHTML = '<option value="">Failed loading capsules</option>';
  }

  document.getElementById('ceremony-create-modal').classList.add('open');
}

function closeCeremonyCreateModal() {
  document.getElementById('ceremony-create-modal').classList.remove('open');
}

async function submitCreateCeremony(e) {
  e.preventDefault();
  const capId = document.getElementById('ceremony-capsule-select').value;
  const purpose = document.getElementById('ceremony-purpose').value;
  const ttl = parseInt(document.getElementById('ceremony-ttl').value, 10);

  try {
    const res = await fetch('/api/ceremonies/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ capsule_id: capId, purpose: purpose, ttl_minutes: ttl })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed creating ceremony');

    closeCeremonyCreateModal();
    loadCeremonies();
    loadAudit();
  } catch (err) {
    alert('Ceremony error: ' + err.message);
  }
}

function openCeremonySubmitModal(sessionId) {
  activeCeremonySessionId = sessionId;
  document.getElementById('ceremony-submit-session-id').textContent = sessionId;
  document.getElementById('ceremony-custodian-name').value = currentUser ? currentUser.name : '';
  document.getElementById('ceremony-share-input').value = '';
  document.getElementById('ceremony-submit-modal').classList.add('open');
}

function closeCeremonySubmitModal() {
  document.getElementById('ceremony-submit-modal').classList.remove('open');
}

async function submitCeremonyShare(e) {
  e.preventDefault();
  const name = document.getElementById('ceremony-custodian-name').value.trim();
  const share = document.getElementById('ceremony-share-input').value.trim();

  try {
    const res = await fetch('/api/ceremonies/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: activeCeremonySessionId, custodian_name: name, share: share })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed submitting share');

    closeCeremonySubmitModal();
    loadCeremonies();
    loadAudit();
    if (data.status === 'quorum_reached') {
      alert(`🎉 Quorum reached for ceremony ${activeCeremonySessionId}! You can now execute the restore drill.`);
    }
  } catch (err) {
    alert('Share submission error: ' + err.message);
  }
}

async function executeCeremony(sessionId) {
  if (!confirm(`Execute quorum restore drill for ceremony ${sessionId}?`)) return;

  try {
    const res = await fetch('/api/ceremonies/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Ceremony execution failed');

    alert(`✓ Quorum drill executed successfully! Result: ${data.drill_summary.passed ? 'PASSED' : 'FAILED'} in ${data.drill_summary.duration_ms}ms.`);
    loadCeremonies();
    loadDrills();
    loadReadiness();
    loadAudit();
  } catch (err) {
    alert('Execution error: ' + err.message);
  }
}

async function cancelCeremony(sessionId) {
  if (!confirm(`Are you sure you want to cancel ceremony ${sessionId}?`)) return;

  try {
    const res = await fetch('/api/ceremonies/cancel', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId })
    });
    if (!res.ok) throw new Error('Failed cancelling ceremony');
    loadCeremonies();
    loadAudit();
  } catch (err) {
    alert('Error cancelling ceremony: ' + err.message);
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
        <td><strong>${t.name}</strong></td>
        <td><span class="pill-badge">${t.type.toUpperCase()}</span></td>
        <td>
          <code style="font-size: 12px;">${t.type === 'local' ? t.endpoint : (t.bucket + ' (' + t.region + ')')}</code>
        </td>
        <td>
          <span class="status-pill ${t.auto_sync ? 'ready' : 'warning'}">
            <span class="dot"></span> ${t.auto_sync ? 'ENABLED' : 'MANUAL'}
          </span>
        </td>
        <td>
          <span class="status-pill ${t.status === 'active' ? 'ready' : (t.status === 'error' ? 'danger' : 'warning')}">
            <span class="dot"></span> ${t.status.toUpperCase()}
          </span>
        </td>
        <td>${t.last_sync_at ? new Date(t.last_sync_at).toLocaleString() : '<span style="color: var(--text-dim);">Never</span>'}</td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="syncAllToTarget('${t.id}')">Sync All</button>
          <button class="btn btn-sm" style="color: var(--accent-red); margin-left: 4px;" onclick="deleteReplicationTarget('${t.id}')">Delete</button>
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
        <td><code>${l.target_id}</code></td>
        <td><code>${l.capsule_id}</code></td>
        <td>${(l.bytes_transferred / 1024).toFixed(1)} KB</td>
        <td>${l.duration_ms} ms</td>
        <td>
          <span class="status-pill ${l.status === 'success' ? 'ready' : 'danger'}">
            <span class="dot"></span> ${l.status.toUpperCase()}
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

  if (preset === 'local') {
    s3Fields.style.display = 'none';
    endpointLabel.textContent = 'Destination Local Directory / Mount Path';
    endpointInput.placeholder = '/mnt/cold-storage/kyrecovery-vault';
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
  const type = preset === 'local' ? 'local' : 's3';

  return {
    name: document.getElementById('repl-name').value.trim(),
    type: type,
    endpoint: document.getElementById('repl-endpoint').value.trim(),
    bucket: document.getElementById('repl-bucket') ? document.getElementById('repl-bucket').value.trim() : '',
    region: document.getElementById('repl-region') ? document.getElementById('repl-region').value.trim() : 'us-east-1',
    access_key: document.getElementById('repl-access-key') ? document.getElementById('repl-access-key').value.trim() : '',
    secret_key: document.getElementById('repl-secret-key') ? document.getElementById('repl-secret-key').value.trim() : '',
    prefix: document.getElementById('repl-prefix').value.trim() || 'capsules/',
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

// 10. Snapshot Diff & Rollback Inspector
let selectedDiffTargetId = null;

async function openDiffModal() {
  const baseSelect = document.getElementById('diff-base-select');
  const targetSelect = document.getElementById('diff-target-select');
  baseSelect.innerHTML = '<option value="">Loading...</option>';
  targetSelect.innerHTML = '<option value="">Loading...</option>';

  try {
    const res = await fetch('/api/capsules');
    const capsules = await res.json() || [];
    if (capsules.length < 2) {
      alert('You need at least 2 capsules captured to run a version diff comparison.');
      return;
    }

    const optionsHTML = capsules.map(c => `
      <option value="${c.id}">${c.id} (${c.service_name}, ${(c.size_bytes / 1024).toFixed(1)} KB, ${new Date(c.created_at).toLocaleTimeString()})</option>
    `).join('');

    baseSelect.innerHTML = optionsHTML;
    targetSelect.innerHTML = optionsHTML;

    // Set defaults: base = older, target = newest
    if (capsules.length >= 2) {
      baseSelect.selectedIndex = 1;
      targetSelect.selectedIndex = 0;
    }

    document.getElementById('diff-results-container').style.display = 'none';
    document.getElementById('btn-rollback-target').style.display = 'none';
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

  selectedDiffTargetId = targetID;

  try {
    const res = await fetch(`/api/capsules/diff?base=${encodeURIComponent(baseID)}&target=${encodeURIComponent(targetID)}`);
    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.error || 'Failed generating version diff');
    }
    const report = await res.json();

    // 1. Metric Badges
    const filesDeltaEl = document.getElementById('diff-files-delta');
    filesDeltaEl.textContent = (report.total_files_delta >= 0 ? '+' : '') + report.total_files_delta;
    filesDeltaEl.style.color = report.total_files_delta === 0 ? 'var(--text-main)' : (report.total_files_delta > 0 ? 'var(--accent-green)' : 'var(--accent-red)');

    const sizeDeltaEl = document.getElementById('diff-size-delta');
    const kbDelta = (report.total_size_delta / 1024).toFixed(2);
    sizeDeltaEl.textContent = (report.total_size_delta >= 0 ? '+' : '') + kbDelta + ' KB';
    sizeDeltaEl.style.color = report.total_size_delta === 0 ? 'var(--text-main)' : (report.total_size_delta > 0 ? 'var(--accent-cyan)' : 'var(--accent-red)');

    const driftBadgeEl = document.getElementById('diff-drift-badge');
    if (report.identical_payload) {
      driftBadgeEl.textContent = 'IDENTICAL';
      driftBadgeEl.style.color = 'var(--accent-green)';
    } else {
      driftBadgeEl.textContent = 'DRIFT DETECTED';
      driftBadgeEl.style.color = 'var(--accent-amber)';
    }

    // 2. Files Diff Table
    const tbody = document.getElementById('diff-files-tbody');
    if (!report.file_diffs || report.file_diffs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-dim);">No file changes between snapshots.</td></tr>';
    } else {
      tbody.innerHTML = report.file_diffs.map(f => {
        let pillClass = 'ready';
        if (f.status === 'modified') pillClass = 'warning';
        if (f.status === 'removed') pillClass = 'danger';
        if (f.status === 'added') pillClass = 'ready';

        const deltaFormatted = (f.size_delta >= 0 ? '+' : '') + f.size_delta + ' B';

        return `
          <tr>
            <td><code>${f.path}</code></td>
            <td><span class="status-pill ${pillClass}"><span class="dot"></span> ${f.status.toUpperCase()}</span></td>
            <td>${f.old_size_bytes} B</td>
            <td>${f.new_size_bytes} B</td>
            <td style="font-family: var(--font-mono);">${deltaFormatted}</td>
          </tr>
        `;
      }).join('');
    }

    // 3. Dependencies
    const depContainer = document.getElementById('diff-dependencies-list');
    if (!report.dependency_diffs || report.dependency_diffs.length === 0) {
      depContainer.innerHTML = '<em>No environment or port configuration drift detected.</em>';
    } else {
      depContainer.innerHTML = report.dependency_diffs.map(d => {
        let color = 'var(--text-dim)';
        if (d.status === 'added') color = 'var(--accent-green)';
        if (d.status === 'removed') color = 'var(--accent-red)';
        return `<div style="margin-bottom: 4px;"><strong style="color: ${color};">[${d.status.toUpperCase()}]</strong> ${d.type.toUpperCase()}: <code>${d.name}</code></div>`;
      }).join('');
    }

    document.getElementById('diff-results-container').style.display = 'block';
    document.getElementById('btn-rollback-target').style.display = 'inline-flex';
  } catch (err) {
    alert('Diff inspection error: ' + err.message);
  }
}

function triggerRollbackDrill() {
  if (!selectedDiffTargetId) return;
  closeDiffModal();
  openDrillModal(selectedDiffTargetId);
}



