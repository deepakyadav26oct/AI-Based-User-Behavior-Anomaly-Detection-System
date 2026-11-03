/**
 * Interactive UI behaviors, AJAX handlers, and Modals for CyberGuard Sentinel
 */

// Format Risk Badge Helper
function getRiskBadge(score, level) {
  if (level === 'High' || score >= 70) {
    return `<span class="badge-risk-high"><i class="fas fa-biohazard me-1"></i>HIGH (${score})</span>`;
  } else if (level === 'Medium' || score >= 30) {
    return `<span class="badge-risk-med"><i class="fas fa-exclamation-triangle me-1"></i>MED (${score})</span>`;
  } else {
    return `<span class="badge-risk-low"><i class="fas fa-check-circle me-1"></i>LOW (${score})</span>`;
  }
}

// Activity Detail Inspector Modal
function inspectActivity(activityId) {
  const modalEl = document.getElementById('activityDetailModal');
  if (!modalEl) return;

  const modal = new bootstrap.Modal(modalEl);
  const container = document.getElementById('activityModalContent');
  container.innerHTML = `<div class="text-center py-4"><div class="spinner-border text-info" role="status"></div></div>`;
  modal.show();

  fetch(`/api/activities/${activityId}`)
    .then(r => r.json())
    .then(data => {
      const act = data.activity;
      const det = data.detection || {};
      const reasonsList = (det.reasons || []).map(r => `<li>${r}</li>`).join('');
      const flagsList = (det.rule_flags || []).map(f => `<span class="badge bg-dark border border-secondary me-1 mb-1 font-monospace">${f}</span>`).join('');
      const mitreList = (data.mitre_techniques || []).map(m => 
        `<a href="${m.url}" target="_blank" rel="noopener" class="badge bg-danger text-light me-1 mb-1 text-decoration-none font-monospace"><i class="fas fa-crosshairs me-1"></i>${m.id}: ${m.name}</a>`
      ).join('');

      container.innerHTML = `
        <div class="row g-3">
          <div class="col-md-6">
            <h6 class="text-uppercase text-secondary font-monospace" style="font-size: 0.75rem;">Authentication Telemetry</h6>
            <table class="table table-sm table-dark table-borderless font-monospace" style="font-size: 0.8rem;">
              <tr><td class="text-secondary">Principal:</td><td><strong class="text-info">${act.username}</strong></td></tr>
              <tr><td class="text-secondary">Status:</td><td><span class="badge ${act.login_status === 'SUCCESS' ? 'bg-success' : 'bg-danger'}">${act.login_status}</span></td></tr>
              <tr><td class="text-secondary">Timestamp:</td><td>${act.timestamp}</td></tr>
              <tr><td class="text-secondary">Source IP:</td><td>${act.ip_address}</td></tr>
              <tr><td class="text-secondary">Origin Location:</td><td>${act.location || 'N/A'}</td></tr>
              <tr><td class="text-secondary">Operating System:</td><td>${act.operating_system}</td></tr>
              <tr><td class="text-secondary">Client Browser:</td><td>${act.browser}</td></tr>
              <tr><td class="text-secondary">Hardware Profile:</td><td>${act.device_info}</td></tr>
              <tr><td class="text-secondary">Target Resource:</td><td><code>${act.accessed_resource}</code></td></tr>
              <tr><td class="text-secondary">Asset Sensitivity:</td><td><span class="badge bg-secondary">${act.resource_sensitivity}</span></td></tr>
              <tr><td class="text-secondary">Session Duration:</td><td>${Math.round(act.session_duration / 60)} mins</td></tr>
              <tr><td class="text-secondary">Failed Attempt Count:</td><td>${act.failed_login_count}</td></tr>
            </table>
          </div>
          <div class="col-md-6 border-start border-secondary">
            <h6 class="text-uppercase text-secondary font-monospace" style="font-size: 0.75rem;">AI Anomaly & Risk Evaluation</h6>
            <div class="mb-3 p-3 rounded" style="background: rgba(0,0,0,0.3); border: 1px solid #212c3d;">
              <div class="d-flex justify-content-between align-items-center mb-2">
                <span class="text-secondary small">Calculated Risk Score:</span>
                ${getRiskBadge(det.calculated_risk_score, det.risk_level)}
              </div>
              <div class="progress" style="height: 8px; background: #161b26;">
                <div class="progress-bar ${det.calculated_risk_score >= 70 ? 'bg-danger' : det.calculated_risk_score >= 30 ? 'bg-warning' : 'bg-success'}" 
                     style="width: ${det.calculated_risk_score}%;"></div>
              </div>
              <div class="d-flex justify-content-between small text-secondary mt-1">
                <span>0 (Low)</span><span>50</span><span>100 (Critical)</span>
              </div>
            </div>

            <table class="table table-sm table-dark table-borderless font-monospace" style="font-size: 0.8rem;">
              <tr><td class="text-secondary">Isolation Forest Decision:</td><td>${det.is_ml_anomaly ? '<span class="text-danger fw-bold">ANOMALY OUTLIER (-1)</span>' : '<span class="text-success">NORMAL INLIER (+1)</span>'}</td></tr>
              <tr><td class="text-secondary">ML Outlier Score:</td><td><code>${det.ml_anomaly_score || 0.0}</code> (Range: 0.0-1.0)</td></tr>
              <tr><td class="text-secondary">Evaluation Time:</td><td>${det.evaluated_at || 'N/A'}</td></tr>
            </table>

            <div class="mb-2">
              <label class="text-secondary small d-block mb-1">Triggered Heuristic Flags:</label>
              <div>${flagsList || '<span class="text-muted small">No security rules triggered.</span>'}</div>
            </div>

            <div class="mb-2">
              <label class="text-secondary small d-block mb-1 font-monospace"><i class="fas fa-chess-board text-info me-1"></i>MITRE ATT&CK Correlation:</label>
              <div>${mitreList || '<span class="text-muted small">None correlated</span>'}</div>
            </div>

            <div>
              <label class="text-secondary small d-block mb-1">Explainable Detection Reasons:</label>
              <ul class="small ps-3 text-light" style="font-size: 0.78rem;">${reasonsList || '<li>Verified normal profile behavior.</li>'}</ul>
            </div>
          </div>
        </div>
      `;
    })
    .catch(err => {
      container.innerHTML = `<div class="alert alert-danger">Failed to fetch activity telemetry: ${err}</div>`;
    });
}

// User Profile Baseline Inspector Modal
function inspectUserProfile(userId) {
  const modalEl = document.getElementById('userProfileModal');
  if (!modalEl) return;

  const modal = new bootstrap.Modal(modalEl);
  const container = document.getElementById('userProfileContent');
  container.innerHTML = `<div class="text-center py-4"><div class="spinner-border text-info" role="status"></div></div>`;
  modal.show();

  fetch(`/users/${userId}/profile-data`)
    .then(r => r.json())
    .then(data => {
      const u = data.user;
      const p = data.profile;

      const ips = (p.known_ips || []).map(ip => `<span class="badge bg-dark border border-secondary me-1 mb-1 font-monospace">${ip}</span>`).join('');
      const devices = (p.known_devices || []).map(d => `<span class="badge bg-dark border border-secondary me-1 mb-1 font-monospace">${d}</span>`).join('');
      const hours = (p.typical_login_hours || []).sort((a,b)=>a-b).map(h => `<span class="badge bg-primary me-1 mb-1 font-monospace">${h}:00</span>`).join('');
      const resources = (p.typical_resources || []).map(res => `<span class="badge bg-secondary me-1 mb-1 font-monospace">${res}</span>`).join('');

      container.innerHTML = `
        <div class="p-2">
          <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary">
            <div>
              <h5 class="text-info mb-0">${u.username}</h5>
              <small class="text-secondary">${u.email} | ${u.department} | Role: <strong>${u.role.toUpperCase()}</strong></small>
            </div>
            <div>
              ${p.is_baseline_locked 
                ? '<span class="badge bg-danger"><i class="fas fa-lock me-1"></i>BASELINE LOCKED</span>'
                : '<span class="badge bg-success"><i class="fas fa-lock-open me-1"></i>CONTINUOUS LEARNING ACTIVE</span>'}
            </div>
          </div>

          <div class="row g-3">
            <div class="col-md-6">
              <label class="text-secondary small fw-bold">Verified Known IP Addresses:</label>
              <div class="p-2 rounded bg-dark border border-secondary mb-3">${ips || '<span class="text-muted small">None recorded yet</span>'}</div>

              <label class="text-secondary small fw-bold">Verified Hardware / Devices:</label>
              <div class="p-2 rounded bg-dark border border-secondary mb-3">${devices || '<span class="text-muted small">None recorded yet</span>'}</div>
            </div>
            <div class="col-md-6">
              <label class="text-secondary small fw-bold">Typical Business Login Hours:</label>
              <div class="p-2 rounded bg-dark border border-secondary mb-3">${hours || '<span class="text-muted small">Standard default schedule</span>'}</div>

              <label class="text-secondary small fw-bold">Typical Resources Accessed:</label>
              <div class="p-2 rounded bg-dark border border-secondary mb-3">${resources || '<span class="text-muted small">Standard defaults</span>'}</div>
            </div>
          </div>

          <div class="row g-2 text-center mt-2 pt-2 border-top border-secondary">
            <div class="col-4">
              <div class="p-2 bg-dark rounded border border-secondary">
                <span class="text-secondary small d-block">Total Successful Logins</span>
                <strong class="text-light">${p.total_logins}</strong>
              </div>
            </div>
            <div class="col-4">
              <div class="p-2 bg-dark rounded border border-secondary">
                <span class="text-secondary small d-block">Failed Login Attempts</span>
                <strong class="text-warning">${p.total_failed_logins}</strong>
              </div>
            </div>
            <div class="col-4">
              <div class="p-2 bg-dark rounded border border-secondary">
                <span class="text-secondary small d-block">Avg Session Duration</span>
                <strong class="text-info">${Math.round(p.avg_session_duration / 60)} mins</strong>
              </div>
            </div>
          </div>
        </div>
      `;
    })
    .catch(err => {
      container.innerHTML = `<div class="alert alert-danger">Error loading user profile: ${err}</div>`;
    });
}

// Live Account Defense Mode Toggle Handler
function toggleLiveDefenseMode(isChecked) {
  const badge = document.getElementById('modeStatusBadge');
  const desc = document.getElementById('modeStatusDesc');
  if (isChecked) {
    if (badge) {
      badge.className = 'badge bg-danger text-white font-monospace';
      badge.innerHTML = '<i class="fas fa-bolt me-1"></i>LIVE ACCOUNT DEFENSE MODE';
    }
    if (desc) {
      desc.innerHTML = '<strong class="text-danger"><i class="fas fa-triangle-exclamation me-1"></i>WARNING: Live Mode is Active!</strong> Attacks will execute directly against the selected account, triggering real SOAR lockdowns, live Threat Map pins, and immediate dashboard alerts.';
    }
  } else {
    if (badge) {
      badge.className = 'badge bg-secondary font-monospace';
      badge.innerHTML = 'LAB MODE (SIMULATED)';
    }
    if (desc) {
      desc.innerHTML = 'Simulated events are tagged with <span class="badge-simulated font-monospace">IS_SIMULATED = TRUE</span> (dry-run without locking accounts). Toggle <strong>Live Mode</strong> to execute real SOAR lockdowns and live dashboard alerts.';
    }
  }
}

// Security Simulation Handler
function runScenarioSimulation(scenarioKey) {
  const resultCard = document.getElementById('simulationLiveResult');
  const userSelect = document.getElementById('simulationTargetUser');
  const targetUsername = userSelect ? userSelect.value : '';
  const liveToggle = document.getElementById('liveModeToggle');
  const isLive = liveToggle ? liveToggle.checked : false;

  if (resultCard) {
    resultCard.innerHTML = `
      <div class="cyber-card p-4 text-center">
        <div class="spinner-border text-info mb-2" role="status"></div>
        <div class="text-secondary font-monospace small">Executing AI Anomaly Detection Pipeline & Contextual Scoring...</div>
      </div>
    `;
    resultCard.scrollIntoView({ behavior: 'smooth' });
  }

  fetch('/api/simulation/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario: scenarioKey, username: targetUsername, live_mode: isLive })
  })
    .then(r => r.json())
    .then(res => {
      if (!resultCard) return;

      const reasons = res.reasons.map(r => `<li>${r}</li>`).join('');
      const flags = res.rule_flags.map(f => `<span class="badge bg-dark border border-secondary font-monospace me-1">${f}</span>`).join('');
      const eventBadge = res.live_mode
        ? `<span class="badge bg-danger text-white text-uppercase me-2"><i class="fas fa-bolt me-1"></i>LIVE ACCOUNT SOAR ENGAGED</span>`
        : `<span class="badge-simulated text-uppercase me-2"><i class="fas fa-flask me-1"></i>SIMULATED EVENT</span>`;

      resultCard.innerHTML = `
        <div class="cyber-card ${res.live_mode ? 'border-danger' : 'border-info'} p-4" style="box-shadow: 0 0 25px ${res.live_mode ? 'rgba(239, 68, 68, 0.3)' : 'rgba(0, 242, 254, 0.2)'};">
          <div class="d-flex justify-content-between align-items-center pb-3 mb-3 border-bottom border-secondary">
            <div>
              ${eventBadge}
              <h5 class="d-inline text-light fw-bold">${res.scenario_title}</h5>
            </div>
            <div>
              ${getRiskBadge(res.calculated_risk_score, res.risk_level)}
            </div>
          </div>

          <div class="row g-3">
            <div class="col-md-5">
              <h6 class="text-secondary font-monospace small text-uppercase">Ingested Event Parameters</h6>
              <ul class="list-unstyled font-monospace small text-secondary">
                <li><strong class="text-info">Target Principal:</strong> ${res.username}</li>
                <li><strong class="text-light">Source IP:</strong> ${res.ip_address}</li>
                <li><strong class="text-light">Origin Location:</strong> <span class="badge bg-dark border border-secondary text-info"><i class="fas fa-location-dot me-1"></i>${res.city || 'N/A'}, ${res.country || 'N/A'}</span></li>
                <li><strong class="text-light">Device / Hardware:</strong> ${res.device_info}</li>
                <li><strong class="text-light">Client Environment:</strong> ${res.operating_system} | ${res.browser}</li>
                <li><strong class="text-light">Resource Target:</strong> <code>${res.accessed_resource}</code></li>
                <li><strong class="text-light">Status:</strong> <span class="badge ${res.login_status === 'SUCCESS' ? 'bg-success' : 'bg-danger'}">${res.login_status}</span></li>
              </ul>
            </div>

            <div class="col-md-7 border-start border-secondary">
              <h6 class="text-secondary font-monospace small text-uppercase">Detection Pipeline Analysis</h6>
              <div class="d-flex align-items-center gap-3 mb-2 font-monospace small">
                <div>ML Outlier Flag: <strong>${res.is_ml_anomaly ? '<span class="text-danger">ANOMALOUS (-1)</span>' : '<span class="text-success">NORMAL (+1)</span>'}</strong></div>
                <div>ML Score: <code>${res.ml_anomaly_score.toFixed(4)}</code></div>
                <div>Latency: <span class="text-info">${res.ml_latency_ms.toFixed(2)} ms</span></div>
              </div>

              ${res.travel_evaluation && res.travel_evaluation.is_impossible_travel ? `
                <div class="alert py-2 px-3 small my-2 font-monospace" style="background: rgba(255, 51, 102, 0.22); border: 1.5px solid #ff3366; color: #ffe4e6; box-shadow: 0 0 12px rgba(255, 51, 102, 0.25);">
                  <i class="fas fa-plane-circle-exclamation me-1" style="color: #ff4d6d !important;"></i>
                  <strong style="color: #ffffff !important; font-weight: 700;">CRITICAL IMPOSSIBLE TRAVEL:</strong> 
                  <span style="color: #ffe4e6;">${res.travel_evaluation.distance_km} km traversed in ${res.travel_evaluation.time_delta_mins} mins</span>
                  <span class="badge ms-1" style="background: #ff3366; color: #ffffff; font-weight: 700;">Speed: ${res.travel_evaluation.velocity_kmh} km/h</span>
                </div>
              ` : ''}

              <div class="mb-2">
                <span class="small text-secondary d-block">Security Rule Flags:</span>
                <div>${flags || '<span class="text-muted small">None</span>'}</div>
              </div>

              <div class="mb-2">
                <span class="small text-secondary d-block">Flagged Explanations:</span>
                <ul class="small ps-3 text-light" style="font-size: 0.8rem;">${reasons}</ul>
              </div>

              <div class="p-2 rounded bg-dark border border-secondary small mb-2">
                <i class="fas fa-shield-alt text-info me-1"></i>
                Baseline Safeguard Protection: <em>${res.baseline_msg}</em>
              </div>

              ${res.account_locked ? `
                <div class="alert py-2 px-3 small my-2 font-monospace" style="background: rgba(255, 51, 102, 0.25); border: 1.5px solid #ff3366; color: #ffe4e6; box-shadow: 0 0 15px rgba(255, 51, 102, 0.35);">
                  <i class="fas fa-lock me-1" style="color: #ff4d6d !important;"></i>
                  <strong style="color: #ffffff !important;">LIVE SOAR LOCKDOWN EXECUTED:</strong> Account <strong>${res.username}</strong> has been locked down by Sentinel AI! Subsequent logins at <code>/login</code> will be blocked until unlocked in User Management.
                </div>
              ` : ''}

              ${res.alert_raised 
                ? `<div class="alert mt-3 py-2 px-3 small mb-0 font-monospace" style="background: rgba(255, 51, 102, 0.22); border: 1.5px solid #ff3366; color: #ffe4e6;"><i class="fas fa-bell me-1" style="color: #ff4d6d !important;"></i><strong style="color: #ffffff !important;">Security Alert Dispatched!</strong> Alert #${res.alert_id} was generated and dispatched to the SOC triage queue.</div>` 
                : `<div class="alert mt-3 py-2 px-3 small mb-0 font-monospace" style="background: rgba(0, 240, 118, 0.2); border: 1.5px solid #00f076; color: #dcfce7;"><i class="fas fa-check me-1" style="color: #00f076 !important;"></i><strong style="color: #ffffff !important;">Nominal Event:</strong> Risk score within normal bounds. No alert dispatched.</div>`}
            </div>
          </div>
        </div>
      `;
    })
    .catch(err => {
      resultCard.innerHTML = `<div class="alert alert-danger">Simulation failed: ${err}</div>`;
    });
}

// ==========================================
// Server-Sent Events (SSE) Live Telemetry Stream
// ==========================================
function initSSEStream() {
  const ssePulse = document.getElementById('ssePulseDot');
  const sseStatus = document.getElementById('sseStatusBadge');
  const sseTicker = document.getElementById('sseLatestEventText');
  const alertsTableBody = document.getElementById('recentAlertsTableBody');

  if (!sseStatus) return; // Not on the dashboard overview page

  const evtSource = new EventSource('/api/stream/events');

  evtSource.addEventListener('connected', function(e) {
    if (ssePulse) ssePulse.className = 'spinner-grow spinner-grow-sm text-success';
    if (sseStatus) sseStatus.innerHTML = 'LIVE TELEMETRY STREAM: CONNECTED';
  });

  evtSource.addEventListener('activity', function(e) {
    try {
      const act = JSON.parse(e.data);
      if (sseTicker) {
        const simTag = act.is_simulated ? '[SIM] ' : '';
        const lockTag = act.account_locked ? ' • [AI LOCKED]' : '';
        sseTicker.innerHTML = `<span class="text-info">${act.timestamp}</span> &mdash; ${simTag}<strong>${act.username}</strong> from ${act.ip_address} (${act.city || 'Unknown'}) &bull; Risk: <strong>${act.risk_score}/100</strong> (${act.risk_level})${lockTag}`;
      }

      // Increment counters
      incrementMetric('metricTotalLogins');
      if (act.login_status === 'FAILED') incrementMetric('metricFailedLogins');
      if (act.risk_score >= 70) incrementMetric('metricHighRisk');
      if (act.risk_score >= 30) incrementMetric('metricSuspicious');
      if (act.account_locked) incrementMetric('metricLockedAccounts');

      // Drop dynamic live marker on Threat Map
      if (act.lat && act.lon && typeof threatMapInstance !== 'undefined' && threatMapInstance) {
        let pinColor = act.risk_score >= 70 ? '#ff3366' : (act.risk_score >= 30 ? '#ffa502' : '#00f076');
        let pinRadius = act.risk_score >= 70 ? 10 : (act.risk_score >= 30 ? 7 : 5);
        const liveMarker = L.circleMarker([act.lat, act.lon], {
          radius: pinRadius,
          fillColor: pinColor,
          color: '#ffffff',
          weight: 2,
          opacity: 1,
          fillOpacity: 0.85
        }).addTo(threatMapInstance);

        liveMarker.bindPopup(`
          <div style="font-family: monospace; font-size: 0.8rem; line-height: 1.5; min-width: 190px;">
            <strong style="color: #38bdf8; font-size: 0.88rem;">${act.city || 'Live Ingress'}, ${act.country || ''}</strong><br/>
            <span style="color: #94a3b8;">User:</span> <strong style="color: #fff;">${act.username}</strong><br/>
            <span style="color: #94a3b8;">IP:</span> <code style="color: #f43f5e;">${act.ip_address}</code><br/>
            <span style="color: #94a3b8;">Risk Score:</span> <strong style="color: ${act.risk_score >= 70 ? '#f43f5e' : (act.risk_score >= 30 ? '#facc15' : '#4ade80')};">${act.risk_score} / 100</strong><br/>
            <span style="color: #94a3b8;">Status:</span> <strong style="color: ${act.account_locked ? '#f43f5e' : '#4ade80'};">${act.account_locked ? 'ACCOUNT LOCKED' : act.login_status}</strong>
          </div>
        `);

        if (act.risk_score >= 70) {
          threatMapInstance.flyTo([act.lat, act.lon], 4, { duration: 1.0 });
          liveMarker.openPopup();
        }
      }
    } catch (err) {
      console.warn('SSE Activity parse error:', err);
    }
  });

  evtSource.addEventListener('alert', function(e) {
    try {
      const al = JSON.parse(e.data);
      incrementMetric('metricOpenAlerts');

      if (alertsTableBody) {
        const simBadge = al.is_simulated ? '<span class="badge-simulated ms-1">SIM</span>' : '';
        const sevClass = (al.severity === 'Critical' || al.severity === 'High') ? 'badge-risk-high' : (al.severity === 'Medium' ? 'badge-risk-med' : 'badge-risk-low');
        const scoreClass = al.risk_score >= 70 ? 'text-danger' : (al.risk_score >= 30 ? 'text-warning' : 'text-success');

        const newRow = document.createElement('tr');
        newRow.className = 'table-danger';
        newRow.style.transition = 'all 1s ease';
        newRow.innerHTML = `
          <td class="font-monospace text-secondary">#${al.alert_id}</td>
          <td><strong class="text-light">${al.username}</strong>${simBadge}</td>
          <td class="font-monospace text-secondary">${al.ip_address}</td>
          <td><span class="text-light">${al.title}</span></td>
          <td><strong class="font-monospace ${scoreClass}">${al.risk_score.toFixed(1)}</strong></td>
          <td><span class="${sevClass}">${al.severity}</span></td>
          <td class="font-monospace text-secondary" style="font-size: 0.8rem;">${al.timestamp}</td>
          <td><span class="badge badge-status-open">OPEN</span></td>
          <td class="text-end">
            <button class="btn btn-sm btn-dark border border-secondary" onclick="inspectActivity(${al.activity_id})" title="View Telemetry Forensics">
              <i class="fas fa-magnifying-glass text-info"></i>
            </button>
          </td>
        `;

        alertsTableBody.insertBefore(newRow, alertsTableBody.firstChild);
        setTimeout(() => { newRow.classList.remove('table-danger'); }, 2500);
      }

      // Prepend to Glassmorphic Live Incident Feed
      const liveFeed = document.getElementById('liveIncidentFeedContainer');
      if (liveFeed) {
        const item = document.createElement('div');
        item.className = 'list-group-item bg-transparent text-secondary px-2 py-2 border-secondary mb-1 rounded';
        item.style = 'background: rgba(239, 68, 68, 0.25) !important; border: 1px solid #ef4444 !important; transition: all 0.5s ease;';
        item.innerHTML = `
          <div class="d-flex justify-content-between align-items-start">
            <div>
              <span class="badge ${sevClass} font-monospace me-1">${al.risk_score.toFixed(1)}</span>
              <strong class="text-light">${al.username}</strong>
              <span class="text-secondary font-monospace small ms-2">(${al.ip_address})</span>
            </div>
            <span class="badge badge-status-open font-monospace" style="font-size: 0.65rem;">OPEN</span>
          </div>
          <div class="text-light small mt-1 font-monospace" style="font-size: 0.78rem;">${al.title}</div>
          <div class="d-flex justify-content-between align-items-center mt-1">
            <span class="text-secondary font-monospace" style="font-size: 0.7rem;"><i class="fas fa-clock me-1"></i>${al.timestamp}</span>
            <div class="d-flex gap-1">
              <button onclick="inspectActivity(${al.activity_id})" class="btn btn-outline-info btn-sm py-0 px-1 font-monospace" style="font-size: 0.65rem;">Forensics</button>
              <button onclick="quarantineIP('${al.ip_address}', 'Flagged from Live Incident Deck')" class="btn btn-outline-danger btn-sm py-0 px-1 font-monospace" style="font-size: 0.65rem;">Quarantine</button>
            </div>
          </div>
        `;
        liveFeed.insertBefore(item, liveFeed.firstChild);
        setTimeout(() => { item.style.background = 'rgba(15, 23, 42, 0.4) !important'; item.style.border = ''; }, 3000);
      }

      // Update Peak Threat Speedometer Gauge if new peak
      const peakNum = document.getElementById('gaugePeakNum');
      const peakValCircle = document.getElementById('gaugePeakVal');
      if (peakNum && peakValCircle) {
        const curMax = parseFloat(peakNum.innerText) || 0;
        if (al.risk_score > curMax) {
          peakNum.innerText = al.risk_score.toFixed(1);
          const offset = 314 - (314 * (al.risk_score / 100));
          peakValCircle.style.strokeDashoffset = offset;
        }
      }
    } catch (err) {
      console.warn('SSE Alert parse error:', err);
    }
  });

  evtSource.onerror = function() {
    if (ssePulse) ssePulse.className = 'spinner-grow spinner-grow-sm text-warning';
    if (sseStatus) sseStatus.innerHTML = 'STREAM: RECONNECTING...';
  };
}

function incrementMetric(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const currentVal = parseInt(el.innerText) || 0;
  el.innerText = currentVal + 1;
  el.style.transform = 'scale(1.15)';
  el.style.transition = 'transform 0.3s ease';
  setTimeout(() => { el.style.transform = 'scale(1)'; }, 350);
}

document.addEventListener('DOMContentLoaded', function() {
  initSSEStream();
  initCyberThreatMap();
});

// ==========================================
// Interactive Global Cyber Threat Map (Leaflet)
// ==========================================
let threatMapInstance = null;

function initCyberThreatMap() {
  const mapContainer = document.getElementById('cyberThreatMap');
  if (!mapContainer) return;

  // Check if Leaflet loaded
  if (typeof L === 'undefined') {
    mapContainer.innerHTML = `
      <div class="d-flex flex-column align-items-center justify-content-center h-100 text-center p-3">
        <i class="fas fa-triangle-exclamation text-warning fa-2x mb-2"></i>
        <span class="text-light fw-bold font-monospace">Leaflet map library could not be loaded from CDN.</span>
        <small class="text-secondary">Please check your internet connection and refresh the page.</small>
      </div>
    `;
    return;
  }

  try {
    if (threatMapInstance) {
      threatMapInstance.remove();
      threatMapInstance = null;
    }

    threatMapInstance = L.map('cyberThreatMap', {
      center: [22.0, 18.0],
      zoom: 2,
      minZoom: 1,
      maxZoom: 18,
      zoomControl: true,
      scrollWheelZoom: true
    });

    // 1. Primary 100% Free Source: OpenStreetMap (OSM)
    const osmFreeLayer = L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 19,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank">OpenStreetMap</a> contributors &bull; CyberGuard Sentinel'
    });

    // 2. Carto Dark Matter (Cyber Aesthetic)
    const cartoDarkLayer = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      maxZoom: 19,
      subdomains: 'abcd',
      attribution: '&copy; <a href="https://carto.com/">CARTO</a> &bull; Sentinel AI SOC'
    });

    // 3. Esri Satellite / World Imagery (Free)
    const esriSatellite = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
      maxZoom: 18,
      attribution: 'Tiles &copy; Esri &mdash; Sentinel SOC'
    });

    // By default, add Carto Dark layer with automatic OpenStreetMap fallback
    cartoDarkLayer.addTo(threatMapInstance);

    // Layer Switcher Control so user can switch between Free OpenStreetMap, Dark Matter & Satellite
    const baseMaps = {
      "<span style='color: #38bdf8;'><i class='fas fa-shield-halved me-1'></i>Carto Dark</span>": cartoDarkLayer,
      "<span style='color: #4ade80;'><i class='fas fa-globe me-1'></i>OpenStreetMap (Free)</span>": osmFreeLayer,
      "<span style='color: #facc15;'><i class='fas fa-satellite me-1'></i>Satellite</span>": esriSatellite
    };
    L.control.layers(baseMaps, null, { position: 'topright' }).addTo(threatMapInstance);

    // If Carto tiles fail to load, automatically fallback to OpenStreetMap
    cartoDarkLayer.on('tileerror', function() {
      if (!threatMapInstance.hasLayer(osmFreeLayer)) {
        console.warn('Carto tile error. Auto-fallback to OpenStreetMap.');
        threatMapInstance.removeLayer(cartoDarkLayer);
        osmFreeLayer.addTo(threatMapInstance);
      }
    });

    // Invalidate size after layout calculation (strictly needed for Leaflet inside containers)
    setTimeout(() => {
      if (threatMapInstance) threatMapInstance.invalidateSize();
    }, 150);
    setTimeout(() => {
      if (threatMapInstance) threatMapInstance.invalidateSize();
    }, 500);

    // Fetch live attack surface telemetry
    fetch('/api/dashboard/threat-map')
      .then(r => r.json())
      .then(data => {
        // Plot ingress point beacons
        (data.points || []).forEach(pt => {
          if (!pt.lat || !pt.lon) return;

          let color = '#00f2fe';
          let radius = 6;
          let weight = 1;

          if (pt.risk_score >= 70 || pt.is_ml_anomaly) {
            color = '#ff3366';
            radius = 10;
            weight = 2;
          } else if (pt.risk_score >= 30) {
            color = '#ffa502';
            radius = 7;
          }

          const marker = L.circleMarker([pt.lat, pt.lon], {
            radius: radius,
            fillColor: color,
            color: '#ffffff',
            weight: weight,
            opacity: 0.9,
            fillOpacity: 0.85
          }).addTo(threatMapInstance);

          const popupContent = `
            <div style="font-family: monospace; font-size: 0.8rem; line-height: 1.5; min-width: 190px;">
              <strong style="color: #38bdf8; font-size: 0.88rem;">${pt.city}, ${pt.country}</strong><br/>
              <span style="color: #94a3b8;">User:</span> <strong style="color: #fff;">${pt.username}</strong><br/>
              <span style="color: #94a3b8;">IP:</span> <code style="color: #f43f5e;">${pt.ip_address}</code><br/>
              <span style="color: #94a3b8;">Status:</span> <span style="font-weight: bold; color: ${pt.login_status === 'SUCCESS' ? '#4ade80' : '#f43f5e'};">${pt.login_status}</span><br/>
              <span style="color: #94a3b8;">Risk Score:</span> <strong style="color: ${pt.risk_score >= 70 ? '#f43f5e' : (pt.risk_score >= 30 ? '#facc15' : '#4ade80')};">${pt.risk_score} / 100</strong> (${pt.risk_level})<br/>
              <span style="color: #94a3b8;">ML Anomaly:</span> <strong style="color: ${pt.is_ml_anomaly ? '#f43f5e' : '#4ade80'};">${pt.is_ml_anomaly ? 'OUTLIER (-1)' : 'NORMAL (+1)'}</strong><br/>
              <div style="margin-top: 8px; display: flex; gap: 6px;">
                <button onclick="inspectActivity(${pt.activity_id})" style="padding: 3px 8px; font-size: 0.72rem; background: #0284c7; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">Forensics</button>
                <button onclick="quarantineIP('${pt.ip_address}', 'Flagged from Global Threat Map')" style="padding: 3px 8px; font-size: 0.72rem; background: #dc2626; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">Quarantine IP</button>
              </div>
            </div>
          `;
          marker.bindPopup(popupContent);
        });

        // Plot Impossible Travel Geodesic Vector Arcs
        (data.impossible_vectors || []).forEach(vec => {
          const latlngs = [
            [vec.source_lat, vec.source_lon],
            [vec.dest_lat, vec.dest_lon]
          ];
          const polyline = L.polyline(latlngs, {
            color: '#ff3366',
            weight: 3.5,
            opacity: 0.9,
            dashArray: '8, 8',
            lineCap: 'round'
          }).addTo(threatMapInstance);

          polyline.bindPopup(`
            <div style="font-family: monospace; font-size: 0.8rem; line-height: 1.5; min-width: 220px;">
              <strong style="color: #f43f5e; font-size: 0.88rem;"><i class="fas fa-triangle-exclamation me-1"></i>IMPOSSIBLE TRAVEL VECTOR</strong><br/>
              <span style="color: #94a3b8;">Transit:</span> <strong style="color: #fff;">${vec.source_city} &rarr; ${vec.dest_city}</strong><br/>
              <span style="color: #94a3b8;">Distance:</span> <strong style="color: #fff;">${vec.distance_km} km</strong><br/>
              <span style="color: #94a3b8;">Elapsed:</span> <strong style="color: #fff;">${vec.time_delta_mins} mins</strong><br/>
              <span style="color: #94a3b8;">Speed:</span> <strong style="color: #f43f5e; font-size: 0.85rem;">${vec.transit_velocity_kmh.toLocaleString()} km/h</strong><br/>
              <span style="color: #fb7185; font-size: 0.72rem; font-weight: bold;">[!] EXCEEDS 800 KM/H LIMIT</span>
            </div>
          `);
        });
      })
      .catch(err => console.warn('Failed to load threat map points:', err));
  } catch (err) {
    console.warn('Threat map init error:', err);
  }
}

// ==========================================
// SOAR Incident Response: IP Quarantine Shield
// ==========================================
function quarantineIP(ipAddress, reason = 'Quarantined by SOC analyst via Sentinel SOAR') {
  if (!confirm(`Are you sure you want to QUARANTINE IP address ${ipAddress}? It will immediately be blocked from all application access.`)) {
    return;
  }

  fetch('/api/firewall/block-ip', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip_address: ipAddress, reason: reason })
  })
  .then(r => r.json())
  .then(data => {
    if (data.success) {
      alert(`[SHIELD ACTIVE] ${data.message}`);
      location.reload();
    } else {
      alert(`Failed to quarantine IP: ${data.message}`);
    }
  })
  .catch(err => alert(`Network error during quarantine dispatch: ${err.message}`));
}

function unblockIP(ipAddress) {
  if (!confirm(`Release and UNBLOCK IP address ${ipAddress} from firewall quarantine?`)) {
    return;
  }

  fetch('/api/firewall/unblock-ip', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip_address: ipAddress })
  })
  .then(r => r.json())
  .then(data => {
    if (data.success) {
      alert(`[RELEASED] ${data.message}`);
      location.reload();
    } else {
      alert(`Failed to unblock IP: ${data.message}`);
    }
  })
  .catch(err => alert(`Error releasing IP: ${err.message}`));
}
