/**
 * CLICKGUARD - Enterprise Security Middleware for Autonomous Web Agents
 * High-Fidelity Client Controller
 */

// ============================================================================
// 1. CONFIGURATION & CORE STATE
// ============================================================================
const CONFIG = {
  apiEndpoint: localStorage.getItem('clickguard_endpoint') || 'http://localhost:8000/analyze',
  groqApiKey: localStorage.getItem('clickguard_groq_key') || '',
  stepDuration: 420
};

let pendingAudit = null;
let currentAnalysisData = null;
let currentFilter = 'all';

// Sections that start hidden and are revealed after analysis completes
const HIDDEN_SECTIONS = [
  'verdict-section',
  'intent-reality-section',
  'wireframe-section',
  'forensic-section'
];

function revealResultSections() {
  HIDDEN_SECTIONS.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = '';
  });
  const metricsGrid = document.querySelector('.metrics-summary-grid');
  if (metricsGrid) metricsGrid.style.display = '';
}

// ============================================================================
// 2. LIFECYCLE INITIALIZATION
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  initEngineState();
  initFormControls();
  initScenarioPills();
  initTabs();
  initViewportInteractivity();
  initModals();
  initScrollNav();
  // No mock data rendered on load — user must trigger an audit
});

function initEngineState() {
  const statusLabel = document.getElementById('backend-status-label');
  const statusDot = document.getElementById('status-dot');
  const settingEndpoint = document.getElementById('setting-api-url');
  const settingGroq = document.getElementById('setting-groq-key');

  if (settingEndpoint) settingEndpoint.value = CONFIG.apiEndpoint;
  if (settingGroq) settingGroq.value = CONFIG.groqApiKey;

  if (statusLabel) statusLabel.textContent = "FastAPI Backend (:8000)";
  if (statusDot) statusDot.className = "pulse-indicator warning";

  // Check backend health
  fetch(CONFIG.apiEndpoint.replace('/analyze', '/'), { method: 'GET' })
    .then(r => r.json())
    .then(data => {
      if (statusLabel) statusLabel.textContent = "FastAPI Backend (:8000)";
      if (statusDot) statusDot.className = "pulse-indicator safe";
    })
    .catch(() => {
      if (statusLabel) statusLabel.textContent = "Backend Offline";
      if (statusDot) statusDot.className = "pulse-indicator danger";
    });
}

function initFormControls() {
  const analyzeBtn = document.getElementById('analyze-button');
  const clearUrlBtn = document.getElementById('clear-url-btn');

  if (analyzeBtn) {
    analyzeBtn.addEventListener('click', (e) => {
      e.preventDefault();
      runActiveAudit();
    });
  }

  if (clearUrlBtn) {
    clearUrlBtn.addEventListener('click', () => {
      const urlInput = document.getElementById('website-url-input');
      if (urlInput) {
        urlInput.value = '';
        urlInput.focus();
      }
    });
  }

  const inputs = [document.getElementById('website-url-input'), document.getElementById('agent-task-input')];
  inputs.forEach(input => {
    if (input) {
      input.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
          runActiveAudit();
        }
      });
    }
  });
}

function initScenarioPills() {
  const pills = document.querySelectorAll('.scenario-hero-card, .scenario-pill');
  pills.forEach(pill => {
    pill.addEventListener('click', () => {
      pills.forEach(p => {
        p.classList.remove('active');
        const indicator = p.querySelector('.card-active-indicator');
        if (indicator) indicator.textContent = 'BENCHMARK';
      });
      pill.classList.add('active');
      const activeIndicator = pill.querySelector('.card-active-indicator');
      if (activeIndicator) activeIndicator.textContent = 'ACTIVE AUDIT';

      const url = pill.getAttribute('data-url');
      const task = pill.getAttribute('data-task');

      const urlInput = document.getElementById('website-url-input');
      const taskInput = document.getElementById('agent-task-input');

      if (urlInput && url) urlInput.value = url;
      if (taskInput && task) taskInput.value = task;

      runActiveAudit();
    });
  });
}

function initTabs() {
  const tabButtons = document.querySelectorAll('.forensic-tab-btn');
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabKey = btn.getAttribute('data-tab');

      tabButtons.forEach(b => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');

      const panes = document.querySelectorAll('.forensic-pane');
      panes.forEach(p => p.classList.remove('active'));
      const activePane = document.getElementById(`tab-pane-${tabKey}`);
      if (activePane) activePane.classList.add('active');
    });
  });

  const filterBtns = document.querySelectorAll('.sev-filter-btn');
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.getAttribute('data-filter') || 'all';
      if (currentAnalysisData) {
        renderFindings(currentAnalysisData.findings || []);
      }
    });
  });
}

function initViewportInteractivity() {
  const btnXray = document.getElementById('btn-mode-xray');
  const btnCursor = document.getElementById('btn-simulate-cursor');
  const btnReset = document.getElementById('btn-reset-viewport');
  const jumpXray = document.getElementById('btn-toggle-xray');
  const realTargetBtn = document.getElementById('real-target-btn');
  const interceptorOverlay = document.getElementById('interceptor-overlay');

  const handleDirectClick = (e) => {
    e.preventDefault();
    if (!currentAnalysisData) return;
    const isTrap = currentAnalysisData.verdict === 'BLOCK';

    if (isTrap) {
      if (interceptorOverlay) {
        interceptorOverlay.style.boxShadow = '0 0 45px #F43F5E';
        interceptorOverlay.style.backgroundColor = 'rgba(244, 63, 94, 0.5)';
        setTimeout(() => {
          interceptorOverlay.style.boxShadow = '';
          interceptorOverlay.style.backgroundColor = '';
        }, 1200);
      }
      showToast("[POINTER INTERCEPTED]: Your click was captured by an invisible overlay instead of the visible target!", "danger");
    } else {
      showToast("[CLEAN INTERACTION]: Direct pointer event dispatched to intended destination.", "safe");
    }
  };

  if (realTargetBtn) realTargetBtn.addEventListener('click', handleDirectClick);
  if (interceptorOverlay) interceptorOverlay.addEventListener('click', handleDirectClick);

  if (btnXray) {
    btnXray.addEventListener('click', () => {
      const overlayEl = document.getElementById('interceptor-overlay');
      const isActive = btnXray.classList.toggle('active');
      if (overlayEl) {
        overlayEl.classList.toggle('active-highlight', isActive);
        overlayEl.style.display = isActive ? 'block' : 'none';
      }
      showToast(isActive ? "X-Ray: Interceptor layer highlighted" : "X-Ray: Deceptive overlay concealed", "safe");
    });
  }

  if (jumpXray) {
    jumpXray.addEventListener('click', () => {
      const wireframe = document.getElementById('wireframe-section');
      if (wireframe) {
        wireframe.scrollIntoView({ behavior: 'smooth', block: 'start' });
        if (btnXray && !btnXray.classList.contains('active')) {
          btnXray.click();
        }
      }
    });
  }

  if (btnCursor) {
    btnCursor.addEventListener('click', () => {
      simulateAgentCursor();
    });
  }

  if (btnReset) {
    btnReset.addEventListener('click', () => {
      const cursor = document.getElementById('agent-cursor');
      if (cursor) cursor.style.display = 'none';
      if (btnXray && !btnXray.classList.contains('active')) {
        btnXray.classList.add('active');
      }
      const overlayEl = document.getElementById('interceptor-overlay');
      if (overlayEl) {
        overlayEl.classList.add('active-highlight');
        overlayEl.style.display = 'block';
      }
      showToast("Viewport simulator reset to baseline", "safe");
    });
  }
}

function simulateAgentCursor() {
  const cursor = document.getElementById('agent-cursor');
  const realBtn = document.getElementById('real-target-btn');
  const overlay = document.getElementById('interceptor-overlay');
  if (!cursor || !realBtn || !overlay) return;

  cursor.style.display = 'flex';
  cursor.style.top = '-40px';
  cursor.style.left = '0px';

  setTimeout(() => {
    cursor.style.top = '12px';
    cursor.style.left = '60px';
    setTimeout(() => {
      overlay.style.boxShadow = '0 0 40px #F43F5E';
      overlay.style.backgroundColor = 'rgba(244, 63, 94, 0.45)';
      showToast("[POINTER INTERCEPTED]: Click diverted by invisible overlay!", "danger");
      setTimeout(() => {
        overlay.style.boxShadow = '';
        overlay.style.backgroundColor = '';
      }, 1500);
    }, 650);
  }, 100);
}

function initScrollNav() {
  const navBtns = document.querySelectorAll('.header-nav .nav-item');
  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const sel = btn.getAttribute('data-scroll');
      if (sel) {
        const el = document.querySelector(sel);
        if (el) {
          navBtns.forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      }
    });
  });
}

// ============================================================================
// 3. MODALS
// ============================================================================

function initModals() {
  const settingsBtn = document.getElementById('settings-button');
  const closeSettingsBtn = document.getElementById('close-settings-modal');
  const saveSettingsBtn = document.getElementById('save-settings-btn');
  const closeForensicBtn = document.getElementById('close-forensic-modal');

  if (settingsBtn) settingsBtn.addEventListener('click', openSettingsModal);
  if (closeSettingsBtn) closeSettingsBtn.addEventListener('click', closeSettingsModal);
  if (closeForensicBtn) closeForensicBtn.addEventListener('click', closeForensicModal);

  if (saveSettingsBtn) {
    saveSettingsBtn.addEventListener('click', () => {
      const endpointInput = document.getElementById('setting-api-url');
      const groqInput = document.getElementById('setting-groq-key');

      if (endpointInput) {
        CONFIG.apiEndpoint = endpointInput.value.trim() || 'http://localhost:8000/analyze';
        localStorage.setItem('clickguard_endpoint', CONFIG.apiEndpoint);
      }
      if (groqInput) {
        CONFIG.groqApiKey = groqInput.value.trim();
        localStorage.setItem('clickguard_groq_key', CONFIG.groqApiKey);
      }

      closeSettingsModal();
      showToast("Configuration saved", "safe");
      initEngineState();
    });
  }

  // Close modals on overlay click
  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) overlay.style.display = 'none';
    });
  });
}

function openSettingsModal() {
  const modal = document.getElementById('settings-modal');
  if (modal) modal.style.display = 'flex';
}

function closeSettingsModal() {
  const modal = document.getElementById('settings-modal');
  if (modal) modal.style.display = 'none';
}

function closeForensicModal() {
  const modal = document.getElementById('forensic-modal');
  if (modal) modal.style.display = 'none';
}

function openBackendOfflineModal(url, task) {
  pendingAudit = { url, task };
  showToast("Backend unavailable — ensure FastAPI server is running on :8000", "danger");
}

// ============================================================================
// 4. AUDIT PIPELINE EXECUTION
// ============================================================================

function runActiveAudit() {
  const urlInput = document.getElementById('website-url-input');
  const taskInput = document.getElementById('agent-task-input');
  const url = urlInput ? urlInput.value.trim() : '';
  const task = taskInput ? taskInput.value.trim() : '';

  if (!url) {
    showToast("Enter a target URL before auditing", "danger");
    return;
  }

  const progressSection = document.getElementById('analysis-progress');
  const scanBtn = document.getElementById('analyze-button');

  if (scanBtn) scanBtn.disabled = true;
  if (progressSection) progressSection.style.display = 'block';

  const stages = [
    { id: 'stage-browser', desc: 'Isolated sandbox active' },
    { id: 'stage-dom', desc: 'Topology & z-index parsed' },
    { id: 'stage-javascript', desc: 'Listener traps audited' },
    { id: 'stage-network', desc: 'Redirect routes mapped' },
    { id: 'stage-risk', desc: 'Policy scorecard ready' }
  ];

  let currentStage = 0;
  const percentEl = document.getElementById('progress-percent');

  function step() {
    if (currentStage < stages.length) {
      const s = stages[currentStage];
      const el = document.getElementById(s.id);
      if (el) {
        el.classList.add('active');
        const desc = document.getElementById(`${s.id}-desc`);
        if (desc) desc.textContent = 'Analyzing...';
      }

      const pct = Math.round(((currentStage + 1) / stages.length) * 100);
      if (percentEl) percentEl.textContent = `${pct}%`;

      setTimeout(() => {
        if (el) {
          el.classList.remove('active');
          el.classList.add('complete');
          const desc = document.getElementById(`${s.id}-desc`);
          if (desc) desc.textContent = s.desc;
        }
        currentStage++;
        step();
      }, CONFIG.stepDuration);
    } else {
      // Animation steps are complete, but backend might still be processing.
      // Keep the UI visible and indicate it's finalizing.
      if (percentEl) percentEl.textContent = '99%';
      const lastStageEl = document.getElementById('stage-risk');
      if (lastStageEl) lastStageEl.classList.add('active');
      const lastDesc = document.getElementById('stage-risk-desc');
      if (lastDesc) lastDesc.textContent = 'Finalizing response...';
    }
  }

  stages.forEach(s => {
    const el = document.getElementById(s.id);
    if (el) {
      el.className = 'stage-box';
      const desc = document.getElementById(`${s.id}-desc`);
      if (desc) desc.textContent = 'Waiting';
    }
  });

  step();

  // Start the backend request and hide progress bar only when it finishes
  executeLiveBackend(url, task).finally(() => {
    if (percentEl) percentEl.textContent = '100%';
    const lastStageEl = document.getElementById('stage-risk');
    if (lastStageEl) lastStageEl.classList.remove('active');
    
    // Brief delay to show 100% before hiding
    setTimeout(() => {
      if (progressSection) progressSection.style.display = 'none';
      if (scanBtn) scanBtn.disabled = false;
    }, 400);
  });
}

async function executeLiveBackend(url, task) {
  try {
    const payload = { url, task };
    if (CONFIG.groqApiKey) payload.groq_api_key = CONFIG.groqApiKey;

    const res = await fetch(CONFIG.apiEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const data = await res.json();
    data.target_url = url;
    data.intended_task = task;
    data.timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

    renderResults(data);
    showToast("Audit complete — Live Playwright inspection", "safe");
  } catch (err) {
    console.warn("Backend error:", err);
    openBackendOfflineModal(url, task);
  }
}

// ============================================================================
// 5. RENDERING ENGINE
// ============================================================================

function deriveCWE(findings) {
  const titles = findings.map(f => (f.title || '').toLowerCase());
  if (titles.some(t => t.includes('overlay') || t.includes('clickjack') || t.includes('interceptor'))) return 'CWE-1021: UI Redressing (Clickjacking)';
  if (titles.some(t => t.includes('redirect'))) return 'CWE-601: URL Redirection to Untrusted Site';
  return '';
}

function deriveOWASP(findings) {
  const titles = findings.map(f => (f.title || '').toLowerCase());
  if (titles.some(t => t.includes('injection') || t.includes('prompt'))) return 'OWASP LLM01: Prompt Injection';
  if (titles.some(t => t.includes('redirect'))) return 'OWASP LLM04: Model Denial / Evasion';
  return '';
}

function renderResults(data) {
  currentAnalysisData = data;

  // Reveal all hidden result sections
  revealResultSections();

  const score = data.interaction_risk_score !== undefined ? data.interaction_risk_score : (data.risk_score || 0);

  // ── 1. Verdict Master Card ──
  const masterCard = document.getElementById('verdict-section');
  const riskScoreEl = document.getElementById('risk-score');
  const gaugeCircle = document.getElementById('risk-gauge-circle');
  const badgeEl = document.getElementById('verdict-decision-badge');
  const titleEl = document.getElementById('verdict-title');
  const summaryEl = document.getElementById('verdict-summary');
  const cweTag = document.getElementById('threat-cwe-tag');
  const owaspTag = document.getElementById('threat-owasp-tag');
  const enforceBtn = document.getElementById('block-action-button');

  const isDanger = data.verdict === 'BLOCK' || score >= 60;
  const isWarning = data.verdict === 'CAUTION' || (score >= 30 && score < 60);

  if (masterCard) {
    masterCard.className = 'verdict-master-card ' + (isDanger ? 'verdict-danger' : isWarning ? 'verdict-warning' : 'verdict-safe');
  }

  if (riskScoreEl) riskScoreEl.textContent = String(score);

  if (gaugeCircle) {
    const circumference = 314;
    const offset = circumference - (circumference * (score / 100));
    gaugeCircle.style.strokeDashoffset = String(offset);
  }

  if (isDanger) {
    if (badgeEl) { badgeEl.className = 'decision-flag danger'; badgeEl.innerHTML = '<span class="pulse-ruby"></span> BLOCK ACTION'; }
    if (titleEl) titleEl.textContent = 'Adversarial Deception Layer Detected';
    if (enforceBtn) enforceBtn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg><span>Enforce Block Policy</span>`;
  } else if (isWarning) {
    if (badgeEl) { badgeEl.className = 'decision-flag warning'; badgeEl.innerHTML = '<span class="pulse-ruby"></span> CAUTION REQUIRED'; }
    if (titleEl) titleEl.textContent = 'High-Risk Network Redirection';
    if (enforceBtn) enforceBtn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg><span>Enforce Sandboxed Execution</span>`;
  } else {
    if (badgeEl) { badgeEl.className = 'decision-flag safe'; badgeEl.innerHTML = '<span class="pulse-ruby"></span> VERIFIED SAFE'; }
    if (titleEl) titleEl.textContent = 'Clean Interaction Surface Verified';
    if (enforceBtn) enforceBtn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><polyline points="20 6 9 17 4 12"></polyline></svg><span>Authorize Execution</span>`;
  }

  if (summaryEl) summaryEl.textContent = data.summary || '';

  const cwe = data.cwe || deriveCWE(data.findings || []);
  const owasp = data.owasp || deriveOWASP(data.findings || []);
  if (cweTag) cweTag.textContent = cwe;
  if (owaspTag) owaspTag.textContent = owasp;

  // ── Risk Signal Breakdown ──
  const totalBadge = document.getElementById('breakdown-total-badge');
  if (totalBadge) {
    totalBadge.textContent = `${score}/100`;
    totalBadge.className = `factors-header-badge font-mono ${isDanger ? 'danger' : isWarning ? 'warning' : 'safe'}`;
  }

  const breakdown = data.score_breakdown || [];
  const hasOverlay = breakdown.some(s => (s.signal || '').toLowerCase().includes('interceptor')) || data.overlay_interception != null;
  const hasMismatch = breakdown.some(s => (s.signal || '').toLowerCase().includes('mismatch')) || data.destination_mismatch_detail != null;
  const hasInjection = breakdown.some(s => (s.signal || '').toLowerCase().includes('injection') || (s.signal || '').toLowerCase().includes('instruction')) || data.prompt_injection_detail != null;
  const hasRedirect = breakdown.some(s => (s.signal || '').toLowerCase().includes('redirect')) || (data.redirect_chain && data.redirect_chain.length > 1);
  const hasJs = (data.javascript_signals && data.javascript_signals.length > 0);

  // Derive signal evidence from actual score_breakdown + response data
  const overlayBreakdown = breakdown.find(s => (s.signal || '').toLowerCase().includes('interceptor'));
  const mismatchBreakdown = breakdown.find(s => (s.signal || '').toLowerCase().includes('mismatch'));
  const injectionBreakdown = breakdown.find(s => (s.signal || '').toLowerCase().includes('injection') || (s.signal || '').toLowerCase().includes('instruction'));
  const redirectBreakdown = breakdown.find(s => (s.signal || '').toLowerCase().includes('redirect'));
  const jsBreakdown = breakdown.find(s => (s.signal || '').toLowerCase().includes('javascript') || (s.signal || '').toLowerCase().includes('navigation'));

  const ivr = data.intent_vs_reality || {};

  const overlayEv = hasOverlay
    ? (data.overlay_interception
        ? `opacity: ${data.overlay_interception.opacity} · z-index: ${data.overlay_interception.z_index} · pointer-events: ${data.overlay_interception.pointer_events}`
        : (overlayBreakdown ? overlayBreakdown.evidence : 'Overlay detected'))
    : 'No interceptor layer';

  const mismatchEv = hasMismatch
    ? (mismatchBreakdown
        ? mismatchBreakdown.evidence
        : (ivr.expected_destination && ivr.actual_destination
            ? `${ivr.expected_destination} → ${ivr.actual_destination}`
            : 'Destination diverges from expected'))
    : 'Target resolves directly';

  const injectionEv = hasInjection
    ? (injectionBreakdown
        ? injectionBreakdown.evidence
        : (data.prompt_injection_detail && data.prompt_injection_detail.matched_phrases
            ? data.prompt_injection_detail.matched_phrases.join(', ')
            : 'Injection detected'))
    : 'No injection patterns';

  const redirectEv = hasRedirect
    ? (redirectBreakdown
        ? redirectBreakdown.evidence
        : `${(data.redirect_chain || []).length} hop(s) recorded`)
    : 'Direct navigation';

  const jsEv = hasJs
    ? (jsBreakdown
        ? jsBreakdown.evidence
        : (data.javascript_signals || []).map(s => s.signal).join(', '))
    : 'No suspicious API hooks';

  updateSignalUI('sig-overlay', hasOverlay, 'INTERCEPTED', 'CLEAN', overlayEv);
  updateSignalUI('sig-mismatch', hasMismatch, 'MISMATCH', 'ALIGNED', mismatchEv);
  updateSignalUI('sig-injection', hasInjection, 'INJECTION', 'CLEAN', injectionEv);
  updateSignalUI('sig-redirect', hasRedirect, 'REDIRECT', 'CLEAN', redirectEv);
  updateSignalUI('sig-js', hasJs, 'ACTIVE', 'CLEAN', jsEv);
  // ── 2. Agent Intent vs Browser Reality ──
  renderIntentVsReality(data, isDanger, isWarning);

  // ── 3. Telemetry Stream ──
  renderTelemetryStream(data);

  // ── 4. Ribbon ──
  setElText('ribbon-url', data.target_url);
  setElText('ribbon-timestamp', data.timestamp);
  const policyRule = data.recommendation?.action === 'BLOCK ACTION' ? 'SEC-DISALLOW-OVERLAY-TRAP' :
                     data.recommendation?.action === 'CAUTION REQUIRED' ? 'SEC-REQUIRE-HUMAN-CONFIRM' :
                     'SEC-POLICY-ALLOW-VERIFIED';
  setElText('ribbon-policy', data.policy_rule || policyRule);
  const ribbonPolicy = document.getElementById('ribbon-policy');
  if (ribbonPolicy) ribbonPolicy.className = `ribbon-v font-mono ${isDanger ? 'danger' : isWarning ? 'warning' : 'safe'}`;

  // ── 5. Metrics ──
  const m = data.metrics || {};
  setElText('metric-dom-elements', m.dom_elements);
  setElText('metric-network-requests', m.network_requests);
  setElText('metric-redirects', m.redirects);
  setElText('metric-scripts', m.scripts);
  setElText('metric-suspicious-signals', m.suspicious_signals);

  // ── 6. Viewport ──
  renderViewport(data, isDanger, isWarning);

  // ── 7. Forensic Tabs ──
  renderFindings(data.findings || []);
  renderInteractions(data.interactions || []);
  renderRedirects(data.redirect_chain || []);
  renderJavaScriptSignals(data.javascript_signals || []);
  renderAiInsights(data.ai_insights);
  renderTelemetry(data);
}

// ── Viewport Rendering ──

function renderViewport(data, isDanger, isWarning) {
  const simUrl = document.getElementById('sim-address-url');
  const simStatus = document.getElementById('sim-status-chip');
  const simDocCard = document.getElementById('sim-doc-card');
  const liveWebCard = document.getElementById('live-web-card');
  const liveImg = document.getElementById('live-page-screenshot');
  const liveDom = document.getElementById('live-dom-surfaces');
  const liveDomainTitle = document.getElementById('live-target-domain-title');
  const liveElementTally = document.getElementById('live-target-element-tally');
  const liveTypeBadge = document.getElementById('live-target-type-badge');
  const awaitingState = document.getElementById('viewport-awaiting-state');

  if (simUrl) simUrl.textContent = data.target_url;
  if (awaitingState) awaitingState.style.display = 'none';

  // If backend provided a screenshot, always use live card
  if (data.screenshot) {
    if (simDocCard) simDocCard.style.display = 'none';
    if (liveWebCard) liveWebCard.style.display = 'flex';

    let domainName = data.target_url;
    try {
      const u = new URL(data.target_url.startsWith('http') ? data.target_url : 'https://' + data.target_url);
      domainName = u.hostname;
    } catch (_) {
      domainName = data.target_url.split('/').pop() || data.target_url;
    }

    if (liveDomainTitle) liveDomainTitle.textContent = domainName;
    if (liveTypeBadge) liveTypeBadge.textContent = 'Live Chromium Capture (Playwright)';
    const items = data.raw_elements || data.interactions || [];
    if (liveElementTally) liveElementTally.textContent = `${items.length} Interactive Elements Mapped`;

    if (liveImg) {
      liveImg.src = data.screenshot;
      liveImg.style.display = 'block';
    }

    if (liveDom) {
      liveDom.innerHTML = '';
      items.slice(0, 12).forEach(it => {
        const box = document.createElement('div');
        const isThreat = (it.risk || '').toUpperCase() === 'HIGH' || (it.risk || '').toUpperCase() === 'CRITICAL';
        box.className = `live-node-box ${isThreat ? 'node-threat' : ''}`;
        box.innerHTML = `
          <div class="live-node-top">
            <span class="live-node-tag">${escapeHtml(it.element || it.tag_name || '')}</span>
            <span class="live-node-risk ${isThreat ? 'danger' : 'safe'}">${escapeHtml(it.risk || 'LOW')}</span>
          </div>
          <span class="live-node-text">${escapeHtml(it.visible_text || '')}</span>
          <span class="live-node-dest">${escapeHtml(it.destination || it.href || '')}</span>
        `;
        liveDom.appendChild(box);
      });
    }

    if (simStatus) {
      simStatus.className = `browser-status-chip ${isDanger ? 'danger' : isWarning ? 'warning' : 'safe'}`;
      simStatus.textContent = isDanger ? 'Threat Blocked' : isWarning ? 'Caution' : 'Direct Navigation';
    }
  } else {
    // No screenshot — show interaction surface map
    if (simDocCard) simDocCard.style.display = 'none';
    if (liveWebCard) liveWebCard.style.display = 'flex';

    let domainName = data.target_url;
    try {
      const u = new URL(data.target_url.startsWith('http') ? data.target_url : 'https://' + data.target_url);
      domainName = u.hostname;
    } catch (_) {
      domainName = data.target_url.split('/').pop() || data.target_url;
    }

    if (liveDomainTitle) liveDomainTitle.textContent = domainName;
    if (liveTypeBadge) liveTypeBadge.textContent = 'Interaction Surface Map';
    const items = data.raw_elements || data.interactions || [];
    if (liveElementTally) liveElementTally.textContent = `${items.length} Interactive Elements Mapped`;
    if (liveImg) liveImg.style.display = 'none';

    if (liveDom) {
      liveDom.innerHTML = '';
      items.slice(0, 20).forEach(it => {
        const box = document.createElement('div');
        const riskLevel = (it.risk || '').toUpperCase();
        const isThreat = riskLevel === 'HIGH' || riskLevel === 'CRITICAL';
        const tag = it.element || (it.tag_name ? `${it.tag_name}${it.id ? '#' + it.id : ''}` : '');
        const dest = it.destination || it.href || '';
        const text = it.visible_text || '';

        box.className = `live-node-box ${isThreat ? 'node-threat' : ''}`;
        box.innerHTML = `
          <div class="live-node-top">
            <span class="live-node-tag">${escapeHtml(tag)}</span>
            <span class="live-node-risk ${isThreat ? 'danger' : 'safe'}">${escapeHtml(it.risk || 'LOW')}</span>
          </div>
          <span class="live-node-text">${escapeHtml(text)}</span>
          <span class="live-node-dest">${escapeHtml(dest)}</span>
        `;
        box.addEventListener('click', () => {
          showToast(`Inspecting: ${tag} → ${dest}`, isThreat ? 'danger' : 'safe');
        });
        liveDom.appendChild(box);
      });
    }

    if (simStatus) {
      simStatus.className = `browser-status-chip ${isDanger ? 'danger' : isWarning ? 'warning' : 'safe'}`;
      simStatus.textContent = isDanger ? 'Threat Layer Active' : isWarning ? 'Caution' : 'Clean Target';
    }
  }
}

// ── Intent vs Reality ──

function renderIntentVsReality(data, isDanger, isWarning) {
  const ivr = data.intent_vs_reality || {};
  const fd = data.forensic_details || {};

  setElText('ivr-agent-action', ivr.agent_intent || '—');
  setElText('ivr-agent-task', ivr.expected_goal || data.intended_task || '—');
  setElText('ivr-expected-dest', ivr.expected_destination || '—');
  setElText('ivr-visible-tag', fd.visible_element || '—');
  setElText('ivr-actual-target', fd.interceptor && fd.interceptor !== 'None (Surface Unobstructed)' ? fd.interceptor : (ivr.actual_target || 'Direct Button'));
  setElText('ivr-interceptor-props', fd.interceptor_properties && fd.interceptor_properties !== 'N/A' ? fd.interceptor_properties : '—');
  setElText('ivr-actual-dest', ivr.actual_destination || '—');
  setElText('ivr-assessment', ivr.browser_reality || '—');

  // Color coding for destination fields
  const expectedDest = document.getElementById('ivr-expected-dest');
  const actualDest = document.getElementById('ivr-actual-dest');
  const actualTarget = document.getElementById('ivr-actual-target');
  const interceptorProps = document.getElementById('ivr-interceptor-props');

  if (expectedDest) expectedDest.className = `ivr-val font-mono ${isDanger || isWarning ? 'safe' : ''}`;
  if (actualDest) actualDest.className = `ivr-val font-mono ${isDanger ? 'danger' : isWarning ? 'warning' : ''}`;
  if (actualTarget) actualTarget.className = `ivr-val font-mono ${isDanger ? 'danger' : isWarning ? 'warning' : ''}`;
  if (interceptorProps) interceptorProps.className = `ivr-val font-mono ${isDanger ? 'danger' : isWarning ? 'warning' : ''}`;

  // Status pill
  const statusPill = document.getElementById('ivr-status-pill');
  if (statusPill) {
    statusPill.textContent = ivr.status || '—';
    statusPill.className = `pill-badge font-mono ${isDanger ? 'danger' : isWarning ? 'warning' : 'safe'}`;
  }

  // Verdict flag
  const verdictFlag = document.getElementById('ivr-verdict-flag');
  if (verdictFlag) {
    verdictFlag.textContent = isDanger ? 'ACTION INTERCEPTED' : isWarning ? 'CAUTION FLAGGED' : 'ACTION VERIFIED';
    verdictFlag.className = `ivr-verdict-flag font-mono ${isDanger ? 'danger' : isWarning ? 'warning' : 'safe'}`;
  }

  // Banner
  const banner = document.getElementById('ivr-banner');
  const bannerStatus = document.getElementById('ivr-banner-status');
  const bannerDesc = document.getElementById('ivr-banner-desc');

  if (banner) banner.className = `ivr-banner ${isDanger ? 'danger' : isWarning ? 'warning' : 'safe'}`;
  if (bannerStatus) bannerStatus.textContent = `STATUS: ${ivr.status || '—'}`;
  if (bannerDesc) {
    if (isDanger || isWarning) {
      bannerDesc.textContent = `Click would actually trigger ${ivr.actual_destination || 'an alternate destination'} instead of the expected ${ivr.expected_destination || 'target'}. ${isDanger ? 'Action Firewall blocks interaction.' : 'Human verification advised.'}`;
    } else {
      bannerDesc.textContent = 'Click dispatches directly to the intended target. Interaction surface verified.';
    }
  }
}

// ── Telemetry Stream ──

function renderTelemetryStream(data) {
  const terminal = document.getElementById('live-event-terminal');
  const streamStatus = document.getElementById('stream-status-text');
  if (!terminal) return;

  if (streamStatus) streamStatus.textContent = 'LIVE';

  const events = generateTelemetryEvents(data);
  terminal.innerHTML = '';

  events.forEach((evt, idx) => {
    const line = document.createElement('div');
    line.className = `stream-line stream-${evt.tag}`;
    line.style.animationDelay = `${idx * 80}ms`;
    line.innerHTML = `
      <span class="stream-tag font-mono">${escapeHtml(evt.tag.toUpperCase())}</span>
      <span class="stream-msg">${escapeHtml(evt.msg)}</span>
    `;
    terminal.appendChild(line);
  });
}

function generateTelemetryEvents(data) {
  const events = [];
  const tel = data.telemetry || {};
  const findings = data.findings || [];

  events.push({ tag: "agent", msg: `Autonomous agent task: "${data.intended_task || tel.intended_task || 'N/A'}"` });
  events.push({ tag: "dom", msg: `Target: ${data.target_url} (${(data.metrics || {}).dom_elements || 0} DOM elements)` });

  if (data.overlay_interception) {
    events.push({ tag: "firewall", msg: "ClickGuard Action Firewall intercepted proposed pointer event" });
    events.push({ tag: "threat", msg: `Overlay: opacity=${data.overlay_interception.opacity} z-index=${data.overlay_interception.z_index} pointer-events=${data.overlay_interception.pointer_events}` });
  }

  if (data.destination_mismatch_detail) {
    events.push({ tag: "threat", msg: `Destination mismatch: expected '${data.destination_mismatch_detail.expected_destination}', diverted to '${data.destination_mismatch_detail.actual_destination}'` });
  }

  if (data.prompt_injection_detail) {
    events.push({ tag: "threat", msg: `Prompt injection: ${(data.prompt_injection_detail.matched_phrases || []).join(', ')}` });
  }

  if ((data.redirect_chain || []).length > 1) {
    events.push({ tag: "warning", msg: `${data.redirect_chain.length} redirect hops detected` });
  }

  if ((data.javascript_signals || []).length > 0) {
    data.javascript_signals.forEach(s => {
      events.push({ tag: "warning", msg: `JS signal: ${s.signal} — ${s.details || s.evidence || ''}` });
    });
  }

  findings.forEach(f => {
    events.push({ tag: f.severity === 'critical' || f.severity === 'high' ? 'threat' : 'warning', msg: `${f.severity.toUpperCase()}: ${f.title}` });
  });

  events.push({ tag: "firewall", msg: `Interaction Risk Score: ${data.interaction_risk_score || 0} / 100` });
  events.push({ tag: "firewall", msg: `DIRECTIVE: ${data.verdict || '—'}` });

  return events;
}

// ── Signal UI Helper ──

function updateSignalUI(id, active, activeLabel, inactiveLabel, evidence) {
  const item = document.getElementById(id);
  const badge = document.getElementById(`${id}-badge`);
  const evidenceEl = document.getElementById(`${id}-evidence`);

  if (item) {
    item.classList.toggle('active', active);
  }

  if (badge) {
    const isSignalDanger = id === 'sig-overlay' || id === 'sig-injection';
    const isSignalWarning = id === 'sig-mismatch' || id === 'sig-redirect';
    badge.textContent = active ? activeLabel : inactiveLabel;
    badge.className = `sig-status-badge font-mono ${active ? (isSignalDanger ? 'danger' : isSignalWarning ? 'warning' : 'info') : 'safe'}`;
  }

  if (evidenceEl) evidenceEl.textContent = evidence;
}

// ── Forensic Tab Renderers ──

function setElText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val !== undefined && val !== null && val !== '' ? String(val) : '—';
}

function renderFindings(findings) {
  const container = document.getElementById('findings-container');
  const badgeCount = document.getElementById('badge-count-findings');
  if (!container) return;

  container.innerHTML = '';
  if (badgeCount) badgeCount.textContent = String(findings.length);

  const filtered = (currentFilter === 'all')
    ? findings
    : findings.filter(f => (f.severity || '').toLowerCase() === currentFilter);

  if (filtered.length === 0) {
    container.innerHTML = `<div style="padding: 2rem; text-align: center; color: var(--text-subtle); font-size: 0.88rem;">No threat findings detected matching current filter criteria.</div>`;
    return;
  }

  filtered.forEach(item => {
    const card = document.createElement('div');
    const sev = (item.severity || 'low').toLowerCase();
    card.className = `finding-card sev-${sev}`;
    card.innerHTML = `
      <div class="finding-header">
        <span class="badge-tag ${sev}">${escapeHtml(item.severity || 'INFO')}</span>
        <h4 class="finding-title">${escapeHtml(item.title)}</h4>
      </div>
      <p class="finding-desc">${escapeHtml(item.description)}</p>
      ${item.evidence ? `<div class="finding-code-frame font-mono"><code>${escapeHtml(item.evidence)}</code></div>` : ''}
    `;
    container.appendChild(card);
  });
}

function renderInteractions(interactions) {
  const tbody = document.getElementById('interaction-table-body');
  const badgeCount = document.getElementById('badge-count-interactions');
  if (!tbody) return;

  tbody.innerHTML = '';
  if (badgeCount) badgeCount.textContent = String(interactions.length);

  if (interactions.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-subtle); padding: 2rem;">No interactive DOM elements evaluated.</td></tr>`;
    return;
  }

  interactions.forEach(item => {
    const tr = document.createElement('tr');
    const r = (item.risk || 'LOW').toLowerCase();
    tr.innerHTML = `
      <td><span class="dom-tag font-mono">${escapeHtml(item.element)}</span></td>
      <td><strong style="color: var(--text-main);">${escapeHtml(item.visible_text)}</strong></td>
      <td>${escapeHtml(item.type)}</td>
      <td><span class="font-mono" style="color: var(--text-muted);">${escapeHtml(item.destination)}</span></td>
      <td>${escapeHtml(item.visibility)}</td>
      <td class="align-right"><span class="table-badge ${r}">${escapeHtml(item.risk)}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderRedirects(chain) {
  const container = document.getElementById('redirect-chain-container');
  const badgeCount = document.getElementById('badge-count-redirects');
  if (!container) return;

  container.innerHTML = '';
  if (badgeCount) badgeCount.textContent = String(chain.length);

  if (chain.length === 0) {
    container.innerHTML = `<div style="padding: 2rem; color: var(--text-subtle); font-size: 0.86rem; text-align: center;">Direct socket request. No redirect hops detected.</div>`;
    return;
  }

  chain.forEach((node, idx) => {
    const nodeEl = document.createElement('div');
    nodeEl.className = 'network-flow-node';

    let codeClass = 'ok';
    if (node.status >= 300 && node.status < 400) codeClass = 'redirect';
    if (node.status >= 400 || node.severity === 'danger') codeClass = 'danger';

    nodeEl.innerHTML = `
      <div class="flow-node-left">
        <span class="flow-hop-badge font-mono">${idx + 1}</span>
        <div>
          <span class="flow-node-domain font-mono">${escapeHtml(node.domain)}</span>
          <div class="flow-node-type">${escapeHtml(node.type || 'Direct Request')}</div>
        </div>
      </div>
      <span class="http-status-tag font-mono ${codeClass}">${node.status} ${escapeHtml(node.status_text || node.statusText || 'OK')}</span>
    `;
    container.appendChild(nodeEl);

    if (idx < chain.length - 1) {
      const arrow = document.createElement('div');
      arrow.className = 'flow-connector-line';
      arrow.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>`;
      container.appendChild(arrow);
    }
  });
}

function renderJavaScriptSignals(signals) {
  const tbody = document.getElementById('javascript-table-body');
  if (!tbody) return;

  tbody.innerHTML = '';

  if (!signals || signals.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-subtle); padding: 2rem;">No suspicious JavaScript execution hooks detected.</td></tr>`;
    return;
  }

  signals.forEach(item => {
    const tr = document.createElement('tr');
    const sev = (item.severity || 'low').toLowerCase();
    tr.innerHTML = `
      <td><span class="font-mono">${escapeHtml(item.signal)}</span></td>
      <td>${escapeHtml(item.source || 'inline')}</td>
      <td>${escapeHtml(item.details || item.evidence || '')}</td>
      <td class="align-right"><span class="table-badge ${sev}">${escapeHtml(item.severity || 'LOW')}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderAiInsights(ai) {
  const modelName = document.getElementById('ai-model-name');
  const verdictBadge = document.getElementById('ai-verdict-badge');
  const deceptionText = document.getElementById('ai-deception-text');
  const adviceBox = document.getElementById('ai-advice-box');

  if (!ai) {
    if (modelName) modelName.textContent = 'Not available';
    if (verdictBadge) { verdictBadge.textContent = 'N/A'; verdictBadge.className = 'ai-verdict-tag font-mono'; }
    if (deceptionText) deceptionText.textContent = 'AI reasoning was not available for this audit. Configure a Groq API key in settings to enable AI deception analysis.';
    if (adviceBox) adviceBox.textContent = '—';
    return;
  }

  if (modelName) modelName.textContent = ai.model_used || 'Unknown Model';

  const aiVerdict = (ai.ai_verdict || '').toUpperCase();
  const isDanger = aiVerdict === 'BLOCK';
  const isWarning = aiVerdict === 'CAUTION';

  if (verdictBadge) {
    verdictBadge.textContent = ai.ai_verdict || '—';
    verdictBadge.className = `ai-verdict-tag font-mono ${isDanger ? 'danger' : isWarning ? 'warning' : 'safe'}`;
  }

  if (deceptionText) deceptionText.textContent = ai.deception_analysis || ai.executive_summary || '—';
  if (adviceBox) adviceBox.textContent = ai.recommended_action || '—';
}

function renderTelemetry(data) {
  const output = document.getElementById('telemetry-json-output');
  if (!output) return;

  // Build clean telemetry payload for display
  const payload = {
    verdict: data.verdict,
    interaction_risk_score: data.interaction_risk_score,
    target_url: data.target_url,
    intended_task: data.intended_task,
    timestamp: data.timestamp,
    score_breakdown: data.score_breakdown,
    findings: (data.findings || []).map(f => ({ severity: f.severity, title: f.title })),
    redirect_chain: data.redirect_chain,
    javascript_signals: data.javascript_signals,
    ai_insights: data.ai_insights ? { model: data.ai_insights.model_used, verdict: data.ai_insights.ai_verdict } : null,
    telemetry: data.telemetry
  };

  output.textContent = JSON.stringify(payload, null, 2);

  // Wire copy/download buttons
  const copyJsonBtn = document.getElementById('copy-telemetry-button');
  const copyCurlBtn = document.getElementById('copy-curl-btn');
  const downloadBtn = document.getElementById('download-telemetry-btn');

  if (copyJsonBtn) {
    copyJsonBtn.onclick = () => {
      navigator.clipboard.writeText(JSON.stringify(payload, null, 2)).then(() => showToast("JSON copied to clipboard", "safe"));
    };
  }

  if (copyCurlBtn) {
    copyCurlBtn.onclick = () => {
      const curl = `curl -X POST ${CONFIG.apiEndpoint} \\\n  -H "Content-Type: application/json" \\\n  -d '{"url": "${data.target_url}", "task": "${data.intended_task}"}'`;
      navigator.clipboard.writeText(curl).then(() => showToast("cURL command copied", "safe"));
    };
  }

  if (downloadBtn) {
    downloadBtn.onclick = () => {
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `clickguard-audit-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showToast("Dossier downloaded", "safe");
    };
  }

  // Wire export button in verdict section
  const exportBtn = document.getElementById('btn-export-audit');
  if (exportBtn) {
    exportBtn.onclick = () => {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `clickguard-dossier-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showToast("Full audit dossier exported", "safe");
    };
  }
}

// ============================================================================
// 6. UTILITIES
// ============================================================================

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

let toastTimeout = null;
function showToast(message, type) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.style.cssText = 'position: fixed; bottom: 24px; right: 24px; z-index: 99999; display: flex; flex-direction: column; gap: 8px; pointer-events: none;';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  const bgColor = type === 'danger' ? '#F43F5E' : type === 'warning' ? '#F59E0B' : '#10B981';
  toast.style.cssText = `
    background: ${bgColor}; color: #fff; padding: 10px 18px; border-radius: 8px;
    font-size: 13px; font-family: 'Plus Jakarta Sans', sans-serif; font-weight: 600;
    box-shadow: 0 4px 16px rgba(0,0,0,0.2); pointer-events: auto;
    animation: toast-in 0.3s ease; max-width: 420px;
  `;
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}