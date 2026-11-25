(() => {
  'use strict';

  const QUICK_REMARK_TAGS = ['电脑', '手机', '平板', '测试机', '办公机'];
  const DURATION_UNITS = ['m', 'h', 'd'];

  const state = {
    authenticated: false,
    mockMode: false,
    snapshot: null,
    serverClockOffsetMs: 0,
    ws: null,
    wsTimer: null,
    filter: localStorage.getItem('gk_filter') || 'all',
    sortBy: localStorage.getItem('gk_sort_by') || 'smart',
    sortDir: localStorage.getItem('gk_sort_dir') || 'desc',
    durationUnit: localStorage.getItem('gk_duration_unit') || 'm',
    search: '',
    editingMac: null,
    editingDraft: '',
    popoverMac: null,
    knownPendingMacs: new Set(),
    hasReceivedInitialState: false,
    audioCtx: null,
    rowCache: new Map(),
    tunnelOpen: false,
  };

  if (!DURATION_UNITS.includes(state.durationUnit)) state.durationUnit = 'm';

  const els = {
    loginOverlay: document.getElementById('login-overlay'),
    loginForm: document.getElementById('login-form'),
    loginPassword: document.getElementById('login-password'),
    loginHint: document.getElementById('login-hint'),
    loginError: document.getElementById('login-error'),
    appShell: document.getElementById('app-shell'),
    modeBadge: document.getElementById('mode-badge'),
    wsDot: document.getElementById('ws-dot'),
    wsStatusText: document.getElementById('ws-status-text'),
    routerMeta: document.getElementById('router-meta'),
    openPortalLink: document.getElementById('open-portal-link'),
    btnToggleTunnel: document.getElementById('btn-toggle-tunnel'),
    tunnelNavDot: document.getElementById('tunnel-nav-dot'),
    btnOpenAudit: document.getElementById('btn-open-audit'),
    btnOpenGuide: document.getElementById('btn-open-guide'),
    btnSoundToggle: document.getElementById('btn-sound-toggle'),
    soundLabel: document.getElementById('sound-label'),
    btnSettings: document.getElementById('btn-settings'),
    btnLogout: document.getElementById('btn-logout'),
    whitelistBanner: document.getElementById('whitelist-banner'),
    whitelistBannerText: document.getElementById('whitelist-banner-text'),
    btnProtectViewer: document.getElementById('btn-protect-viewer'),
    masterSwitchCard: document.getElementById('master-switch-card'),
    masterBadge: document.getElementById('master-badge'),
    masterDesc: document.getElementById('master-desc'),
    btnMasterSwitch: document.getElementById('btn-master-switch'),
    masterSwitchText: document.getElementById('master-switch-text'),
    kpiAuthCount: document.getElementById('kpi-auth-count'),
    kpiMaxCount: document.getElementById('kpi-max-count'),
    kpiQuotaBar: document.getElementById('kpi-quota-bar'),
    kpiAuthSub: document.getElementById('kpi-auth-sub'),
    btnMaxDec: document.getElementById('btn-max-dec'),
    btnMaxInc: document.getElementById('btn-max-inc'),
    kpiPendingCard: document.getElementById('kpi-pending-card'),
    kpiPendingCount: document.getElementById('kpi-pending-count'),
    kpiPendingBadge: document.getElementById('kpi-pending-badge'),
    kpiPendingSub: document.getElementById('kpi-pending-sub'),
    kpiBlockedCount: document.getElementById('kpi-blocked-count'),
    kpiTotalTraffic: document.getElementById('kpi-total-traffic'),
    kpiBlockedSub: document.getElementById('kpi-blocked-sub'),
    kpiNftBadge: document.getElementById('kpi-nft-badge'),
    probeDomestic: document.getElementById('probe-domestic'),
    probeProxy: document.getElementById('probe-proxy'),
    kpiHealthSub: document.getElementById('kpi-health-sub'),
    tunnelDrawer: document.getElementById('tunnel-drawer'),
    tunnelBadge: document.getElementById('tunnel-badge'),
    tunnelDesc: document.getElementById('tunnel-desc'),
    tunnelUrlBox: document.getElementById('tunnel-url-box'),
    tunnelPublicUrl: document.getElementById('tunnel-public-url'),
    btnCopyTunnel: document.getElementById('btn-copy-tunnel'),
    tunnelLogs: document.getElementById('tunnel-logs'),
    tunnelModeSelect: document.getElementById('tunnel-mode-select'),
    btnTunnelInstall: document.getElementById('btn-tunnel-install'),
    btnTunnelStart: document.getElementById('btn-tunnel-start'),
    btnTunnelStop: document.getElementById('btn-tunnel-stop'),
    pendingStrip: document.getElementById('pending-strip'),
    pendingCards: document.getElementById('pending-cards'),
    mockToolbar: document.getElementById('mock-toolbar'),
    btnMockSim: document.getElementById('btn-mock-sim'),
    btnMockReset: document.getElementById('btn-mock-reset'),
    filterTabs: document.getElementById('filter-tabs'),
    cntAll: document.getElementById('cnt-all'),
    cntApproved: document.getElementById('cnt-approved'),
    cntPending: document.getElementById('cnt-pending'),
    cntPaused: document.getElementById('cnt-paused'),
    cntWhitelist: document.getElementById('cnt-whitelist'),
    sortBy: document.getElementById('sort-by'),
    btnSortDir: document.getElementById('btn-sort-dir'),
    deviceSearch: document.getElementById('device-search'),
    devicesList: document.getElementById('devices-list'),
    timedPausePopover: document.getElementById('timed-pause-popover'),
    customPauseVal: document.getElementById('custom-pause-val'),
    customPauseUnit: document.getElementById('custom-pause-unit'),
    btnCustomPauseGo: document.getElementById('btn-custom-pause-go'),
    btnPermPauseGo: document.getElementById('btn-perm-pause-go'),
    conflictModal: document.getElementById('conflict-modal'),
    conflictMessage: document.getElementById('conflict-message'),
    btnEvictOldest: document.getElementById('btn-evict-oldest'),
    conflictActiveList: document.getElementById('conflict-active-list'),
    btnConflictCancel: document.getElementById('btn-conflict-cancel'),
    guideModal: document.getElementById('guide-modal'),
    btnGuideClose: document.getElementById('btn-guide-close'),
    auditModal: document.getElementById('audit-modal'),
    btnSwitchAudit: document.getElementById('btn-switch-audit'),
    btnSwitchScript: document.getElementById('btn-switch-script'),
    btnAuditClose: document.getElementById('btn-audit-close'),
    auditPane: document.getElementById('audit-pane'),
    scriptPane: document.getElementById('script-pane'),
    scriptRuleCount: document.getElementById('script-rule-count'),
    scriptContent: document.getElementById('script-content'),
    btnCopyScript: document.getElementById('btn-copy-script'),
    settingsModal: document.getElementById('settings-modal'),
    settingsForm: document.getElementById('settings-form'),
    setMaxDevices: document.getElementById('set-max-devices'),
    setPortalTitle: document.getElementById('set-portal-title'),
    setTunnelToken: document.getElementById('set-tunnel-token'),
    setTokenStatus: document.getElementById('set-token-status'),
    setNewPassword: document.getElementById('set-new-password'),
    setAllowPorts: document.getElementById('set-allow-ports'),
    btnSettingsClose: document.getElementById('btn-settings-close'),
    btnSettingsCancel: document.getElementById('btn-settings-cancel'),
    toastContainer: document.getElementById('toast-container'),
  };

  // 全局点击水波纹动效（GPU transform + opacity 合成，极速不掉帧）
  document.addEventListener('pointerdown', (e) => {
    const target = e.target.closest('.btn, .tab-btn, .tag-chip, .duration-chip, .stepper-btn, .switch-btn, .conflict-device-btn');
    if (!target || target.disabled) return;
    const rect = target.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    const wave = document.createElement('span');
    wave.className = 'ripple';
    wave.style.width = `${size}px`;
    wave.style.height = `${size}px`;
    wave.style.left = `${e.clientX - rect.left - size / 2}px`;
    wave.style.top = `${e.clientY - rect.top - size / 2}px`;
    target.appendChild(wave);
    setTimeout(() => wave.remove(), 420);
  });

  function setText(el, val) {
    if (el && el.textContent !== val) el.textContent = val;
  }

  function escapeHTML(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function showToast(msg, type = 'info') {
    const div = document.createElement('div');
    div.className = `toast ${type === 'error' ? 'toast-error' : type === 'success' ? 'toast-success' : ''}`;
    div.textContent = msg;
    els.toastContainer.appendChild(div);
    setTimeout(() => div.remove(), 2800);
  }

  function flashRow(mac, kind) {
    const entry = state.rowCache.get(mac);
    if (!entry) return;
    const cls = kind === 'danger' ? 'flash-danger' : kind === 'info' ? 'flash-info' : 'flash-success';
    entry.el.classList.remove('flash-success', 'flash-danger', 'flash-info');
    void entry.el.offsetWidth;
    entry.el.classList.add(cls);
  }

  function formatRate(bps) {
    if (!bps || bps <= 0) return '0 B/s';
    const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
    let v = bps;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    return `${v >= 10 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
  }

  function formatBytes(bytes) {
    if (!bytes || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let v = bytes;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    return `${v >= 10 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
  }

  function formatClock(iso) {
    if (!iso) return '--:--:--';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '--:--:--';
    return d.toLocaleTimeString('zh-CN', { hour12: false });
  }

  function alignedNowMs() {
    return Date.now() + state.serverClockOffsetMs;
  }

  function formatConnectTime(d) {
    const raw = (d.status === 'approved' || d.is_whitelist) ? (d.approved_at || d.first_seen_at) : (d.requested_at || d.first_seen_at);
    if (!raw) return { label: '时间未知', full: '' };
    const dt = new Date(raw);
    if (Number.isNaN(dt.getTime()) || dt.getFullYear() < 2000) return { label: '时间未知', full: '' };
    const now = new Date(alignedNowMs());
    const hm = `${String(dt.getHours()).padStart(2, '0')}:${String(dt.getMinutes()).padStart(2, '0')}`;
    const full = `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}-${String(dt.getDate()).padStart(2, '0')} ${hm}:${String(dt.getSeconds()).padStart(2, '0')}`;
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    const dayDiff = Math.floor((todayStart - new Date(dt.getFullYear(), dt.getMonth(), dt.getDate()).getTime()) / 86400000);
    let prefix = `${dt.getMonth() + 1}-${dt.getDate()}`;
    if (dayDiff === 0) prefix = '今天';
    else if (dayDiff === 1) prefix = '昨天';
    return { label: `${prefix} ${hm} 联网`, full };
  }

  function getLiveOnlineSeconds(d) {
    if (!d.online || (d.status !== 'approved' && !d.is_whitelist)) return 0;
    const raw = d.approved_at || d.first_seen_at;
    if (raw) {
      const ts = new Date(raw).getTime();
      if (!Number.isNaN(ts) && ts > 946684800000) {
        return Math.max(0, Math.floor((alignedNowMs() - ts) / 1000));
      }
    }
    return d.online_duration_sec || 0;
  }

  // 分钟 / 小时 / 天三种单位均精确到秒，每秒持续走表不卡顿
  function formatDurationByUnit(sec, unit) {
    if (sec <= 0) {
      return unit === 'd' ? '0 天 00 时 00 分 00 秒' : unit === 'h' ? '0 时 00 分 00 秒' : '0 秒';
    }
    if (unit === 'h') {
      const h = Math.floor(sec / 3600);
      const m = Math.floor((sec % 3600) / 60);
      const s = sec % 60;
      return `${h} 时 ${String(m).padStart(2, '0')} 分 ${String(s).padStart(2, '0')} 秒`;
    }
    if (unit === 'd') {
      const days = Math.floor(sec / 86400);
      const h = Math.floor((sec % 86400) / 3600);
      const m = Math.floor((sec % 3600) / 60);
      const s = sec % 60;
      return `${days} 天 ${String(h).padStart(2, '0')} 时 ${String(m).padStart(2, '0')} 分 ${String(s).padStart(2, '0')} 秒`;
    }
    const mins = Math.floor(sec / 60);
    const s = sec % 60;
    if (mins === 0) return `${s} 秒`;
    return `${mins} 分 ${String(s).padStart(2, '0')} 秒`;
  }

  function getLivePauseRemainingSec(d) {
    if (d.status !== 'paused' || !d.pause_until) return 0;
    const ts = new Date(d.pause_until).getTime();
    if (Number.isNaN(ts)) return 0;
    return Math.max(0, Math.ceil((ts - alignedNowMs()) / 1000));
  }

  function formatCountdown(sec) {
    if (sec <= 0) return '即将恢复...';
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    if (h > 0) return `${h}时${String(m).padStart(2, '0')}分${String(s).padStart(2, '0')}秒`;
    if (m > 0) return `${m}分${String(s).padStart(2, '0')}秒`;
    return `${s}秒`;
  }

  function getDeviceIconSVG(d) {
    const txt = `${d.admin_remark || ''} ${d.requested_name || ''} ${d.hostname || ''}`.toLowerCase();
    if (/电脑|pc|mac|book|imac|desktop|laptop|thinkpad|win|ubuntu|台式|笔记本/.test(txt)) {
      return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>';
    }
    if (/平板|ipad|pad|tablet/.test(txt)) {
      return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="16" height="20" x="4" y="2" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>';
    }
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="20" x="5" y="2" rx="2" ry="2"/><path d="M12 18h.01"/></svg>';
  }

  function playAlertChime() {
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      if (!state.audioCtx) state.audioCtx = new AudioCtx();
      if (state.audioCtx.state === 'suspended') state.audioCtx.resume().catch(() => {});
      const now = state.audioCtx.currentTime;
      const tone = (freq, off, dur) => {
        const osc = state.audioCtx.createOscillator();
        const gain = state.audioCtx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(freq, now + off);
        gain.gain.setValueAtTime(0.001, now + off);
        gain.gain.exponentialRampToValueAtTime(0.11, now + off + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.001, now + off + dur);
        osc.connect(gain);
        gain.connect(state.audioCtx.destination);
        osc.start(now + off);
        osc.stop(now + off + dur + 0.02);
      };
      tone(880, 0, 0.14);
      tone(1174.66, 0.13, 0.22);
    } catch (_) {}
  }

  async function apiFetch(url, options = {}) {
    const resp = await fetch(url, {
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
      ...options,
    });
    const text = await resp.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : {};
    } catch (_) {
      data = { error: text };
    }
    if (resp.status === 401) {
      state.authenticated = false;
      closeWebSocket();
      showLoginView();
      throw new Error(data?.error || '登录已过期');
    }
    return { status: resp.status, ok: resp.ok, data };
  }

  async function bootstrap() {
    els.sortBy.value = state.sortBy;
    updateSortDirBtn();
    syncActiveFilterTab();

    try {
      const res = await fetch('/api/auth/me', { credentials: 'same-origin' });
      const info = await res.json();
      state.mockMode = Boolean(info.mock_mode);
      if (state.mockMode) els.loginHint.classList.remove('hidden');
      if (info.authenticated) {
        state.authenticated = true;
        showDashboardView();
        await fetchInitialState();
        connectWebSocket();
      } else {
        showLoginView();
      }
    } catch (_) {
      showLoginView();
      showToast('连接后端失败，请确认服务正在运行', 'error');
    }
  }

  function showLoginView() {
    els.loginOverlay.classList.remove('hidden');
    els.appShell.classList.add('hidden');
    els.loginPassword.focus();
  }

  function showDashboardView() {
    els.loginOverlay.classList.add('hidden');
    els.appShell.classList.remove('hidden');
  }

  async function fetchInitialState() {
    const { ok, data } = await apiFetch('/api/state');
    if (ok && data) applySnapshot(data);
  }

  function connectWebSocket() {
    closeWebSocket();
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${window.location.host}/api/ws`);
    state.ws = ws;

    els.wsDot.className = 'dot dot-amber';
    setText(els.wsStatusText, '连接中...');

    ws.onopen = () => {
      els.wsDot.className = 'dot dot-green';
      setText(els.wsStatusText, '实时同步');
    };

    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if (msg.type === 'state' && msg.data) applySnapshot(msg.data);
      } catch (_) {}
    };

    ws.onclose = () => {
      els.wsDot.className = 'dot dot-rose';
      setText(els.wsStatusText, '重连中...');
      if (state.authenticated) state.wsTimer = setTimeout(connectWebSocket, 1800);
    };

    ws.onerror = () => ws.close();
  }

  function closeWebSocket() {
    if (state.wsTimer) {
      clearTimeout(state.wsTimer);
      state.wsTimer = null;
    }
    if (state.ws) {
      try { state.ws.close(); } catch (_) {}
      state.ws = null;
    }
  }

  function applySnapshot(snap) {
    if (snap.generated_at) {
      const serverTs = new Date(snap.generated_at).getTime();
      if (!Number.isNaN(serverTs) && serverTs > 946684800000) {
        state.serverClockOffsetMs = serverTs - Date.now();
      }
    }
    state.snapshot = snap;
    state.mockMode = Boolean(snap.health?.mock_mode);

    const currentPending = new Set(
      (snap.devices || []).filter((d) => d.status === 'pending').map((d) => d.mac)
    );
    if (state.hasReceivedInitialState) {
      let hasNewPending = false;
      currentPending.forEach((mac) => {
        if (!state.knownPendingMacs.has(mac)) hasNewPending = true;
      });
      if (hasNewPending) {
        if (snap.settings?.sound_enabled) playAlertChime();
        showToast('收到新的联网申请，请审批！');
      }
    }
    state.knownPendingMacs = currentPending;
    state.hasReceivedInitialState = true;

    renderAllFromSnapshot();
  }

  function renderAllFromSnapshot() {
    const snap = state.snapshot;
    if (!snap) return;
    renderTopbar(snap);
    renderWhitelistBanner(snap);
    renderMasterSwitch(snap);
    renderKPIs(snap);
    renderPendingStrip(snap);
    renderTunnel(snap);
    reconcileDeviceList(snap);
    if (!els.auditModal.classList.contains('hidden')) {
      renderAuditLogs(snap);
    }
  }

  function renderTopbar(snap) {
    const h = snap.health || {};
    if (h.mock_mode) {
      els.modeBadge.className = 'pill pill-indigo';
      setText(els.modeBadge, '本地仿真');
      els.mockToolbar.classList.remove('hidden');
      const portalPort = h.portal_port || 8089;
      if (window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost') {
        els.openPortalLink.href = `http://${window.location.hostname}:${portalPort}/portal`;
      } else {
        els.openPortalLink.href = '/portal';
      }
    } else {
      els.modeBadge.className = 'pill pill-success';
      setText(els.modeBadge, '软路由生产');
      els.mockToolbar.classList.add('hidden');
      els.openPortalLink.href = '/portal';
    }
    setText(els.routerMeta, `网关 ${h.router_ip || '192.168.6.1'} (${h.lan_iface || 'br-lan'})`);
    setText(els.soundLabel, snap.settings?.sound_enabled ? '提示音开' : '提示音关');
    els.tunnelNavDot.className = snap.tunnel?.connected
      ? 'dot dot-green'
      : snap.tunnel?.running ? 'dot dot-amber' : 'dot dot-gray';
  }

  function renderMasterSwitch(snap) {
    const enabled = snap.settings?.gatekeeper_enabled !== false;
    els.btnMasterSwitch.setAttribute('aria-checked', String(enabled));
    els.btnMasterSwitch.classList.toggle('on', enabled);
    els.masterSwitchCard.classList.toggle('is-enabled', enabled);
    els.masterSwitchCard.classList.toggle('is-bypass', !enabled);
    setText(els.masterSwitchText, enabled ? '已开启' : '已关闭直通');
    if (enabled) {
      els.masterBadge.className = 'pill pill-success';
      setText(els.masterBadge, '管控运行中');
      setText(els.masterDesc, '开启时：新手机需填昵称并审批才能上网，支持断网与并发数量限制；关闭后：所有设备免填昵称直接自由上网。');
    } else {
      els.masterBadge.className = 'pill pill-amber';
      setText(els.masterBadge, '自由直通模式');
      setText(els.masterDesc, '总开关已关闭：已自动卸除拦截规则，任何手机无需输入昵称均可直接联网且不受设备数限制。');
    }
  }

  function renderWhitelistBanner(snap) {
    if (snap.viewer_whitelisted) {
      els.whitelistBanner.classList.add('hidden');
    } else {
      els.whitelistBanner.classList.remove('hidden');
      setText(els.whitelistBannerText, `当前控制机（${snap.viewer_ip}${snap.viewer_mac ? ' / ' + snap.viewer_mac : ''}）尚未列入白名单，建议一键保护防误断网。`);
    }
  }

  function renderKPIs(snap) {
    const devices = snap.devices || [];
    const max = snap.settings?.max_concurrent_devices || 2;
    const gkEnabled = snap.settings?.gatekeeper_enabled !== false;
    let authCount = 0;
    let authOnline = 0;
    let wlCount = 0;
    let pendingCount = 0;
    let pausedCount = 0;
    let blockedCount = 0;
    let rxSum = 0;
    let txSum = 0;

    for (const d of devices) {
      if (d.is_whitelist) {
        wlCount++;
        rxSum += d.rx_rate_bps || 0;
        txSum += d.tx_rate_bps || 0;
      } else if (d.status === 'approved') {
        authCount++;
        if (d.online) authOnline++;
        rxSum += d.rx_rate_bps || 0;
        txSum += d.tx_rate_bps || 0;
      } else if (d.status === 'pending') {
        pendingCount++;
      } else if (d.status === 'paused') {
        pausedCount++;
        blockedCount++;
      } else {
        blockedCount++;
      }
    }

    setText(els.cntAll, String(devices.length));
    setText(els.cntApproved, String(authCount));
    setText(els.cntPending, String(pendingCount));
    setText(els.cntPaused, String(pausedCount));
    setText(els.cntWhitelist, String(wlCount));

    const pct = Math.min(100, Math.round((authCount / max) * 100));
    setText(els.kpiAuthCount, String(authCount));
    setText(els.kpiMaxCount, String(max));
    els.kpiQuotaBar.style.width = `${pct}%`;
    els.kpiQuotaBar.className = `progress-fill ${authCount >= max ? 'full' : ''}`;
    setText(els.kpiAuthSub, `在线 ${authOnline} 台 · 白名单 ${wlCount} 台（不占名额）`);

    setText(els.kpiPendingCount, String(pendingCount));
    if (pendingCount > 0) {
      els.kpiPendingCard.classList.add('alert-flash');
      els.kpiPendingBadge.className = 'pill pill-amber';
      setText(els.kpiPendingBadge, `${pendingCount} 台待批`);
    } else {
      els.kpiPendingCard.classList.remove('alert-flash');
      els.kpiPendingBadge.className = 'pill pill-muted';
      setText(els.kpiPendingBadge, '无新申请');
    }

    setText(els.kpiBlockedCount, String(blockedCount));
    setText(els.kpiTotalTraffic, `↓ ${formatRate(rxSum)} · ↑ ${formatRate(txSum)}`);
    setText(els.kpiBlockedSub, gkEnabled ? `当前暂停断网 ${pausedCount} 台 · 已封堵 PassWall 绕过` : '总开关已关闭（自由直通中）');

    const h = snap.health || {};
    els.probeDomestic.style.color = h.domestic_reachable ? '#34d399' : '#fb7185';
    setText(els.probeDomestic, h.domestic_reachable ? `通 (${h.domestic_latency_ms}ms)` : '断');
    els.probeProxy.style.color = h.proxy_reachable ? '#38bdf8' : '#fbbf24';
    setText(els.probeProxy, h.proxy_reachable ? `通 (${h.proxy_latency_ms}ms)` : '待定');
    setText(els.kpiNftBadge, !gkEnabled ? '已直通' : h.nftables_active ? `已防护 (${h.firewall_rules_count || 0})` : '未就绪');
    setText(els.kpiHealthSub, `${h.passwall_active ? 'PassWall 运行中' : 'PassWall 未运行'} · 负载 ${h.cpu_load || '-'}`);
  }

  function renderPendingStrip(snap) {
    const gkEnabled = snap.settings?.gatekeeper_enabled !== false;
    const pendingList = gkEnabled ? (snap.devices || []).filter((d) => d.status === 'pending') : [];
    if (pendingList.length === 0) {
      els.pendingStrip.classList.add('hidden');
      if (els.pendingCards.childElementCount > 0) els.pendingCards.innerHTML = '';
      return;
    }
    els.pendingStrip.classList.remove('hidden');
    const sig = pendingList.map((d) => `${d.mac}:${d.requested_name}:${d.ip}`).join('|');
    if (els.pendingCards.dataset.sig === sig) return;
    els.pendingCards.dataset.sig = sig;
    els.pendingCards.innerHTML = pendingList.map((d) => `
      <div class="pending-item">
        <div>
          <div class="pending-item-name">${escapeHTML(d.requested_name || d.display_name)}</div>
          <div class="pending-item-meta">${escapeHTML(d.ip || '-')} · ${escapeHTML(d.mac)}</div>
        </div>
        <button type="button" class="btn btn-success btn-sm" data-action="approve" data-mac="${escapeHTML(d.mac)}">批准连网</button>
      </div>
    `).join('');
  }

  function renderTunnel(snap) {
    const t = snap.tunnel || {};
    const h = snap.health || {};
    const needInstall = !h.mock_mode && !h.cloudflared_installed;
    els.btnTunnelInstall.classList.toggle('hidden', !needInstall);

    if (t.running) {
      if (t.connected) {
        els.tunnelBadge.className = 'pill pill-success';
        setText(els.tunnelBadge, t.mode === 'mock' || h.mock_mode ? '已连通（仿真）' : 'HTTP/2 已连通');
      } else {
        els.tunnelBadge.className = 'pill pill-amber';
        setText(els.tunnelBadge, '正在连接边缘节点...');
      }
      setText(els.tunnelDesc, t.status_text || '全球访问隧道运行中');
      els.btnTunnelStart.classList.add('hidden');
      els.btnTunnelStop.classList.remove('hidden');
      if (t.public_url) {
        els.tunnelUrlBox.classList.remove('hidden');
        els.tunnelPublicUrl.href = t.public_url;
        setText(els.tunnelPublicUrl, t.public_url);
      } else {
        els.tunnelUrlBox.classList.add('hidden');
      }
    } else {
      els.tunnelBadge.className = needInstall ? 'pill pill-amber' : 'pill pill-muted';
      setText(els.tunnelBadge, needInstall ? '缺少 cloudflared' : '未启用');
      setText(els.tunnelDesc, t.error ? `提示：${t.error}` : '已启用 HTTP/2 协议穿透国内网络，无需公网 IP 与域名，一键生成加密 HTTPS 地址。');
      els.btnTunnelStart.classList.remove('hidden');
      els.btnTunnelStop.classList.add('hidden');
      els.tunnelUrlBox.classList.add('hidden');
    }

    const logs = t.recent_logs || [];
    if (logs.length > 0) {
      els.tunnelLogs.classList.remove('hidden');
      setText(els.tunnelLogs, logs.join('\n'));
    } else {
      els.tunnelLogs.classList.add('hidden');
    }
  }

  function computeSortedFilteredDevices(snap) {
    const q = state.search.toLowerCase();
    const list = (snap.devices || []).filter((d) => {
      if (state.filter === 'approved' && (d.status !== 'approved' || d.is_whitelist)) return false;
      if (state.filter === 'pending' && d.status !== 'pending') return false;
      if (state.filter === 'paused' && d.status !== 'paused') return false;
      if (state.filter === 'whitelist' && !d.is_whitelist) return false;
      if (q) {
        const hay = `${d.display_name} ${d.requested_name} ${d.admin_remark} ${d.hostname} ${d.ip} ${d.mac}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    const dir = state.sortDir === 'asc' ? 1 : -1;
    const rank = (d) => {
      if (d.status === 'pending') return 0;
      if (d.status === 'approved' && !d.is_whitelist) return 1;
      if (d.is_whitelist) return 2;
      if (d.status === 'paused') return 3;
      return 4;
    };
    const tsOf = (iso) => {
      if (!iso) return 0;
      const t = new Date(iso).getTime();
      return Number.isNaN(t) ? 0 : t;
    };
    const ipNum = (ip) => {
      const p = (ip || '').split('.').map(Number);
      if (p.length !== 4 || p.some(Number.isNaN)) return 0;
      return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
    };

    list.sort((a, b) => {
      switch (state.sortBy) {
        case 'approved_at': {
          const ta = tsOf(a.approved_at || a.first_seen_at);
          const tb = tsOf(b.approved_at || b.first_seen_at);
          if (ta !== tb) return (ta - tb) * dir;
          break;
        }
        case 'duration': {
          const da = getLiveOnlineSeconds(a);
          const db = getLiveOnlineSeconds(b);
          if (da !== db) return (da - db) * dir;
          break;
        }
        case 'rate': {
          const ra = (a.rx_rate_bps || 0) + (a.tx_rate_bps || 0);
          const rb = (b.rx_rate_bps || 0) + (b.tx_rate_bps || 0);
          if (ra !== rb) return (ra - rb) * dir;
          break;
        }
        case 'name': {
          const cmp = (a.display_name || a.mac).localeCompare(b.display_name || b.mac, 'zh-CN');
          if (cmp !== 0) return cmp * dir;
          break;
        }
        case 'ip': {
          const ia = ipNum(a.ip);
          const ib = ipNum(b.ip);
          if (ia !== ib) return (ia - ib) * dir;
          break;
        }
        default: {
          const ra = rank(a);
          const rb = rank(b);
          if (ra !== rb) return ra - rb;
          if (a.online !== b.online) return a.online ? -1 : 1;
          const ta = tsOf(a.approved_at || a.first_seen_at);
          const tb = tsOf(b.approved_at || b.first_seen_at);
          if (ta !== tb) return (ta - tb) * dir;
        }
      }
      return a.mac.localeCompare(b.mac);
    });
    return list;
  }

  function createDeviceRow(mac) {
    const el = document.createElement('div');
    el.className = 'device-row';
    el.dataset.mac = mac;
    el.innerHTML = `
      <div class="dev-identity">
        <div class="dev-avatar">
          <span class="dev-icon-slot"></span>
          <span class="dot dot-gray"></span>
        </div>
        <div class="dev-name-wrap">
          <div class="dev-name-view">
            <div class="dev-name-line">
              <span class="dev-title" data-action="edit-remark" title="点击修改设备备注"></span>
              <button type="button" class="btn-edit-name" title="备注名称" data-action="edit-remark">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>
              </button>
              <span class="dev-status-pill"></span>
            </div>
            <div class="dev-subline">
              <span class="dev-origin-text"></span>
              <span class="dev-connect-time"></span>
              <button type="button" class="duration-chip hidden" data-action="cycle-duration" title="点击切换时间单位：分钟 → 小时 → 天"></button>
            </div>
          </div>
          <div class="remark-editor hidden">
            <div class="remark-editor-row">
              <input type="text" class="input" data-remark-input maxlength="40" placeholder="输入备注（如：电脑）" />
              <button type="button" class="btn btn-primary btn-xs" data-action="save-remark">保存</button>
              <button type="button" class="btn btn-ghost btn-xs" data-action="cancel-remark">取消</button>
            </div>
            <div class="quick-tags">
              ${QUICK_REMARK_TAGS.map((t) => `<button type="button" class="tag-chip" data-action="quick-tag" data-tag="${t}">${t}</button>`).join('')}
            </div>
          </div>
        </div>
      </div>

      <div class="dev-net">
        <span class="dev-ip"></span>
        <span class="dev-mac"></span>
      </div>

      <div class="dev-metrics">
        <div class="rate-row">
          <span class="rate-down"></span>
          <span class="rate-up"></span>
        </div>
        <div class="metrics-sub"></div>
        <div class="countdown-text hidden"></div>
        <div class="error-inline hidden"></div>
      </div>

      <div class="dev-actions"></div>
    `;

    el.querySelectorAll('[data-action]').forEach((node) => {
      node.dataset.mac = mac;
    });
    const inp = el.querySelector('[data-remark-input]');
    inp.dataset.mac = mac;

    return {
      el,
      refs: {
        iconSlot: el.querySelector('.dev-icon-slot'),
        dot: el.querySelector('.dot'),
        nameView: el.querySelector('.dev-name-view'),
        title: el.querySelector('.dev-title'),
        statusPill: el.querySelector('.dev-status-pill'),
        originText: el.querySelector('.dev-origin-text'),
        connectTime: el.querySelector('.dev-connect-time'),
        durationChip: el.querySelector('.duration-chip'),
        remarkEditor: el.querySelector('.remark-editor'),
        remarkInput: inp,
        ip: el.querySelector('.dev-ip'),
        macEl: el.querySelector('.dev-mac'),
        rateDown: el.querySelector('.rate-down'),
        rateUp: el.querySelector('.rate-up'),
        metricsSub: el.querySelector('.metrics-sub'),
        countdownText: el.querySelector('.countdown-text'),
        errorInline: el.querySelector('.error-inline'),
        actions: el.querySelector('.dev-actions'),
      },
      prev: {},
    };
  }

  function updateDeviceRow(entry, d) {
    const { el, refs, prev } = entry;

    const rowCls = `device-row ${d.status === 'pending' ? 'is-pending' : ''} ${d.status === 'paused' ? 'is-paused' : ''}`;
    if (prev.rowCls !== rowCls) {
      el.className = rowCls;
      prev.rowCls = rowCls;
    }

    const iconHtml = getDeviceIconSVG(d);
    if (prev.iconHtml !== iconHtml) {
      refs.iconSlot.innerHTML = iconHtml;
      prev.iconHtml = iconHtml;
    }

    const dotCls = `dot ${!d.online ? 'dot-gray' : d.status === 'pending' ? 'dot-amber' : d.status === 'paused' ? 'dot-rose' : 'dot-green'}`;
    if (prev.dotCls !== dotCls) {
      refs.dot.className = dotCls;
      prev.dotCls = dotCls;
    }

    const isEditing = state.editingMac === d.mac;
    if (prev.isEditing !== isEditing) {
      if (isEditing) {
        refs.nameView.classList.add('hidden');
        refs.remarkEditor.classList.remove('hidden');
        refs.remarkInput.value = state.editingDraft;
        refs.remarkInput.focus();
        const len = refs.remarkInput.value.length;
        refs.remarkInput.setSelectionRange(len, len);
      } else {
        refs.remarkEditor.classList.add('hidden');
        refs.nameView.classList.remove('hidden');
      }
      prev.isEditing = isEditing;
    }

    const displayName = d.display_name || d.mac;
    setText(refs.title, displayName);

    let pillCls = 'pill pill-muted';
    let pillText = '未申请';
    if (d.is_whitelist) {
      pillCls = 'pill pill-indigo';
      pillText = '白名单';
    } else if (d.status === 'approved') {
      pillCls = 'pill pill-success';
      pillText = '已联网';
    } else if (d.status === 'pending') {
      pillCls = 'pill pill-amber';
      pillText = '待审批';
    } else if (d.status === 'paused') {
      pillCls = 'pill pill-rose';
      pillText = '已断网';
    }
    if (prev.pillCls !== pillCls || prev.pillText !== pillText) {
      refs.statusPill.className = pillCls;
      setText(refs.statusPill, pillText);
      prev.pillCls = pillCls;
      prev.pillText = pillText;
    }

    const origins = [];
    if (d.requested_name && d.requested_name !== displayName) origins.push(`申请:${d.requested_name}`);
    if (d.hostname) origins.push(d.hostname);
    setText(refs.originText, origins.join(' · '));

    const ct = formatConnectTime(d);
    const ctText = d.online ? ct.label : '当前离线';
    setText(refs.connectTime, ctText);
    if (ct.full && refs.connectTime.title !== ct.full) {
      refs.connectTime.title = `精确时间：${ct.full}`;
    }

    if (d.online && (d.status === 'approved' || d.is_whitelist)) {
      refs.durationChip.classList.remove('hidden');
      const liveSec = getLiveOnlineSeconds(d);
      setText(refs.durationChip, `⏱ ${formatDurationByUnit(liveSec, state.durationUnit)} ↻`);
    } else {
      refs.durationChip.classList.add('hidden');
    }

    setText(refs.ip, d.ip || '未分配 IP');
    setText(refs.macEl, d.mac);

    setText(refs.rateDown, `↓ ${formatRate(d.rx_rate_bps)}`);
    setText(refs.rateUp, `↑ ${formatRate(d.tx_rate_bps)}`);
    setText(refs.metricsSub, `连接 ${d.active_conns || 0} · 累计 ↓${formatBytes(d.total_rx_bytes)}`);

    const remPause = getLivePauseRemainingSec(d);
    if (d.status === 'paused' && remPause > 0) {
      refs.countdownText.classList.remove('hidden');
      const untilClock = d.pause_until ? formatClock(d.pause_until).slice(0, 5) : '';
      setText(refs.countdownText, `⏳ 剩余 ${formatCountdown(remPause)} 自动恢复${untilClock ? ' (' + untilClock + ')' : ''}`);
    } else {
      refs.countdownText.classList.add('hidden');
    }

    if (d.auto_resume_error) {
      refs.errorInline.classList.remove('hidden');
      setText(refs.errorInline, d.auto_resume_error);
    } else {
      refs.errorInline.classList.add('hidden');
    }

    const actionSig = `${d.status}|${d.is_whitelist}|${remPause > 0}`;
    if (prev.actionSig !== actionSig) {
      prev.actionSig = actionSig;
      let html = '';
      if (!d.is_whitelist) {
        if (d.status === 'pending' || d.status === 'unregistered') {
          html += `<button type="button" class="btn btn-success btn-xs" data-action="approve" data-mac="${escapeHTML(d.mac)}">批准连网</button>`;
        } else if (d.status === 'approved') {
          html += `<button type="button" class="btn btn-danger btn-xs" data-action="pause-now" data-mac="${escapeHTML(d.mac)}">断网</button>`;
          html += `<button type="button" class="btn btn-danger-ghost btn-xs" data-action="open-timed-pause" data-mac="${escapeHTML(d.mac)}">定时 ▾</button>`;
        } else if (d.status === 'paused') {
          html += `<button type="button" class="btn btn-success btn-xs" data-action="resume" data-mac="${escapeHTML(d.mac)}">恢复联网</button>`;
          html += `<button type="button" class="btn btn-ghost btn-xs" data-action="open-timed-pause" data-mac="${escapeHTML(d.mac)}">定时</button>`;
        }
      }
      html += `<button type="button" class="btn btn-ghost btn-xs" data-action="toggle-whitelist" data-mac="${escapeHTML(d.mac)}" data-next="${!d.is_whitelist}">${d.is_whitelist ? '移出白名单' : '白名单'}</button>`;
      if (!d.is_whitelist) {
        html += `<button type="button" class="btn btn-danger-ghost btn-xs" data-action="delete" data-mac="${escapeHTML(d.mac)}">删除</button>`;
      }
      refs.actions.innerHTML = html;
    }
  }

  function reconcileDeviceList(snap) {
    const list = computeSortedFilteredDevices(snap);

    const existingEmpty = els.devicesList.querySelector('.empty-placeholder');
    if (list.length === 0) {
      Array.from(els.devicesList.children).forEach((child) => {
        if (!child.classList.contains('empty-placeholder')) child.remove();
      });
      if (!existingEmpty) {
        const empty = document.createElement('div');
        empty.className = 'muted-hint empty-placeholder';
        empty.style.padding = '24px';
        empty.style.textAlign = 'center';
        empty.textContent = '当前筛选条件下暂无设备';
        els.devicesList.appendChild(empty);
      }
      return;
    }
    if (existingEmpty) existingEmpty.remove();

    const activeMacs = new Set(list.map((d) => d.mac));
    Array.from(els.devicesList.children).forEach((child) => {
      if (!activeMacs.has(child.dataset.mac)) child.remove();
    });
    const allKnownMacs = new Set((snap.devices || []).map((d) => d.mac));
    for (const cachedMac of state.rowCache.keys()) {
      if (!allKnownMacs.has(cachedMac)) {
        state.rowCache.delete(cachedMac);
      }
    }

    list.forEach((d, idx) => {
      let entry = state.rowCache.get(d.mac);
      if (!entry) {
        entry = createDeviceRow(d.mac);
        state.rowCache.set(d.mac, entry);
      }
      updateDeviceRow(entry, d);
      const currentAtIdx = els.devicesList.children[idx];
      if (currentAtIdx !== entry.el) {
        els.devicesList.insertBefore(entry.el, currentAtIdx || null);
      }
    });
  }

  // 每秒精确更新全部在线时长与定时断网剩余倒计时
  setInterval(() => {
    if (!state.authenticated || !state.snapshot) return;
    for (const d of state.snapshot.devices || []) {
      const entry = state.rowCache.get(d.mac);
      if (!entry || !entry.el.isConnected) continue;
      if (d.online && (d.status === 'approved' || d.is_whitelist)) {
        const sec = getLiveOnlineSeconds(d);
        setText(entry.refs.durationChip, `⏱ ${formatDurationByUnit(sec, state.durationUnit)} ↻`);
      }
      if (d.status === 'paused' && d.pause_until) {
        const rem = getLivePauseRemainingSec(d);
        if (rem > 0) {
          const untilClock = formatClock(d.pause_until).slice(0, 5);
          setText(entry.refs.countdownText, `⏳ 剩余 ${formatCountdown(rem)} 自动恢复 (${untilClock})`);
        } else {
          setText(entry.refs.countdownText, '⏳ 正在自动恢复...');
        }
      }
    }
  }, 1000);

  function findLocalDevice(mac) {
    return (state.snapshot?.devices || []).find((d) => d.mac === mac);
  }

  function cloneSnapshot() {
    return JSON.parse(JSON.stringify(state.snapshot));
  }

  async function toggleMasterSwitch() {
    if (!state.snapshot?.settings) return;
    const curr = state.snapshot.settings.gatekeeper_enabled !== false;
    const next = !curr;
    const backup = cloneSnapshot();
    state.snapshot.settings.gatekeeper_enabled = next;
    renderAllFromSnapshot();

    try {
      const { ok, data } = await apiFetch('/api/settings', {
        method: 'PUT',
        body: JSON.stringify({ gatekeeper_enabled: next }),
      });
      if (!ok) {
        state.snapshot = backup;
        renderAllFromSnapshot();
        showToast(data?.error || '切换总开关失败', 'error');
        return;
      }
      showToast(next ? '准入认证总开关已开启，已恢复拦截管控' : '总开关已关闭，已切换为自由直通模式', 'success');
    } catch (err) {
      state.snapshot = backup;
      renderAllFromSnapshot();
      showToast(err.message || '切换失败', 'error');
    }
  }

  async function approveOrResumeDevice(mac, mode = 'approve', options = {}) {
    const dev = findLocalDevice(mac);
    let backup = null;
    if (dev && !options.replace_oldest && !options.evict_mac) {
      const snap = state.snapshot;
      const maxConc = snap.settings?.max_concurrent_devices || 2;
      const currentAuth = (snap.devices || []).filter((x) => x.status === 'approved' && !x.is_whitelist && x.mac !== mac).length;
      if (dev.is_whitelist || currentAuth < maxConc) {
        backup = cloneSnapshot();
        dev.status = 'approved';
        dev.approved_at = new Date(alignedNowMs()).toISOString();
        dev.pause_until = null;
        dev.pause_remaining_sec = 0;
        dev.auto_resume_error = '';
        renderAllFromSnapshot();
        flashRow(mac, 'success');
      }
    }

    const endpoint = mode === 'resume' ? `/api/devices/${encodeURIComponent(mac)}/resume` : `/api/devices/${encodeURIComponent(mac)}/approve`;
    try {
      const { status, ok, data } = await apiFetch(endpoint, { method: 'POST', body: JSON.stringify(options) });
      if (status === 409 && data && data.code === 'CONCURRENCY_LIMIT_REACHED') {
        if (backup) { state.snapshot = backup; renderAllFromSnapshot(); }
        openConflictModal(mac, mode, data);
        return;
      }
      if (!ok) {
        if (backup) { state.snapshot = backup; renderAllFromSnapshot(); }
        showToast(data?.error || '操作失败', 'error');
        return;
      }
      closeConflictModal();
      flashRow(mac, 'success');
      showToast(data?.evicted ? `已顶替「${data.evicted.display_name}」并放行` : '已放行联网', 'success');
    } catch (err) {
      if (backup) { state.snapshot = backup; renderAllFromSnapshot(); }
      showToast(err.message || '请求失败', 'error');
    }
  }

  async function executePause(mac, durationMinutes) {
    closeTimedPausePopover();
    const dev = findLocalDevice(mac);
    const backup = dev ? cloneSnapshot() : null;
    if (dev) {
      dev.status = 'paused';
      dev.rx_rate_bps = 0;
      dev.tx_rate_bps = 0;
      dev.active_conns = 0;
      dev.auto_resume_error = '';
      if (durationMinutes > 0) {
        dev.pause_until = new Date(alignedNowMs() + durationMinutes * 60000).toISOString();
        dev.pause_remaining_sec = Math.round(durationMinutes * 60);
      } else {
        dev.pause_until = null;
        dev.pause_remaining_sec = 0;
      }
      renderAllFromSnapshot();
      flashRow(mac, 'danger');
    }

    try {
      const { ok, data } = await apiFetch(`/api/devices/${encodeURIComponent(mac)}/pause`, {
        method: 'POST',
        body: JSON.stringify(durationMinutes > 0 ? { duration_minutes: durationMinutes } : {}),
      });
      if (!ok) {
        if (backup) { state.snapshot = backup; renderAllFromSnapshot(); }
        showToast(data?.error || '断网失败', 'error');
        return;
      }
      showToast(durationMinutes > 0 ? `已定时断网 ${durationMinutes >= 60 && durationMinutes % 60 === 0 ? (durationMinutes / 60) + ' 小时' : durationMinutes + ' 分钟'}` : '已切断设备网络', 'success');
    } catch (err) {
      if (backup) { state.snapshot = backup; renderAllFromSnapshot(); }
      showToast(err.message || '请求失败', 'error');
    }
  }

  function openTimedPausePopover(mac, anchorBtn) {
    state.popoverMac = mac;
    const pop = els.timedPausePopover;
    pop.classList.remove('hidden');
    const rect = anchorBtn.getBoundingClientRect();
    const pw = 268;
    const ph = 185;
    let left = rect.right - pw;
    if (left < 10) left = 10;
    if (left + pw > window.innerWidth - 10) left = window.innerWidth - pw - 10;
    let top = rect.bottom + 6;
    if (top + ph > window.innerHeight - 10) top = Math.max(10, rect.top - ph - 6);
    pop.style.left = `${left}px`;
    pop.style.top = `${top}px`;
  }

  function closeTimedPausePopover() {
    state.popoverMac = null;
    els.timedPausePopover.classList.add('hidden');
  }

  function openConflictModal(targetMac, mode, conflict) {
    els.conflictMessage.textContent = conflict.message || `当前已达上限（${conflict.current}/${conflict.max}）`;
    const oldest = conflict.oldest_device;
    if (oldest) {
      els.btnEvictOldest.classList.remove('hidden');
      els.btnEvictOldest.textContent = `一键顶替最早设备：${oldest.display_name} (${oldest.ip || oldest.mac})`;
      els.btnEvictOldest.onclick = () => approveOrResumeDevice(targetMac, mode, { replace_oldest: true });
    } else {
      els.btnEvictOldest.classList.add('hidden');
    }
    els.conflictActiveList.innerHTML = (conflict.active_devices || []).map((d) => `
      <button type="button" class="conflict-device-btn" data-evict-mac="${escapeHTML(d.mac)}">
        <div>
          <strong>${escapeHTML(d.display_name)}</strong>
          <div class="muted-hint">${escapeHTML(d.ip || '-')} · ${escapeHTML(d.mac)}</div>
        </div>
        <span class="pill pill-rose">顶替下线</span>
      </button>
    `).join('');
    els.conflictActiveList.querySelectorAll('[data-evict-mac]').forEach((btn) => {
      btn.addEventListener('click', () => {
        approveOrResumeDevice(targetMac, mode, { evict_mac: btn.getAttribute('data-evict-mac') });
      });
    });
    els.conflictModal.classList.remove('hidden');
  }

  function closeConflictModal() {
    els.conflictModal.classList.add('hidden');
  }

  function renderAuditLogs(snap) {
    const logs = snap.audit_logs || [];
    els.auditPane.innerHTML = logs.length === 0
      ? '<div class="muted-hint">暂无审计记录</div>'
      : logs.map((ev) => `
          <div class="audit-item">
            <div class="audit-top">
              <span class="audit-action">${escapeHTML(ev.action)}</span>
              <span class="audit-time">${formatClock(ev.timestamp)}</span>
            </div>
            <div class="audit-detail">${escapeHTML(ev.detail)}</div>
          </div>
        `).join('');
  }

  function syncActiveFilterTab() {
    els.filterTabs.querySelectorAll('.tab-btn').forEach((b) => {
      b.classList.toggle('active', b.getAttribute('data-filter') === state.filter);
    });
  }

  function updateSortDirBtn() {
    setText(els.btnSortDir, state.sortDir === 'asc' ? '↑ 升序' : '↓ 降序');
  }

  // 事件绑定
  els.loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    els.loginError.classList.add('hidden');
    try {
      const resp = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: els.loginPassword.value }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        els.loginError.textContent = data.error || '密码错误';
        els.loginError.classList.remove('hidden');
        return;
      }
      state.authenticated = true;
      els.loginPassword.value = '';
      showDashboardView();
      await fetchInitialState();
      connectWebSocket();
    } catch (_) {
      els.loginError.textContent = '请求登录失败';
      els.loginError.classList.remove('hidden');
    }
  });

  els.btnLogout.addEventListener('click', async () => {
    await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
    state.authenticated = false;
    closeWebSocket();
    showLoginView();
  });

  els.btnMasterSwitch.addEventListener('click', toggleMasterSwitch);

  els.btnToggleTunnel.addEventListener('click', () => {
    state.tunnelOpen = !state.tunnelOpen;
    els.tunnelDrawer.classList.toggle('hidden', !state.tunnelOpen);
  });

  els.btnOpenGuide.addEventListener('click', () => els.guideModal.classList.remove('hidden'));
  els.btnGuideClose.addEventListener('click', () => els.guideModal.classList.add('hidden'));

  els.btnOpenAudit.addEventListener('click', async () => {
    els.auditModal.classList.remove('hidden');
    if (state.snapshot) renderAuditLogs(state.snapshot);
    els.auditPane.classList.remove('hidden');
    els.scriptPane.classList.add('hidden');
    els.btnSwitchAudit.className = 'btn btn-primary btn-xs';
    els.btnSwitchScript.className = 'btn btn-ghost btn-xs';
  });
  els.btnAuditClose.addEventListener('click', () => els.auditModal.classList.add('hidden'));
  els.btnSwitchAudit.addEventListener('click', () => {
    els.auditPane.classList.remove('hidden');
    els.scriptPane.classList.add('hidden');
    els.btnSwitchAudit.className = 'btn btn-primary btn-xs';
    els.btnSwitchScript.className = 'btn btn-ghost btn-xs';
  });
  els.btnSwitchScript.addEventListener('click', async () => {
    els.auditPane.classList.add('hidden');
    els.scriptPane.classList.remove('hidden');
    els.btnSwitchAudit.className = 'btn btn-ghost btn-xs';
    els.btnSwitchScript.className = 'btn btn-primary btn-xs';
    const { ok, data } = await apiFetch('/api/firewall/script');
    if (ok) {
      setText(els.scriptRuleCount, String(data.rules_count || 0));
      els.scriptContent.textContent = data.script || '';
    }
  });
  els.btnCopyScript.addEventListener('click', async () => {
    if (navigator.clipboard) {
      await navigator.clipboard.writeText(els.scriptContent.textContent);
      showToast('已复制 nftables 规则', 'success');
    }
  });

  els.btnSoundToggle.addEventListener('click', async () => {
    const curr = Boolean(state.snapshot?.settings?.sound_enabled);
    if (state.snapshot?.settings) {
      state.snapshot.settings.sound_enabled = !curr;
      renderTopbar(state.snapshot);
    }
    const { ok } = await apiFetch('/api/settings', { method: 'PUT', body: JSON.stringify({ sound_enabled: !curr }) });
    if (ok && !curr) { playAlertChime(); showToast('已开启提示音'); }
  });

  async function updateMaxDevices(delta) {
    const curr = state.snapshot?.settings?.max_concurrent_devices || 2;
    const next = curr + delta;
    if (next < 1 || next > 256) return;
    state.snapshot.settings.max_concurrent_devices = next;
    renderKPIs(state.snapshot);
    await apiFetch('/api/settings', { method: 'PUT', body: JSON.stringify({ max_concurrent_devices: next }) });
    showToast(`最大同时在线上限已调为 ${next} 台`);
  }
  els.btnMaxDec.addEventListener('click', () => updateMaxDevices(-1));
  els.btnMaxInc.addEventListener('click', () => updateMaxDevices(1));

  els.btnProtectViewer.addEventListener('click', async () => {
    const { ok, data } = await apiFetch('/api/whitelist/current', { method: 'POST' });
    if (ok) showToast('当前控制主机已加入白名单保护', 'success');
    else showToast(data?.error || '保护失败', 'error');
  });

  els.btnTunnelInstall.addEventListener('click', async () => {
    els.btnTunnelInstall.disabled = true;
    setText(els.btnTunnelInstall, '正在下载安装...');
    try {
      const { ok, data } = await apiFetch('/api/tunnel/install', { method: 'POST' });
      if (!ok) {
        showToast(data?.error || '自动安装失败', 'error');
      } else {
        showToast(data?.message || 'cloudflared 安装完成', 'success');
        await fetchInitialState();
      }
    } finally {
      els.btnTunnelInstall.disabled = false;
      setText(els.btnTunnelInstall, '一键安装 cloudflared');
    }
  });

  els.btnTunnelStart.addEventListener('click', async () => {
    els.btnTunnelStart.disabled = true;
    try {
      const { ok, data } = await apiFetch('/api/tunnel/start', {
        method: 'POST',
        body: JSON.stringify({ mode: els.tunnelModeSelect.value }),
      });
      if (!ok) showToast(data?.error || '启动隧道失败', 'error');
      else showToast('正在通过 HTTP/2 建立 Cloudflare 远程隧道...', 'success');
    } finally {
      els.btnTunnelStart.disabled = false;
    }
  });
  els.btnTunnelStop.addEventListener('click', async () => {
    await apiFetch('/api/tunnel/stop', { method: 'POST' });
    showToast('已关闭远程隧道');
  });
  els.btnCopyTunnel.addEventListener('click', async () => {
    const u = els.tunnelPublicUrl.textContent;
    if (u && navigator.clipboard) {
      await navigator.clipboard.writeText(u);
      showToast('已复制公网访问网址', 'success');
    }
  });

  els.btnMockSim.addEventListener('click', async () => {
    const { ok, data } = await apiFetch('/api/mock/simulate-device', { method: 'POST', body: JSON.stringify({}) });
    if (ok) showToast(`模拟新手机「${data.device?.requested_name}」发起申请`);
  });
  els.btnMockReset.addEventListener('click', async () => {
    const { ok } = await apiFetch('/api/mock/reset', { method: 'POST' });
    if (ok) showToast('已重置为 5 台演示设备', 'success');
  });

  els.filterTabs.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-filter]');
    if (!btn) return;
    state.filter = btn.getAttribute('data-filter');
    localStorage.setItem('gk_filter', state.filter);
    syncActiveFilterTab();
    if (state.snapshot) reconcileDeviceList(state.snapshot);
  });

  els.sortBy.addEventListener('change', () => {
    state.sortBy = els.sortBy.value;
    localStorage.setItem('gk_sort_by', state.sortBy);
    if (state.snapshot) reconcileDeviceList(state.snapshot);
  });

  els.btnSortDir.addEventListener('click', () => {
    state.sortDir = state.sortDir === 'desc' ? 'asc' : 'desc';
    localStorage.setItem('gk_sort_dir', state.sortDir);
    updateSortDirBtn();
    if (state.snapshot) reconcileDeviceList(state.snapshot);
  });

  els.deviceSearch.addEventListener('input', () => {
    state.search = els.deviceSearch.value.trim();
    if (state.snapshot) reconcileDeviceList(state.snapshot);
  });

  els.timedPausePopover.addEventListener('click', (e) => {
    const qBtn = e.target.closest('[data-mins]');
    if (qBtn && state.popoverMac) {
      executePause(state.popoverMac, Number(qBtn.getAttribute('data-mins')));
    }
  });
  els.btnCustomPauseGo.addEventListener('click', () => {
    if (!state.popoverMac) return;
    const val = Number(els.customPauseVal.value);
    if (!val || val <= 0) {
      showToast('请输入大于 0 的时长', 'error');
      return;
    }
    const mins = els.customPauseUnit.value === 'h' ? val * 60 : val;
    executePause(state.popoverMac, mins);
  });
  els.btnPermPauseGo.addEventListener('click', () => {
    if (state.popoverMac) executePause(state.popoverMac, 0);
  });

  document.addEventListener('click', (e) => {
    if (!els.timedPausePopover.classList.contains('hidden')) {
      if (!els.timedPausePopover.contains(e.target) && !e.target.closest('[data-action="open-timed-pause"]')) {
        closeTimedPausePopover();
      }
    }
  });

  async function saveRemark(mac, newRemark) {
    const dev = findLocalDevice(mac);
    const backup = dev ? cloneSnapshot() : null;
    if (dev) {
      dev.admin_remark = newRemark;
      dev.display_name = newRemark || dev.requested_name || dev.hostname || dev.mac;
    }
    state.editingMac = null;
    state.editingDraft = '';
    if (state.snapshot) renderAllFromSnapshot();
    flashRow(mac, 'info');

    try {
      const { ok, data } = await apiFetch(`/api/devices/${encodeURIComponent(mac)}/remark`, {
        method: 'PUT',
        body: JSON.stringify({ remark: newRemark }),
      });
      if (!ok) {
        if (backup) { state.snapshot = backup; renderAllFromSnapshot(); }
        showToast(data?.error || '保存备注失败', 'error');
        return;
      }
      showToast('备注已保存', 'success');
    } catch (err) {
      if (backup) { state.snapshot = backup; renderAllFromSnapshot(); }
      showToast(err.message || '保存备注失败', 'error');
    }
  }

  async function handleActionClick(e) {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const action = btn.getAttribute('data-action');
    const mac = btn.getAttribute('data-mac');

    if (action === 'approve' || action === 'resume') {
      await approveOrResumeDevice(mac, action);
    } else if (action === 'pause-now') {
      await executePause(mac, 0);
    } else if (action === 'open-timed-pause') {
      e.stopPropagation();
      if (state.popoverMac === mac && !els.timedPausePopover.classList.contains('hidden')) {
        closeTimedPausePopover();
      } else {
        openTimedPausePopover(mac, btn);
      }
    } else if (action === 'cycle-duration') {
      const idx = DURATION_UNITS.indexOf(state.durationUnit);
      state.durationUnit = DURATION_UNITS[(idx + 1) % DURATION_UNITS.length];
      localStorage.setItem('gk_duration_unit', state.durationUnit);
      if (state.snapshot) reconcileDeviceList(state.snapshot);
      const entry = state.rowCache.get(mac);
      if (entry) {
        entry.refs.durationChip.classList.remove('chip-bounce');
        void entry.refs.durationChip.offsetWidth;
        entry.refs.durationChip.classList.add('chip-bounce');
      }
    } else if (action === 'toggle-whitelist') {
      const next = btn.getAttribute('data-next') === 'true';
      const dev = findLocalDevice(mac);
      const backup = dev ? cloneSnapshot() : null;
      if (dev) {
        dev.is_whitelist = next;
        if (next) { dev.status = 'approved'; dev.pause_until = null; dev.pause_remaining_sec = 0; }
        renderAllFromSnapshot();
        flashRow(mac, 'info');
      }
      const { ok, data } = await apiFetch(`/api/devices/${encodeURIComponent(mac)}/whitelist`, {
        method: 'PUT',
        body: JSON.stringify({ is_whitelist: next }),
      });
      if (!ok) {
        if (backup) { state.snapshot = backup; renderAllFromSnapshot(); }
        showToast(data?.error || '操作失败', 'error');
      } else {
        showToast(next ? '已设为永久白名单' : '已移出白名单', 'success');
      }
    } else if (action === 'delete') {
      const backup = cloneSnapshot();
      state.snapshot.devices = (state.snapshot.devices || []).filter((d) => d.mac !== mac);
      state.rowCache.delete(mac);
      renderAllFromSnapshot();
      const { ok, data } = await apiFetch(`/api/devices/${encodeURIComponent(mac)}`, { method: 'DELETE' });
      if (!ok) {
        state.snapshot = backup;
        renderAllFromSnapshot();
        showToast(data?.error || '删除失败', 'error');
      } else {
        showToast('已删除设备记录');
      }
    } else if (action === 'edit-remark') {
      const dev = findLocalDevice(mac);
      state.editingMac = mac;
      state.editingDraft = dev ? (dev.admin_remark || dev.display_name || '') : '';
      if (state.snapshot) reconcileDeviceList(state.snapshot);
    } else if (action === 'cancel-remark') {
      state.editingMac = null;
      state.editingDraft = '';
      if (state.snapshot) reconcileDeviceList(state.snapshot);
    } else if (action === 'quick-tag') {
      const tag = btn.getAttribute('data-tag') || '';
      const entry = state.rowCache.get(mac);
      if (entry) {
        entry.refs.remarkInput.value = tag;
        state.editingDraft = tag;
        await saveRemark(mac, tag);
      }
    } else if (action === 'save-remark') {
      const entry = state.rowCache.get(mac);
      const val = entry ? entry.refs.remarkInput.value.trim() : state.editingDraft.trim();
      await saveRemark(mac, val);
    }
  }

  els.devicesList.addEventListener('click', handleActionClick);
  els.pendingCards.addEventListener('click', handleActionClick);
  els.devicesList.addEventListener('input', (e) => {
    if (e.target.matches('[data-remark-input]')) {
      state.editingDraft = e.target.value;
    }
  });
  els.devicesList.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.target.matches('[data-remark-input]')) {
      e.preventDefault();
      saveRemark(e.target.dataset.mac, e.target.value.trim());
    } else if (e.key === 'Escape' && e.target.matches('[data-remark-input]')) {
      state.editingMac = null;
      if (state.snapshot) reconcileDeviceList(state.snapshot);
    }
  });

  els.btnConflictCancel.addEventListener('click', closeConflictModal);

  els.btnSettings.addEventListener('click', () => {
    const s = state.snapshot?.settings || {};
    els.setMaxDevices.value = s.max_concurrent_devices || 2;
    els.setPortalTitle.value = s.portal_title || '智慧网络准入认证';
    els.setTunnelToken.value = '';
    els.setNewPassword.value = '';
    els.setAllowPorts.checked = Boolean(s.allow_admin_ports);
    setText(els.setTokenStatus, s.has_tunnel_token ? `已配置 Token (${s.tunnel_token_masked})` : '未配置固定域名 Token');
    els.settingsModal.classList.remove('hidden');
  });
  const closeSettings = () => els.settingsModal.classList.add('hidden');
  els.btnSettingsClose.addEventListener('click', closeSettings);
  els.btnSettingsCancel.addEventListener('click', closeSettings);
  els.settingsForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      max_concurrent_devices: Number(els.setMaxDevices.value),
      portal_title: els.setPortalTitle.value.trim(),
      allow_admin_ports: els.setAllowPorts.checked,
    };
    if (els.setTunnelToken.value.trim()) payload.tunnel_token = els.setTunnelToken.value.trim();
    if (els.setNewPassword.value.trim()) payload.new_password = els.setNewPassword.value.trim();
    const { ok, data } = await apiFetch('/api/settings', { method: 'PUT', body: JSON.stringify(payload) });
    if (!ok) {
      showToast(data?.error || '保存失败', 'error');
      return;
    }
    closeSettings();
    showToast('设置已保存并生效', 'success');
  });

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    closeTimedPausePopover();
    closeConflictModal();
    els.guideModal.classList.add('hidden');
    els.auditModal.classList.add('hidden');
    closeSettings();
  });

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && state.authenticated) {
      fetchInitialState().catch(() => {});
      if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
        connectWebSocket();
      }
    }
  });

  bootstrap();
})();
