(() => {
  'use strict';

  const urlParams = new URLSearchParams(window.location.search);
  let activeMockMac = urlParams.get('mac') || '';
  let currentStatus = null;
  let prevStateKey = '';
  let ws = null;
  let pollTimer = null;
  let tickTimer = null;

  const els = {
    portalCard: document.getElementById('portal-card'),
    mockSwitcher: document.getElementById('mock-switcher'),
    mockPills: document.getElementById('mock-pills'),
    btnNewPhone: document.getElementById('btn-new-phone'),
    statusOrb: document.getElementById('status-orb'),
    portalTitle: document.getElementById('portal-title'),
    portalSubtitle: document.getElementById('portal-subtitle'),
    devMac: document.getElementById('dev-mac'),
    devIp: document.getElementById('dev-ip'),
    rowName: document.getElementById('row-name'),
    devName: document.getElementById('dev-name'),
    applyForm: document.getElementById('apply-form'),
    inputName: document.getElementById('input-name'),
    applyError: document.getElementById('apply-error'),
    btnApply: document.getElementById('btn-apply'),
    pendingPanel: document.getElementById('pending-panel'),
    pendingDetail: document.getElementById('pending-detail'),
    approvedPanel: document.getElementById('approved-panel'),
    approvedHeadline: document.getElementById('approved-headline'),
    approvedDetail: document.getElementById('approved-detail'),
    pausedPanel: document.getElementById('paused-panel'),
    pausedDetail: document.getElementById('paused-detail'),
    pausedCountdownBadge: document.getElementById('paused-countdown-badge'),
    btnRecheck: document.getElementById('btn-recheck'),
    recheckIcon: document.getElementById('recheck-icon'),
    recheckText: document.getElementById('recheck-text'),
    liveTip: document.getElementById('live-tip'),
  };

  // 全页面按钮点击水波纹动效
  document.addEventListener('pointerdown', (e) => {
    const target = e.target.closest('.btn-submit, .btn-recheck, .mock-pill');
    if (!target || target.disabled) return;
    const rect = target.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    const span = document.createElement('span');
    span.className = 'ripple';
    span.style.width = `${size}px`;
    span.style.height = `${size}px`;
    span.style.left = `${e.clientX - rect.left - size / 2}px`;
    span.style.top = `${e.clientY - rect.top - size / 2}px`;
    target.appendChild(span);
    setTimeout(() => span.remove(), 420);
  });

  function statusQuery() {
    return activeMockMac ? `?mac=${encodeURIComponent(activeMockMac)}` : '';
  }

  function formatSecZh(sec) {
    if (sec <= 0) return '即将恢复';
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    if (h > 0) return `${h}时${String(m).padStart(2, '0')}分${String(s).padStart(2, '0')}秒`;
    if (m > 0) return `${m}分${String(s).padStart(2, '0')}秒`;
    return `${s}秒`;
  }

  function updatePausedCountdown(s) {
    if (!s || s.status !== 'paused') return;
    if (s.pause_until) {
      const rem = Math.max(0, Math.ceil((new Date(s.pause_until).getTime() - Date.now()) / 1000));
      if (rem > 0) {
        els.pausedDetail.textContent = '当前设备的网络已被软路由管理员暂停，倒计时结束后将自动恢复联网。';
        els.pausedCountdownBadge.classList.remove('hidden');
        els.pausedCountdownBadge.textContent = `⏳ 预计 ${formatSecZh(rem)} 后自动恢复`;
        return;
      }
    }
    els.pausedCountdownBadge.classList.add('hidden');
    els.pausedDetail.textContent = '当前设备的网络已被软路由管理员暂停，无法访问互联网，请联系管理员恢复联网。';
  }

  function triggerOrbPop() {
    els.statusOrb.classList.remove('pop');
    void els.statusOrb.offsetWidth;
    els.statusOrb.classList.add('pop');
  }

  function renderStatus(s) {
    if (!s) return;
    currentStatus = s;
    if (s.portal_title) els.portalTitle.textContent = s.portal_title;
    els.devMac.textContent = s.mac || '未识别';
    els.devIp.textContent = s.ip || '-';

    if (s.requested_name || s.admin_remark) {
      els.rowName.classList.remove('hidden');
      els.devName.textContent = s.display_name || s.requested_name;
    } else {
      els.rowName.classList.add('hidden');
    }

    els.applyForm.classList.add('hidden');
    els.pendingPanel.classList.add('hidden');
    els.approvedPanel.classList.add('hidden');
    els.pausedPanel.classList.add('hidden');

    const gkEnabled = s.gatekeeper_enabled !== false;
    const nextKey = gkEnabled ? s.status : 'bypass';
    const stateChanged = prevStateKey !== '' && prevStateKey !== nextKey;

    els.portalCard.classList.remove('is-paused', 'is-approved');

    if (!gkEnabled) {
      els.portalCard.classList.add('is-approved');
      els.statusOrb.className = 'status-orb orb-green';
      els.statusOrb.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>';
      els.portalSubtitle.textContent = '准入开关已关闭 · 全网自由直通';
      els.approvedHeadline.textContent = '软路由已开放自由直通';
      els.approvedDetail.textContent = '管理员已关闭准入认证限制，您无需填写昵称即可直接畅通上网。';
      els.approvedPanel.classList.remove('hidden');
    } else if (s.is_whitelist || s.status === 'approved') {
      els.portalCard.classList.add('is-approved');
      els.statusOrb.className = 'status-orb orb-green';
      els.statusOrb.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>';
      els.portalSubtitle.textContent = '网络已放行 · 畅享高速访问';
      els.approvedHeadline.textContent = '已授权联网';
      const sec = s.online_duration_sec || 0;
      const mins = Math.floor(sec / 60);
      const remS = sec % 60;
      els.approvedDetail.textContent = `设备「${s.display_name || s.mac}」已获准接入互联网（本次已连 ${mins} 分 ${String(remS).padStart(2, '0')} 秒）。`;
      els.approvedPanel.classList.remove('hidden');
    } else if (s.status === 'pending') {
      els.statusOrb.className = 'status-orb orb-amber';
      els.statusOrb.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>';
      els.portalSubtitle.textContent = '申请已提交 · 正在实时等待审批';
      els.pendingDetail.textContent = `提交代号「${s.requested_name || s.display_name}」(${s.mac})，等待管理员点击通过...`;
      els.pendingPanel.classList.remove('hidden');
    } else if (s.status === 'paused') {
      els.portalCard.classList.add('is-paused');
      els.statusOrb.className = 'status-orb orb-rose';
      els.statusOrb.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>';
      els.portalSubtitle.textContent = '当前设备网络已被暂停';
      updatePausedCountdown(s);
      els.pausedPanel.classList.remove('hidden');
      if (stateChanged) {
        els.portalCard.classList.remove('alert-shake');
        void els.portalCard.offsetWidth;
        els.portalCard.classList.add('alert-shake');
        if (navigator.vibrate) {
          try { navigator.vibrate([120, 60, 120]); } catch (_) {}
        }
      }
    } else {
      els.statusOrb.className = 'status-orb orb-cyan';
      els.statusOrb.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>';
      els.portalSubtitle.textContent = '请填写设备代号申请 Wi-Fi 上网权限';
      els.applyForm.classList.remove('hidden');
    }

    if (stateChanged || prevStateKey === '') {
      triggerOrbPop();
    }
    prevStateKey = nextKey;

    if (s.mock_mode) {
      loadMockSwitcher(s.mac);
    }
  }

  async function loadMockSwitcher(currentMac) {
    try {
      const resp = await fetch('/api/portal/mock-devices', { credentials: 'same-origin' });
      const data = await resp.json();
      if (!data.mock_mode) return;
      els.mockSwitcher.classList.remove('hidden');

      const devices = data.devices || [];
      els.mockPills.innerHTML = '';
      devices.forEach((d) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = `mock-pill ${d.mac === currentMac ? 'active' : ''}`;
        btn.textContent = `${d.display_name} (${d.status === 'approved' ? '已联网' : d.status === 'pending' ? '待审' : d.status === 'paused' ? '已断网' : '未审'})`;
        btn.addEventListener('click', () => switchMockDevice(d.mac));
        els.mockPills.appendChild(btn);
      });
    } catch (_) {}
  }

  function switchMockDevice(mac) {
    activeMockMac = mac;
    prevStateKey = '';
    els.inputName.value = '';
    els.applyError.classList.add('hidden');
    fetchStatus();
    connectWS();
  }

  async function fetchStatus() {
    try {
      const resp = await fetch(`/api/portal/status${statusQuery()}`, { credentials: 'same-origin' });
      const data = await resp.json();
      if (!activeMockMac && data.mock_mode && data.mac) activeMockMac = data.mac;
      renderStatus(data);
      return data;
    } catch (_) {
      return null;
    }
  }

  function connectWS() {
    if (ws) {
      try { ws.close(); } catch (_) {}
      ws = null;
    }
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${window.location.host}/api/portal/ws${statusQuery()}`);
    ws.onopen = () => {
      els.liveTip.textContent = '实时状态监听中 · 放行/断网状态秒级同步';
    };
    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if (msg.type === 'portal_status' && msg.data) renderStatus(msg.data);
      } catch (_) {}
    };
    ws.onclose = () => {
      els.liveTip.textContent = '实时同步中（自动轮询保底）';
    };
  }

  els.applyForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    els.applyError.classList.add('hidden');
    const name = els.inputName.value.trim();
    if (!name) {
      els.applyError.textContent = '请输入使用者姓名或设备专属代号';
      els.applyError.classList.remove('hidden');
      return;
    }
    els.btnApply.disabled = true;
    try {
      const resp = await fetch(`/api/portal/apply${statusQuery()}`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name,
          mac: activeMockMac || undefined,
          hostname: 'Mobile-Client',
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        els.applyError.textContent = data.error || '提交申请失败';
        els.applyError.classList.remove('hidden');
        return;
      }
      if (data.portal) renderStatus(data.portal);
    } catch (_) {
      els.applyError.textContent = '网络请求失败，请检查 Wi-Fi 连接';
      els.applyError.classList.remove('hidden');
    } finally {
      els.btnApply.disabled = false;
    }
  });

  els.btnRecheck.addEventListener('click', async () => {
    els.recheckIcon.classList.add('spin');
    els.recheckText.textContent = '正在检查最新状态...';
    els.btnRecheck.disabled = true;
    try {
      const s = await fetchStatus();
      if (s) {
        if (s.gatekeeper_enabled === false || s.status === 'approved' || s.is_whitelist) {
          els.recheckText.textContent = '网络已放行！';
        } else if (s.status === 'paused') {
          els.recheckText.textContent = '仍处于软路由断网状态';
        } else {
          els.recheckText.textContent = '状态已刷新';
        }
      }
    } finally {
      setTimeout(() => {
        els.recheckIcon.classList.remove('spin');
        els.recheckText.textContent = '刷新检查联网状态';
        els.btnRecheck.disabled = false;
      }, 650);
    }
  });

  els.btnNewPhone.addEventListener('click', () => {
    const randHex = () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0').toUpperCase();
    switchMockDevice(`AA:BB:CC:${randHex()}:${randHex()}:${randHex()}`);
  });

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
      fetchStatus();
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        connectWS();
      }
    }
  });

  fetchStatus().then(() => connectWS());
  pollTimer = setInterval(fetchStatus, 2000);
  tickTimer = setInterval(() => {
    if (currentStatus && currentStatus.status === 'paused') updatePausedCountdown(currentStatus);
  }, 1000);
  window.addEventListener('beforeunload', () => {
    clearInterval(pollTimer);
    clearInterval(tickTimer);
  });
})();
