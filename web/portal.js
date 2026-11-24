(() => {
  'use strict';

  const urlParams = new URLSearchParams(window.location.search);
  let activeMockMac = urlParams.get('mac') || '';
  let currentStatus = null;
  let ws = null;
  let pollTimer = null;
  let tickTimer = null;

  const els = {
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
    approvedDetail: document.getElementById('approved-detail'),
    pausedPanel: document.getElementById('paused-panel'),
    pausedTitle: document.getElementById('paused-title'),
    pausedDetail: document.getElementById('paused-detail'),
    liveTip: document.getElementById('live-tip'),
  };

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
        els.pausedTitle.textContent = `您的连接已被管理员暂停，预计 ${formatSecZh(rem)} 后自动恢复`;
        els.pausedDetail.textContent = '倒计时结束将自动放行；如需立即上网请联系管理员点击「恢复联网」。';
        return;
      }
    }
    els.pausedTitle.textContent = '您的连接已被管理员暂停，请联系开启';
    els.pausedDetail.textContent = '管理员恢复后本设备将自动放行，无需重新填写代号。';
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

    if (s.is_whitelist || s.status === 'approved') {
      els.statusOrb.className = 'status-orb orb-green';
      els.statusOrb.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>';
      els.portalSubtitle.textContent = '网络已放行 · 畅享高速访问';
      const mins = Math.floor((s.online_duration_sec || 0) / 60);
      els.approvedDetail.textContent = `设备「${s.display_name || s.mac}」已获准接入互联网（本次已连 ${mins} 分钟）。`;
      els.approvedPanel.classList.remove('hidden');
    } else if (s.status === 'pending') {
      els.statusOrb.className = 'status-orb orb-amber';
      els.statusOrb.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>';
      els.portalSubtitle.textContent = '申请已提交 · 正在实时等待审批';
      els.pendingDetail.textContent = `提交代号「${s.requested_name || s.display_name}」(${s.mac})，等待管理员点击通过...`;
      els.pendingPanel.classList.remove('hidden');
    } else if (s.status === 'paused') {
      els.statusOrb.className = 'status-orb orb-rose';
      els.statusOrb.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>';
      els.portalSubtitle.textContent = '访问已被暂停';
      updatePausedCountdown(s);
      els.pausedPanel.classList.remove('hidden');
    } else {
      els.statusOrb.className = 'status-orb orb-cyan';
      els.statusOrb.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>';
      els.portalSubtitle.textContent = '请填写设备代号申请 Wi-Fi 上网权限';
      els.applyForm.classList.remove('hidden');
    }

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
        btn.textContent = `${d.display_name} (${d.status === 'approved' ? '已联网' : d.status === 'pending' ? '待审' : d.status === 'paused' ? '暂停' : '未审'})`;
        btn.addEventListener('click', () => switchMockDevice(d.mac));
        els.mockPills.appendChild(btn);
      });
    } catch (_) {}
  }

  function switchMockDevice(mac) {
    activeMockMac = mac;
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
    } catch (_) {}
  }

  function connectWS() {
    if (ws) {
      try { ws.close(); } catch (_) {}
      ws = null;
    }
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${window.location.host}/api/portal/ws${statusQuery()}`);
    ws.onopen = () => {
      els.liveTip.textContent = '实时状态监听中 · 放行或到期恢复后立即生效';
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

  els.btnNewPhone.addEventListener('click', () => {
    const randHex = () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0').toUpperCase();
    switchMockDevice(`AA:BB:CC:${randHex()}:${randHex()}:${randHex()}`);
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
