"""
src/pipeline/dashboard_html.py

Interactive Web Dashboard UI for ULPF Prism Analytical Visibility.
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ULPF Prism — Unified Security Visibility</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #151c2c;
      --card-border: #232f48;
      --accent: #3b82f6;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --critical: #dc2626;
      --info: #06b6d4;
    }
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    body { background: var(--bg); color: var(--text); padding: 24px; }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--card-border);
    }
    .header h1 { font-size: 24px; font-weight: 700; color: #fff; }
    .header .badge {
      background: #1e3a8a;
      color: #93c5fd;
      padding: 4px 12px;
      border-radius: 9999px;
      font-size: 13px;
      font-weight: 600;
    }
    .filter-bar {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 24px;
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }
    .filter-bar input, .filter-bar select {
      background: #0b0f19;
      border: 1px solid var(--card-border);
      color: #fff;
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 14px;
    }
    .filter-bar input { flex-grow: 1; min-width: 200px; }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .kpi-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 20px;
    }
    .kpi-title {
      font-size: 13px;
      color: var(--text-muted);
      text-transform: uppercase;
      font-weight: 600;
      margin-bottom: 8px;
    }
    .kpi-value { font-size: 28px; font-weight: 700; color: #fff; margin-bottom: 4px; }
    .kpi-subtitle { font-size: 12px; color: var(--text-muted); }
    .panels-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
    @media (max-width: 900px) { .panels-grid { grid-template-columns: 1fr; } }
    .panel {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 20px;
    }
    .panel-title { font-size: 16px; font-weight: 600; margin-bottom: 16px; color: #fff; }
    .bar-row {
      display: flex;
      justify-content: space-between;
      margin-bottom: 10px;
      font-size: 14px;
    }
    .bar-container {
      width: 100%;
      height: 8px;
      background: #232f48;
      border-radius: 4px;
      overflow: hidden;
      margin-top: 4px;
    }
    .bar-fill { height: 100%; border-radius: 4px; }
    .table-container {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      overflow: hidden;
    }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }
    th {
      background: #121826;
      padding: 12px 16px;
      color: var(--text-muted);
      font-weight: 600;
      border-bottom: 1px solid var(--card-border);
    }
    td { padding: 12px 16px; border-bottom: 1px solid #1a2234; }
    tr:hover td { background: #1a243b; cursor: pointer; }
    .pill {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .pill-allow { background: rgba(16, 185, 129, 0.2); color: var(--success); }
    .pill-deny { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
    .pill-critical {
      background: rgba(220, 38, 38, 0.3);
      color: var(--critical);
      border: 1px solid var(--critical);
    }
    .pill-high { background: rgba(245, 158, 11, 0.2); color: var(--warning); }
    .pill-medium { background: rgba(59, 130, 246, 0.2); color: var(--accent); }
    .pill-valid { background: rgba(16, 185, 129, 0.15); color: var(--success); }
    .pill-partial { background: rgba(245, 158, 11, 0.15); color: var(--warning); }
    .drawer {
      position: fixed;
      top: 0;
      right: -600px;
      width: 600px;
      height: 100%;
      background: #0f1624;
      border-left: 1px solid var(--card-border);
      padding: 24px;
      transition: right 0.3s ease;
      overflow-y: auto;
      z-index: 100;
      box-shadow: -10px 0 25px rgba(0,0,0,0.5);
    }
    .drawer.open { right: 0; }
    .drawer-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 12px;
    }
    .drawer-close { background: none; border: none; color: #fff; font-size: 20px; cursor: pointer; }
    .drawer-section { margin-bottom: 20px; }
    .drawer-label {
      font-size: 12px;
      color: var(--text-muted);
      text-transform: uppercase;
      margin-bottom: 4px;
      font-weight: 600;
    }
    .drawer-value {
      font-size: 14px;
      word-break: break-all;
      font-family: monospace;
      background: #080c14;
      padding: 8px 12px;
      border-radius: 6px;
      border: 1px solid #1a2336;
    }
    pre {
      background: #080c14;
      padding: 12px;
      border-radius: 6px;
      overflow-x: auto;
      font-size: 12px;
      color: #a5b4fc;
      max-height: 250px;
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1>ULPF Prism — Unified Visibility Dashboard</h1>
      <p style="color: var(--text-muted); font-size: 14px; margin-top: 4px;">
        Analytical storage, evidence provenance, and multi-vendor log inspection
      </p>
    </div>
    <span class="badge">Live Pipeline Stream</span>
  </div>

  <div class="filter-bar">
    <input type="text" id="searchInput"
           placeholder="Search message, IP, action, or SHA-256 hash..."
           oninput="filterEvents()" />
    <select id="vendorFilter" onchange="filterEvents()">
      <option value="all">All Vendors</option>
      <option value="cisco">Cisco</option>
      <option value="pfsense">pfSense</option>
      <option value="suricata">Suricata</option>
    </select>
    <select id="actionFilter" onchange="filterEvents()">
      <option value="all">All Actions</option>
      <option value="allow">Allow</option>
      <option value="deny">Deny</option>
      <option value="detect">Detect</option>
    </select>
    <select id="severityFilter" onchange="filterEvents()">
      <option value="all">All Severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
    </select>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-title">Total Ingested Events</div>
      <div class="kpi-value" id="kpiTotal">--</div>
      <div class="kpi-subtitle">Processed through Source Packs</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Allow vs. Deny Ratio</div>
      <div class="kpi-value" id="kpiRatio">--</div>
      <div class="kpi-subtitle" id="kpiRatioSub">--</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">High / Critical Alerts</div>
      <div class="kpi-value" id="kpiHighCrit" style="color: var(--warning);">--</div>
      <div class="kpi-subtitle">Security policy triggers</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Schema Quality Rate</div>
      <div class="kpi-value" id="kpiQuality" style="color: var(--success);">--</div>
      <div class="kpi-subtitle">UnifiedEvent v1.0.0 compliance</div>
    </div>
  </div>

  <div class="panels-grid">
    <div class="panel">
      <div class="panel-title">Events by Source & Device</div>
      <div id="sourcesContainer"></div>
    </div>
    <div class="panel">
      <div class="panel-title">Severity Breakdown</div>
      <div id="severityContainer"></div>
    </div>
  </div>

  <div class="table-container">
    <table>
      <thead>
        <tr>
          <th>Observed (UTC)</th>
          <th>Severity</th>
          <th>Action</th>
          <th>Device / Source</th>
          <th>Source Endpoint</th>
          <th>Destination Endpoint</th>
          <th>Event Name / Description</th>
          <th>Quality</th>
        </tr>
      </thead>
      <tbody id="eventsTableBody"></tbody>
    </table>
  </div>

  <div class="drawer" id="detailDrawer">
    <div class="drawer-header">
      <h3>Log Evidence & Provenance Inspector</h3>
      <button class="drawer-close" onclick="closeDrawer()">&times;</button>
    </div>
    <div class="drawer-section">
      <div class="drawer-label">Event ID (UUID)</div>
      <div class="drawer-value" id="drawerEventId"></div>
    </div>
    <div class="drawer-section">
      <div class="drawer-label">Raw Cryptographic SHA-256 Hash</div>
      <div class="drawer-value" id="drawerRawSha256" style="color: #60a5fa;"></div>
    </div>
    <div class="drawer-section">
      <div class="drawer-label">Source Pack & Parser Provenance</div>
      <div class="drawer-value" id="drawerProvenance"></div>
    </div>
    <div class="drawer-section">
      <div class="drawer-label">Raw Verbatim Syslog Payload</div>
      <div class="drawer-value" id="drawerRawPayload" style="color: #34d399;"></div>
    </div>
    <div class="drawer-section">
      <div class="drawer-label">Full Normalized UnifiedEvent (JSON)</div>
      <pre><code id="drawerJson"></code></pre>
    </div>
  </div>

  <script>
    let allEvents = [];

    async function loadDashboard() {
      try {
        const res = await fetch('/v1/analytics/events');
        const data = await res.json();
        allEvents = data.events || [];
        renderKPIs(data.aggregations || {});
        renderPanels(data.aggregations || {});
        renderTable(allEvents);
      } catch (err) {
        console.error("Failed to load dashboard:", err);
      }
    }

    function renderKPIs(aggs) {
      document.getElementById('kpiTotal').innerText = aggs.total_events || allEvents.length;
      const avd = aggs.allow_vs_deny || {
        allow_percent: 0, deny_percent: 0, allow_count: 0, deny_count: 0
      };
      document.getElementById('kpiRatio').innerText =
        `${avd.allow_percent}% / ${avd.deny_percent}%`;
      document.getElementById('kpiRatioSub').innerText =
        `${avd.allow_count} Allow | ${avd.deny_count} Deny`;
      
      const sevs = aggs.severity_distribution || {};
      const highCrit = (sevs.critical || 0) + (sevs.high || 0);
      document.getElementById('kpiHighCrit').innerText = highCrit;

      const q = aggs.quality_metrics || {};
      const valid = q.valid || 0;
      const total = aggs.total_events || 1;
      const validPct = Math.round((valid / total) * 100);
      document.getElementById('kpiQuality').innerText = `${validPct}% Valid`;
    }

    function renderPanels(aggs) {
      const srcCont = document.getElementById('sourcesContainer');
      srcCont.innerHTML = '';
      const sources = aggs.events_by_source || {};
      const total = aggs.total_events || 1;
      for (const [src, count] of Object.entries(sources)) {
        const pct = Math.round((count / total) * 100);
        srcCont.innerHTML += `
          <div style="margin-bottom: 12px;">
            <div class="bar-row">
              <span>${src}</span>
              <span style="font-weight:700;">${count} (${pct}%)</span>
            </div>
            <div class="bar-container">
              <div class="bar-fill" style="width: ${pct}%; background: #3b82f6;"></div>
            </div>
          </div>`;
      }

      const sevCont = document.getElementById('severityContainer');
      sevCont.innerHTML = '';
      const sevs = aggs.severity_distribution || {};
      const colors = {
        critical: '#dc2626',
        high: '#f59e0b',
        medium: '#3b82f6',
        low: '#10b981',
        informational: '#06b6d4'
      };
      for (const [sev, count] of Object.entries(sevs)) {
        if (count === 0) continue;
        const pct = Math.round((count / total) * 100);
        sevCont.innerHTML += `
          <div style="margin-bottom: 12px;">
            <div class="bar-row">
              <span style="text-transform: capitalize;">${sev}</span>
              <span style="font-weight:700;">${count}</span>
            </div>
            <div class="bar-container">
              <div class="bar-fill"
                   style="width: ${pct}%; background: ${colors[sev] || '#6b7280'};"></div>
            </div>
          </div>`;
      }
    }

    function renderTable(events) {
      const tbody = document.getElementById('eventsTableBody');
      tbody.innerHTML = '';
      if (events.length === 0) {
        tbody.innerHTML =
          '<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">' +
          'No events match the current filter.</td></tr>';
        return;
      }
      events.forEach((ev, idx) => {
        const time = ev.time?.observed_at || '--';
        const sev = ev.severity?.label || 'unknown';
        const act = ev.action?.normalized || 'unknown';
        const src = `${ev.source?.ip || 'N/A'}${ev.source?.port ? ':' + ev.source.port : ''}`;
        const dst = (
          `${ev.destination?.ip || 'N/A'}` +
          `${ev.destination?.port ? ':' + ev.destination.port : ''}`
        );
        const device = `${ev.observer?.vendor || ''} ${ev.observer?.product || ''}`;
        const name = ev.event?.name || ev.event?.message || '--';
        const qual = ev.quality?.status || 'valid';

        const actClass = act === 'deny' ? 'pill-deny' : 'pill-allow';
        const sevClass = `pill-${sev}`;
        const qualClass = qual === 'valid' ? 'pill-valid' : 'pill-partial';

        const tr = document.createElement('tr');
        tr.onclick = () => openDrawer(ev);
        tr.innerHTML = `
          <td>${time}</td>
          <td><span class="pill ${sevClass}">${sev}</span></td>
          <td><span class="pill ${actClass}">${act}</span></td>
          <td>${device}</td>
          <td style="font-family: monospace;">${src}</td>
          <td style="font-family: monospace;">${dst}</td>
          <td>${name}</td>
          <td><span class="pill ${qualClass}">${qual}</span></td>
        `;
        tbody.appendChild(tr);
      });
    }

    function filterEvents() {
      const q = document.getElementById('searchInput').value.toLowerCase();
      const v = document.getElementById('vendorFilter').value.toLowerCase();
      const a = document.getElementById('actionFilter').value.toLowerCase();
      const s = document.getElementById('severityFilter').value.toLowerCase();

      const filtered = allEvents.filter(ev => {
        if (v !== 'all' && (ev.observer?.vendor || '').toLowerCase() !== v) return false;
        if (a !== 'all' && (ev.action?.normalized || '').toLowerCase() !== a) return false;
        if (s !== 'all' && (ev.severity?.label || '').toLowerCase() !== s) return false;
        if (q) {
          const rawHash = ev.traceability?.raw_sha256 || '';
          const msg = (ev.event?.message || '').toLowerCase();
          const name = (ev.event?.name || '').toLowerCase();
          const srcIp = (ev.source?.ip || '').toLowerCase();
          const dstIp = (ev.destination?.ip || '').toLowerCase();
          if (
            !rawHash.includes(q) &&
            !msg.includes(q) &&
            !name.includes(q) &&
            !srcIp.includes(q) &&
            !dstIp.includes(q)
          ) return false;
        }
        return true;
      });
      renderTable(filtered);
    }

    function openDrawer(ev) {
      document.getElementById('drawerEventId').innerText = ev.event?.id || 'N/A';
      document.getElementById('drawerRawSha256').innerText =
        ev.traceability?.raw_sha256 || 'N/A';
      const sp = ev.traceability?.source_pack;
      const parser = ev.traceability?.parser;
      document.getElementById('drawerProvenance').innerText =
        `${sp?.name || 'unknown'} v${sp?.version || '1.0.0'} -> ` +
        `${parser?.name || 'unknown'} v${parser?.version || '1.0.0'}`;
      document.getElementById('drawerRawPayload').innerText =
        ev.traceability?.raw_event?.content || 'Raw payload referenced by SHA-256';
      document.getElementById('drawerJson').innerText = JSON.stringify(ev, null, 2);
      document.getElementById('detailDrawer').classList.add('open');
    }

    function closeDrawer() {
      document.getElementById('detailDrawer').classList.remove('open');
    }

    window.onload = loadDashboard;
  </script>
</body>
</html>
"""
