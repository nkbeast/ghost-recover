/* GHOST//RECOVER — interface logic.
 *
 * Talks to the job-based API: long operations are started with a POST that
 * returns a job id, progress is polled, and results are paged in rather than
 * delivered as one enormous document. The previous UI re-ran the preview fetch
 * on every render, which made selecting a file reload it in a loop; preview
 * loading is now keyed on the selection actually changing.
 */
'use strict';

const API = '/api';

/* ------------------------------------------------------------------ utils */
const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function fmtSize(b) {
  b = Number(b) || 0;
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  if (b < 1099511627776) return (b / 1073741824).toFixed(2) + ' GB';
  return (b / 1099511627776).toFixed(2) + ' TB';
}

function fmtNum(n) { return (Number(n) || 0).toLocaleString(); }

function fmtDuration(ms) {
  if (!ms || ms < 0) return '—';
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm ' + (s % 60) + 's';
  return Math.floor(m / 60) + 'h ' + (m % 60) + 'm';
}

function titleCase(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : ''; }

/* -------------------------------------------------------- api + session */
// A root-privileged engine demands the session token on every /api request.
// The browser receives it either as the #tok=… fragment of the launcher URL
// or from the /api/elevate response, then keeps it for the tab's lifetime.
function sessionToken() { return sessionStorage.getItem('ghostToken') || ''; }

async function apiGet(path) {
  const h = {};
  const t = sessionToken();
  if (t) h['X-Ghost-Token'] = t;
  const r = await fetch(API + path, { headers: h });
  const t2 = await r.text();
  if (r.status === 403 && !sessionToken()) {
    throw new Error('engine-locked');
  }
  try { return JSON.parse(t2); } catch (e) { throw new Error('bad response: ' + t2.slice(0, 200)); }
}

async function apiPost(path, body) {
  const h = { 'Content-Type': 'application/json' };
  const t = sessionToken();
  if (t) h['X-Ghost-Token'] = t;
  const r = await fetch(API + path, { method: 'POST', headers: h, body: JSON.stringify(body || {}) });
  const t2 = await r.text();
  try { return JSON.parse(t2); } catch (e) { throw new Error('bad response: ' + t2.slice(0, 200)); }
}

/* ------------------------------------------------------------------ state */
const S = {
  screen: 'welcome',
  health: null,
  disks: [],
  selDisk: null,
  source: null,          // { path, offset, length, label, fs, size }
  partitions: null,
  selPartition: -1,
  partBusy: false,
  deepPartScan: false,

  job: null,             // active job status object
  jobPoll: null,
  results: null,         // page payload from /api/results
  resultJob: null,
  summary: null,         // scan/carve summary from the finished job
  page: 0,
  pageSize: 200,
  filter: { q: '', ext: '', only: '', sort: '' },
  selIndex: -1,
  selected: new Set(),
  previewMode: 'auto',
  previewKey: null,

  modal: null,
  modalData: {},
  browsePath: '',
  browseEntries: [],
  logs: [],
  logOpen: false,
  carvers: null,
  filesystems: null,
  privileges: null,
  elevating: null       // { phase: 'authenticating' | 'restarting' | 'failed', message }
};

function log(msg, level) {
  const t = new Date().toLocaleTimeString('en-GB', { hour12: false });
  S.logs.push({ t, msg, level: level || 'info' });
  if (S.logs.length > 500) S.logs.shift();
  const body = $('#logbody');
  if (body) {
    body.insertAdjacentHTML('beforeend',
      `<div class="logline ${level || 'info'}"><span class="t">[${t}]</span> ${esc(msg)}</div>`);
    body.scrollTop = body.scrollHeight;
  }
}

/* ------------------------------------------------------------------ boot */
async function boot() {
  // The launcher passes the session token as a URL fragment if the engine
  // started privileged: "http://localhost:3030/#tok=<token>". Store it and
  // strip it from the address bar — the fragment is never sent to the server.
  const m = location.hash.match(/^#tok=([0-9a-f]+)/);
  if (m) {
    sessionStorage.setItem('ghostToken', m[1]);
    history.replaceState(null, '', location.pathname + location.search);
  }
  try {
    S.health = await apiGet('/health');
  } catch (e) {
    if (e.message === 'engine-locked') {
      document.getElementById('app').innerHTML =
        `<div class="hero"><img class="logo" src="/logo.png" width="128" height="128" alt="GHOST//RECOVER">
         <div class="tag">engine locked</div>
         <div class="caps">The engine is running with elevated privileges and requires the session
           token. Reopen it from the GHOST//RECOVER launcher (or restart it with
           <span class="mono">sudo ghost_recover</span>) so the browser receives the token
           automatically.</div></div>`;
      return;
    }
    document.getElementById('app').innerHTML =
      `<div class="hero"><img class="logo" src="/logo.png" width="128" height="128" alt="GHOST//RECOVER">
       <div class="tag">engine unreachable</div>
       <div class="caps">${esc(e.message)}</div></div>`;
    return;
  }
  render();
  log(`engine ${S.health.version} ready — ${fmtNum(S.health.carvers)} carvers, ` +
      `${fmtNum(S.health.filesystems)} filesystems`, 'ok');
  if (!S.health.is_root) {
    try { S.privileges = await apiGet('/privileges'); } catch (e) { /* non-fatal */ }
    log('running without root — physical disks are not readable yet. ' +
        'Use “Unlock disk access” to authenticate.', 'warn');
    render();
  }
}

/* ------------------------------------------------------------------ render */
function render() {
  const app = document.getElementById('app');
  let html = '';
  if (S.screen === 'welcome') html = viewWelcome();
  else {
    html = viewTopbar();
    if (S.screen === 'source') html += `<div class="body">${viewSource()}</div>`;
    else if (S.screen === 'partitions') html += `<div class="body">${viewPartitions()}</div>`;
    else if (S.screen === 'workspace') html += viewWorkspace();
    if (S.logOpen) html += viewLog();
  }
  if (S.modal) html += viewModal();
  // innerHTML replacement destroys every scrollable pane (the file table in
  // .tablewrap, the sidebar, the preview), so remember where each one was and
  // put it back — otherwise clicking a file re-renders and jumps to the top.
  const scrollables = $$('#app *').filter(el => el.scrollTop > 0 || el.scrollLeft > 0)
    .map(el => [el.className, el.scrollTop, el.scrollLeft]);
  // The preview element carries a live <img>/<video>/<audio>/<iframe>/hex view.
  // Replacing its HTML re-starts the fetch and resets playback, so when the
  // selection has not actually changed, keep the live node and swap it into
  // the new tree instead of letting syncPreview reload it from scratch.
  const oldPreview = $('#preview');
  const oldKey = oldPreview ? oldPreview.dataset.key : null;
  app.innerHTML = html;
  const newPreview = $('#preview');
  if (oldPreview && newPreview && oldKey === previewKey()) {
    newPreview.parentNode.replaceChild(oldPreview, newPreview);
  }
  scrollables.forEach(([cls, top, left]) => {
    if (!cls) return;
    const els = $$('.' + cls.split(' ').filter(Boolean).join('.'));
    els.forEach(el => { el.scrollTop = top; el.scrollLeft = left; });
  });

  if (S.logOpen) {
    const body = $('#logbody');
    if (body) {
      body.innerHTML = S.logs.map(l =>
        `<div class="logline ${l.level}"><span class="t">[${l.t}]</span> ${esc(l.msg)}</div>`).join('');
      body.scrollTop = body.scrollHeight;
    }
  }
  if (S.screen === 'workspace') syncPreview();
}

function viewTopbar() {
  const busy = S.job && (S.job.state === 'running' || S.job.state === 'queued');
  const stepState = (name) => {
    const order = ['source', 'partitions', 'workspace'];
    const cur = order.indexOf(S.screen);
    const me = order.indexOf(name);
    return me < cur ? 'done' : (me === cur ? 'active' : '');
  };
  return `
  <div class="topbar">
    <span class="brand" onclick="go('welcome')">GHOST//RECOVER</span>
    <span class="ver">v${esc(S.health.version)}</span>
    <div class="steps">
      <div class="step ${stepState('source')}"><span class="n">1</span>Source</div>
      <span class="sep">›</span>
      <div class="step ${stepState('partitions')}"><span class="n">2</span>Volume</div>
      <span class="sep">›</span>
      <div class="step ${stepState('workspace')}"><span class="n">3</span>Recover</div>
    </div>
    <div class="spacer"></div>
    ${S.health.is_root
      ? '<span class="pill ok" title="physical disks are readable">full disk access</span>'
      : `<button class="btn sm warn" onclick="openModal('elevate')"
           title="Physical disks cannot be read without root">🔒 Unlock disk access</button>`}
    <div class="stat"><span class="dot ${busy ? 'red' : 'green'}"></span>
      ${busy ? esc(S.job.phase || 'working') : 'idle'}</div>
    <button class="btn sm" onclick="toggleLog()">Log ${S.logs.length ? '(' + S.logs.length + ')' : ''}</button>
    <button class="btn sm warn" onclick="shutdownEngine()"
      title="Stop the engine and release the port">Shut down</button>
  </div>`;
}

function viewWelcome() {
  const h = S.health || {};
  return `
  <div class="hero">
    <img class="logo" src="/logo.png" width="128" height="128" alt="GHOST//RECOVER">
    <div class="tag">Data Recovery Suite</div>
    <div class="caps">
      ${fmtNum(h.filesystems)} filesystems · ${fmtNum(h.carvers)} carver signatures · RAID reconstruction ·
      bad-sector imaging · partition and superblock repair<br>
      Recovered files are written to <span class="mono">${esc(h.output_root || '')}</span>
    </div>
    <div class="actions">
      <button class="btn primary" onclick="go('source')">Start recovery</button>
      <button class="btn" onclick="openModal('image')">Clone a failing disk first</button>
      <button class="btn" onclick="openModal('about')">What this can do</button>
    </div>
    ${h.is_root ? '' : `<div class="caps" style="color:var(--amber);margin-top:18px">
      Physical disks are not readable yet — that needs administrator access.
      <br><button class="btn warn" style="margin-top:12px" onclick="openModal('elevate')">
        🔒 Unlock disk access</button></div>`}
  </div>`;
}

/* ------------------------------------------------------------------ source */
function viewSource() {
  const disks = S.disks;
  const cards = disks.length ? disks.map((d, i) => {
    const icon = { hdd: '🖴', ssd: '🖴', nvme: '⚡', usb: '🔌', sdcard: '💾', virtio: '🖥' }[d.type] || '🖴';
    const colour = { hdd: '#ff8a3a', ssd: 'var(--blue)', nvme: 'var(--green)',
                     usb: 'var(--red)', sdcard: 'var(--purple)' }[d.type] || 'var(--blue)';
    return `<div class="card ${S.selDisk === d.device_path ? 'sel' : ''}" onclick="pickDisk(${i})">
      <div class="ico" style="color:${colour}">${icon}</div>
      <div class="grow">
        <div class="t nowrap">${esc(d.display_name || d.name)}</div>
        <div class="m mono">${esc(d.device_path)}</div>
        <div class="m">${esc(d.type_label)}${d.partition_count ? ' · ' + d.partition_count + ' partitions' : ''}</div>
        ${d.accessible ? '' : `<div class="m" style="color:var(--amber);margin-top:4px">
          🔒 ${esc(d.status_message)}
          ${S.health.is_root ? '' : `<button class="btn sm warn" style="margin-top:6px"
             onclick="event.stopPropagation();openModal('elevate')">Unlock</button>`}</div>`}
      </div>
      <div class="sz">${fmtSize(d.size_bytes)}</div>
    </div>`;
  }).join('') : `<div class="banner info">No block devices are readable.
      ${S.health.is_root ? 'Attach a disk, or open a disk image file below.'
                         : 'Restart the engine with sudo to see physical disks, or open a disk image file below.'}</div>`;

  return `<div class="screen">
    <h1>Choose a source</h1>
    <div class="sub">Pick a physical disk, or open a disk image (.img, .dd, .raw, .iso, .vmdk).
      Everything is opened read-only.</div>
    <div class="cards">${cards}</div>
    <div style="display:flex;gap:9px;margin-top:20px;align-items:center">
      <button class="btn" onclick="loadDisks()">Rescan devices</button>
      <button class="btn" onclick="openModal('attach')">Open image file…</button>
      <button class="btn" onclick="openModal('raid')">Assemble a RAID array…</button>
      ${S.health.is_root ? '' :
        `<button class="btn warn" onclick="openModal('elevate')">🔒 Unlock disk access</button>`}
      <div class="grow"></div>
      <button class="btn primary" ${S.selDisk ? '' : 'disabled'} onclick="mountSelected()">Continue →</button>
    </div>
  </div>`;
}

async function loadDisks() {
  try {
    const r = await apiGet('/disks');
    S.disks = r.disks || [];
    log(`${S.disks.length} block device(s) detected`);
  } catch (e) { log('device scan failed: ' + e.message, 'err'); }
  render();
}

function pickDisk(i) {
  const d = S.disks[i];
  if (!d) return;
  S.selDisk = d.device_path;
  if (!d.accessible) {
    log(d.status_message, 'warn');
    // Selecting a disk we cannot read is exactly the moment to offer the fix.
    if (!S.health.is_root) { openModal('elevate'); return; }
  }
  render();
}

async function mountSelected() {
  const d = S.disks.find(x => x.device_path === S.selDisk);
  if (d && !d.accessible && !S.health.is_root) { openModal('elevate'); return; }
  await openSource(S.selDisk);
}

async function openSource(path) {
  if (!path) return;
  log(`identifying ${path}`);
  let det;
  try {
    det = await apiPost('/detect', { image_path: path });
  } catch (e) { log('detect failed: ' + e.message, 'err'); return; }
  if (det.ok === false) { log(det.error, 'err'); alert(det.error); return; }
  const r = det.result;

  if (r.is_container && (r.container === 'gpt' || r.container === 'mbr')) {
    S.source = { path, offset: 0, length: 0, size: r.size_bytes };
    S.screen = 'partitions';
    S.partitions = null;
    S.selPartition = -1;
    render();
    await loadPartitions();
    return;
  }
  if (r.is_container) log(r.note, 'warn');

  S.source = {
    path, offset: 0, length: 0, size: r.size_bytes,
    fs: r.filesystem, label: r.label, uuid: r.uuid, detected: r.detected,
    note: r.note || r.error, repairs: r.repairs || []
  };
  log(r.detected ? `${path}: ${r.filesystem}${r.label ? ' “' + r.label + '”' : ''} (${fmtSize(r.size_bytes)})`
                 : `${path}: no filesystem detected — carving only`,
      r.detected ? 'ok' : 'warn');
  enterWorkspace();
}

/* -------------------------------------------------------------- partitions */
async function loadPartitions() {
  S.partBusy = true;
  render();
  log(`reading partition table on ${S.source.path}${S.deepPartScan ? ' (with deleted-partition scan)' : ''}`);
  try {
    const r = await apiPost('/partitions', {
      image_path: S.source.path,
      find_deleted: S.deepPartScan
    });
    S.partitions = r.result || null;
    if (S.partitions) {
      log(`${(S.partitions.partition_table || 'unknown').toUpperCase()}: ` +
          `${S.partitions.count} partition(s), ${S.partitions.deleted_count} other region(s)`,
          S.partitions.count ? 'ok' : 'warn');
      (S.partitions.warnings || []).forEach(w => log(w, 'warn'));
      if (S.partitions.error) log(S.partitions.error, 'warn');
    }
  } catch (e) { log('partition scan failed: ' + e.message, 'err'); }
  S.partBusy = false;
  render();
}

const PART_COLOURS = ['#35c8ff', '#00e57a', '#ffb020', '#b06cff', '#ff2d55',
                      '#ff8a3a', '#5dd6ff', '#7dffb2', '#ffd36b', '#d6a3ff'];

function viewPartitions() {
  const p = S.partitions;
  const total = p ? p.image_size : (S.source ? S.source.size : 0);

  let map = '<div class="partmap"><div class="bar">';
  if (p) {
    const segs = [];
    (p.partitions || []).forEach((x, i) => segs.push({ ...x, kind: 'part', idx: i }));
    (p.deleted_partitions || []).forEach((x, i) =>
      segs.push({ ...x, kind: x.recovered ? 'rec' : 'free', idx: i }));
    segs.sort((a, b) => a.start_byte - b.start_byte);
    let prevEnd = 0;
    segs.forEach(sg => {
      if (sg.start_byte > prevEnd) {
        const pct = ((sg.start_byte - prevEnd) / total) * 100;
        if (pct >= 0.4) map += `<div class="seg free" style="width:${pct}%" title="gap"></div>`;
      }
      const pct = (sg.size_bytes / total) * 100;
      prevEnd = sg.start_byte + sg.size_bytes;
      if (pct < 0.4) return;
      const colour = sg.kind === 'part' ? PART_COLOURS[sg.idx % PART_COLOURS.length]
                   : sg.kind === 'rec' ? '#ff8a3a' : null;
      const label = sg.kind === 'part' ? ('P' + sg.entry)
                  : sg.kind === 'rec' ? 'REC' : 'FREE';
      const handler = sg.kind === 'part' ? `usePartition(${sg.idx})` : `useRegion(${sg.idx})`;
      map += `<div class="seg ${colour ? '' : 'free'}" ${colour ? `style="width:${pct}%;background:${colour}"` : `style="width:${pct}%"`}
        title="${esc((sg.filesystem || sg.type) + ' · ' + fmtSize(sg.size_bytes))}"
        onclick="${handler}">${label}</div>`;
    });
    if (!segs.length) map += '<div class="seg free" style="width:100%">no partitions</div>';
  } else {
    map += `<div class="seg free" style="width:100%">${S.partBusy ? 'scanning…' : 'no data'}</div>`;
  }
  map += '</div>';
  if (p && p.partitions && p.partitions.length) {
    map += '<div class="legend">' + p.partitions.slice(0, 10).map((x, i) =>
      `<span><span class="sw" style="background:${PART_COLOURS[i % PART_COLOURS.length]}"></span>P${x.entry} ${esc(x.filesystem || x.type)}</span>`
    ).join('') + '</div>';
  }
  map += '</div>';

  const statusPill = (s) => {
    const cls = s === 'healthy' ? 'ok' : s === 'damaged' ? 'bad'
              : s === 'unallocated' ? 'mute' : 'warnp';
    return `<span class="pill ${cls}">${esc(s || 'unknown')}</span>`;
  };

  let rows = '';
  if (p) {
    (p.partitions || []).forEach((x, i) => {
      rows += `<tr class="${S.selPartition === i ? 'sel' : ''}" onclick="usePartition(${i})">
        <td style="color:${PART_COLOURS[i % PART_COLOURS.length]};font-weight:700">P${x.entry}</td>
        <td>${esc(x.label || x.name || '—')}</td>
        <td>${x.filesystem ? `<span style="color:var(--green)">${esc(x.filesystem)}</span>` : '<span class="faint">—</span>'}</td>
        <td>${statusPill(x.fs_status)}</td>
        <td class="right">${fmtSize(x.size_bytes)}</td>
        <td class="faint mono">${fmtNum(x.start_lba)}</td>
        <td class="nowrap">${esc(x.type)}</td>
        <td class="right"><button class="btn sm go" onclick="event.stopPropagation();usePartition(${i})">Open</button></td>
      </tr>`;
    });
    (p.deleted_partitions || []).forEach((x, i) => {
      const rec = x.recovered;
      rows += `<tr class="dim" onclick="useRegion(${i})">
        <td class="faint">${rec ? '⟳' : '—'}</td>
        <td class="faint">${rec ? 'Recovered volume' : 'Free space'}</td>
        <td>${x.filesystem ? `<span style="color:var(--amber)">${esc(x.filesystem)}</span>` : '<span class="faint">—</span>'}</td>
        <td>${statusPill(rec ? 'recovered' : 'unallocated')}</td>
        <td class="right">${fmtSize(x.size_bytes)}</td>
        <td class="faint mono">${fmtNum(x.start_lba)}</td>
        <td class="nowrap faint">${esc(x.note || '')}</td>
        <td class="right"><button class="btn sm" onclick="event.stopPropagation();useRegion(${i})">${rec ? 'Open' : 'Carve'}</button></td>
      </tr>`;
    });
  }
  if (!rows) rows = `<tr><td colspan="8" style="padding:34px;text-align:center" class="faint">
      ${S.partBusy ? 'Scanning…' : 'No partitions found.'}</td></tr>`;

  const gpt = p && p.partition_table === 'gpt';
  return `<div class="screen">
    <h1>${esc(S.source.path)}</h1>
    <div class="sub">
      ${fmtSize(total)} · ${p ? (p.partition_table || 'unknown').toUpperCase() : '…'} table
      ${gpt ? ` · primary GPT ${p.gpt_primary_ok ? '<span class="pill ok">valid</span>' : '<span class="pill bad">damaged</span>'}
               · backup GPT ${p.gpt_backup_ok ? '<span class="pill ok">valid</span>' : '<span class="pill bad">damaged</span>'}` : ''}
    </div>
    ${p && p.error ? `<div class="banner warn">${esc(p.error)}</div>` : ''}
    ${(p && p.warnings || []).map(w => `<div class="banner warn">${esc(w)}</div>`).join('')}
    ${map}
    <table class="grid" style="margin-top:16px">
      <thead><tr>
        <th class="static">#</th><th class="static">Volume</th><th class="static">Filesystem</th>
        <th class="static">State</th><th class="static right">Size</th><th class="static">Start LBA</th>
        <th class="static">Type</th><th class="static"></th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <div style="display:flex;gap:9px;margin-top:18px;align-items:center;flex-wrap:wrap">
      <button class="btn" onclick="go('source')">← Back</button>
      <label class="check" style="margin:0">
        <input type="checkbox" ${S.deepPartScan ? 'checked' : ''} onchange="S.deepPartScan=this.checked">
        Search for deleted partitions
      </label>
      <button class="btn" onclick="loadPartitions()" ${S.partBusy ? 'disabled' : ''}>Rescan</button>
      <div class="grow"></div>
      ${p && (!p.gpt_primary_ok || !p.gpt_backup_ok) && p.partition_table === 'gpt'
        ? '<button class="btn warn" onclick="openModal(\'repair\')">Repair partition table…</button>' : ''}
      <button class="btn" onclick="useWholeDisk()">Work on the whole disk</button>
    </div>
  </div>`;
}

function usePartition(i) {
  const p = S.partitions && S.partitions.partitions[i];
  if (!p) return;
  S.selPartition = i;
  S.source = {
    ...S.source,
    offset: p.start_byte, length: p.size_bytes,
    fs: p.filesystem, label: p.label || p.name, size: p.size_bytes,
    title: `Partition ${p.entry}${p.label ? ' “' + p.label + '”' : ''}`
  };
  log(`selected partition ${p.entry}: ${p.filesystem || p.type} at ${fmtSize(p.start_byte)}, ${fmtSize(p.size_bytes)}`, 'ok');
  enterWorkspace();
}

function useRegion(i) {
  const p = S.partitions && S.partitions.deleted_partitions[i];
  if (!p) return;
  S.source = {
    ...S.source,
    offset: p.start_byte, length: p.size_bytes,
    fs: p.filesystem || '', label: '', size: p.size_bytes,
    title: p.recovered ? 'Recovered volume' : 'Unallocated space'
  };
  log(`selected ${p.recovered ? 'recovered volume' : 'free space'} at ${fmtSize(p.start_byte)} (${fmtSize(p.size_bytes)})`,
      'warn');
  enterWorkspace();
}

function useWholeDisk() {
  S.source = { ...S.source, offset: 0, length: 0, fs: '', title: 'Whole disk' };
  log('working on the whole disk — filesystem metadata will not be available, use carving', 'warn');
  enterWorkspace();
}

function enterWorkspace() {
  S.screen = 'workspace';
  S.results = null;
  S.summary = null;
  S.resultJob = null;
  S.selIndex = -1;
  S.selected.clear();
  S.page = 0;
  S.previewKey = null;
  render();
}

/* -------------------------------------------------------------- workspace */
// The progress bar is patched in place by pollJob while a job runs — a full
// render() every 400 ms would restart the preview, blank the details pane and
// steal focus from the filter input, so only this snippet is ever replaced.
function jobBarHtml() {
  if (!(S.job && (S.job.state === 'running' || S.job.state === 'queued'))) return '';
  const pct = Number(S.job.percent) || 0;
  return `<div class="jobbar">
    <span class="pill info">${esc(S.job.kind)}</span>
    <span class="muted nowrap" style="min-width:190px">${esc(S.job.phase || '')}</span>
    <div class="bar"><i style="width:${pct.toFixed(1)}%"></i></div>
    <span class="muted mono">${pct.toFixed(0)}%</span>
    ${S.job.found ? `<span class="muted">${fmtNum(S.job.found)} found</span>` : ''}
    <button class="btn sm warn" onclick="cancelJob()">Cancel</button>
  </div>`;
}

function updateJobBar() {
  const bar = $('.jobbar');
  if (bar) bar.outerHTML = jobBarHtml();
  const stat = $('.topbar .stat');
  if (stat) {
    const busy = S.job && (S.job.state === 'running' || S.job.state === 'queued');
    stat.innerHTML = `<span class="dot ${busy ? 'red' : 'green'}"></span> ` +
                     (busy ? esc(S.job.phase || 'working') : 'idle');
  }
}

function viewWorkspace() {
  const src = S.source;
  const busy = S.job && (S.job.state === 'running' || S.job.state === 'queued');
  const files = (S.results && S.results.files) || [];

  const jobbar = busy ? jobBarHtml() : '';

  return `
  <div class="toolbar">
    <button class="btn go" ${busy ? 'disabled' : ''} onclick="startJob('scan')"
      title="Read filesystem metadata to list live and deleted files">Scan filesystem</button>
    <button class="btn" ${busy ? 'disabled' : ''} onclick="openModal('carve')"
      title="Search raw sectors for known file signatures">Carve signatures…</button>
    <button class="btn primary" ${busy ? 'disabled' : ''} onclick="startJob('deep')"
      title="Scan and carve, merged and deduplicated">Deep recovery</button>
    <div class="sep"></div>
    <button class="btn" ${files.length ? '' : 'disabled'} onclick="openModal('extract')">Recover files…</button>
    <div class="sep"></div>
    <button class="btn sm" onclick="openModal('repair')">Repair…</button>
    <button class="btn sm" onclick="openModal('image')">Clone…</button>
    <button class="btn sm" onclick="backToVolumes()">← Volumes</button>
    <div class="grow"></div>
    <span class="muted nowrap" title="${esc(src.path)}">
      ${esc(src.title || src.path)}${src.offset ? ' @ ' + fmtSize(src.offset) : ''}
      ${src.fs ? ' · ' + esc(src.fs) : ''} · ${fmtSize(src.length || src.size)}
    </span>
  </div>
  ${jobbar}
  <div class="body">
    ${viewSidebar()}
    <div class="center pane">
      ${viewFilters()}
      <div class="tablewrap">${viewFileTable()}</div>
      ${viewPager()}
    </div>
    ${viewInspector()}
  </div>`;
}

function viewSidebar() {
  const sum = S.summary;
  let html = '<div class="sidebar pane"><div class="pane-h">Volume</div>';
  const src = S.source;
  html += kv('Source', src.path.split('/').pop());
  if (src.offset) html += kv('Offset', fmtSize(src.offset));
  html += kv('Size', fmtSize(src.length || src.size));
  if (src.fs) html += kv('Filesystem', src.fs);
  if (src.label) html += kv('Label', src.label);
  if (src.uuid) html += kv('UUID', src.uuid);

  if (sum && sum.scan) {
    const s = sum.scan;
    html += '<div class="pane-h" style="margin-top:8px">Filesystem scan</div>';
    if (!s.ok && s.error) html += `<div style="padding:8px 11px" class="banner warn">${esc(s.error)}</div>`;
    html += kv('Files found', fmtNum(s.file_count));
    html += kv('Deleted', fmtNum(s.deleted_found));
    if (s.block_size) html += kv('Block size', fmtNum(s.block_size));
    if (s.total_blocks) html += kv('Blocks', fmtNum(s.total_blocks));
    if (s.free_blocks > 0) html += kv('Free blocks', fmtNum(s.free_blocks));
    if (s.techniques && s.techniques.length) {
      html += '<div class="pane-h" style="margin-top:8px">Techniques applied</div><div class="tags">' +
        s.techniques.map(t => `<span class="tag">${esc(t.replace(/_/g, ' '))}</span>`).join('') + '</div>';
    }
    const stats = Object.entries(s.stats || {});
    if (stats.length) {
      html += '<div class="pane-h">Counters</div>';
      stats.forEach(([k, v]) => { html += kv(k.replace(/_/g, ' '), fmtNum(v)); });
    }
  }
  if (sum && sum.carve) {
    const c = sum.carve;
    html += '<div class="pane-h" style="margin-top:8px">Carving</div>';
    if (c.error) html += `<div style="padding:8px 11px" class="banner warn">${esc(c.error)}</div>`;
    html += kv('Scanned', fmtSize(c.bytes_scanned));
    html += kv('Signatures', fmtNum(c.signatures_loaded));
    html += kv('Candidates', fmtNum(c.candidates_seen));
    html += kv('Rejected', fmtNum(c.rejected));
    html += kv('Duplicates', fmtNum(c.duplicates));
    html += kv('Recovered', fmtNum(c.files_recovered));
    html += kv('Elapsed', fmtDuration(c.elapsed_ms));
    const byCat = Object.entries(c.by_category || {});
    if (byCat.length) {
      html += '<div class="pane-h">By category</div>';
      byCat.sort((a, b) => b[1] - a[1]).forEach(([k, v]) => { html += kv(k, fmtNum(v)); });
    }
  }
  html += '</div>';
  return html;
}

function kv(k, v) {
  return `<div class="kv"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`;
}

function viewFilters() {
  const exts = S.results ? Object.entries(S.results.by_ext || {}).sort((a, b) => b[1] - a[1]) : [];
  return `<div class="filters">
    <input class="input grow" placeholder="Filter by name or path…" value="${esc(S.filter.q)}"
      oninput="S.filter.q=this.value" onchange="S.page=0;loadResults()"
      onkeydown="if(event.key==='Enter'){S.page=0;loadResults()}">
    <select class="input" onchange="S.filter.ext=this.value;S.page=0;loadResults()">
      <option value="">All types</option>
      ${exts.map(([e, n]) => `<option value="${esc(e)}"
        ${S.filter.ext === e ? 'selected' : ''}>${esc(e)} (${n})</option>`).join('')}
    </select>
    <select class="input" onchange="S.filter.only=this.value;S.page=0;loadResults()">
      <option value="">Everything</option>
      <option value="deleted" ${S.filter.only === 'deleted' ? 'selected' : ''}>Deleted only</option>
      <option value="live" ${S.filter.only === 'live' ? 'selected' : ''}>Existing only</option>
    </select>
    <button class="btn sm" onclick="selectAllShown()">Select page</button>
    <button class="btn sm" onclick="S.selected.clear();render()">Clear</button>
    <span class="muted nowrap">${S.selected.size ? S.selected.size + ' selected' : ''}</span>
  </div>`;
}

function sortHeader(key, label, extra) {
  const active = S.filter.sort === key;
  return `<th class="${extra || ''}" onclick="setSort('${key}')">${esc(label)}${active ? ' ▾' : ''}</th>`;
}

function viewFileTable() {
  if (!S.results) {
    return `<div class="preview"><div class="empty">
      No results yet.<br><br>
      <b>Scan filesystem</b> reads the volume's own metadata and lists files, including deleted ones.<br>
      <b>Carve signatures</b> ignores metadata and finds files by their content, which still works
      when the filesystem is destroyed.<br>
      <b>Deep recovery</b> does both and merges the results.
    </div></div>`;
  }
  const files = S.results.files || [];
  if (!files.length) {
    return `<div class="preview"><div class="empty">Nothing matches the current filter.</div></div>`;
  }
  const rows = files.map(f => {
    const conf = f.confidence >= 0.9 ? 'ok' : f.confidence >= 0.5 ? 'warnp' : 'bad';
    const flags = [
      f.deleted ? '<span class="pill bad">deleted</span>' : '',
      f.recoverable < f.size ? '<span class="pill warnp">incomplete</span>' : '',
      f.encrypted ? '<span class="pill warnp">encrypted</span>' : '',
      f.compressed ? '<span class="pill mute">compressed</span>' : '',
      f.ads ? '<span class="pill info">ADS</span>' : ''
    ].filter(Boolean).join(' ');
    return `<tr class="${S.selIndex === f.index ? 'sel' : ''}" onclick="selectFile(${f.index})">
      <td onclick="event.stopPropagation();toggleSel(${f.index})" style="width:22px">
        <input type="checkbox" ${S.selected.has(f.index) ? 'checked' : ''}
          onclick="event.stopPropagation();toggleSel(${f.index})"></td>
      <td class="nowrap" title="${esc(f.path || f.name)}">${esc(f.name)}</td>
      <td class="faint nowrap" title="${esc(f.path)}">${esc(f.path)}</td>
      <td class="right nowrap">${fmtSize(f.size)}</td>
      <td class="right nowrap ${f.recoverable < f.size ? 'faint' : ''}">${fmtSize(f.recoverable)}</td>
      <td>${flags}</td>
      <td><span class="pill ${conf}">${Math.round(f.confidence * 100)}%</span></td>
      <td class="faint nowrap" title="${esc(f.method)}">${esc((f.method || '').replace(/_/g, ' '))}</td>
      <td class="faint nowrap">${esc((f.mtime_iso || '').replace('T', ' ').replace('Z', ''))}</td>
    </tr>`;
  }).join('');

  return `<table class="grid">
    <thead><tr>
      <th class="static"></th>
      ${sortHeader('name', 'Name')}
      <th class="static">Path</th>
      ${sortHeader('size', 'Size', 'right')}
      <th class="static right">Recoverable</th>
      <th class="static">Flags</th>
      ${sortHeader('confidence', 'Conf')}
      <th class="static">Recovered by</th>
      ${sortHeader('mtime', 'Modified')}
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function viewPager() {
  if (!S.results) return '';
  const r = S.results;
  const from = r.matched ? r.offset + 1 : 0;
  const to = Math.min(r.offset + r.limit, r.matched);
  const pages = Math.max(1, Math.ceil(r.matched / r.limit));
  const cur = Math.floor(r.offset / r.limit) + 1;
  return `<div class="pager">
    <button class="btn sm" ${r.offset <= 0 ? 'disabled' : ''} onclick="S.page--;loadResults()">◀</button>
    <span>${fmtNum(from)}–${fmtNum(to)} of ${fmtNum(r.matched)}${r.matched !== r.total ? ' (filtered from ' + fmtNum(r.total) + ')' : ''}</span>
    <button class="btn sm" ${to >= r.matched ? 'disabled' : ''} onclick="S.page++;loadResults()">▶</button>
    <span class="faint">page ${cur}/${pages}</span>
    <div class="grow"></div>
    <button class="btn sm" ${S.selected.size ? '' : 'disabled'} onclick="openModal('extract')">
      Recover ${S.selected.size ? S.selected.size + ' selected' : 'files'}</button>
  </div>`;
}

function setSort(key) {
  S.filter.sort = S.filter.sort === key ? '' : key;
  S.page = 0;
  loadResults();
}

function selectAllShown() {
  ((S.results && S.results.files) || []).forEach(f => S.selected.add(f.index));
  render();
}

function toggleSel(i) {
  if (S.selected.has(i)) S.selected.delete(i); else S.selected.add(i);
  render();
}

/* -------------------------------------------------------------- inspector */
function currentFile() {
  const files = (S.results && S.results.files) || [];
  return files.find(f => f.index === S.selIndex) || null;
}

function viewInspector() {
  const f = currentFile();
  return `<div class="inspector pane">
    <div class="pane-h">
      <span class="grow nowrap">${f ? esc(f.name) : 'Preview'}</span>
      ${f ? `<button class="btn sm ${S.previewMode === 'auto' ? 'primary' : ''}" onclick="setPreview('auto')">View</button>
             <button class="btn sm ${S.previewMode === 'hex' ? 'primary' : ''}" onclick="setPreview('hex')">Hex</button>`
          : ''}
    </div>
    <div class="preview" id="preview">
      <div class="empty">${f ? 'Loading…' : 'Select a file to preview it.<br><br>Files are read straight from the volume — nothing is written until you choose to recover.'}</div>
    </div>
    <div class="details" id="details">${f ? '' : ''}</div>
  </div>`;
}

function setPreview(mode) {
  S.previewMode = mode;
  render();
}

function selectFile(i) {
  S.selIndex = i;
  render();
}

/* Preview is refreshed only when the selection or mode actually changes, so a
 * re-render caused by anything else does not restart the fetch. The marker
 * lives on the element rather than in S: a render() replaces the pane's HTML,
 * and the new element must be repopulated even though the selection is the
 * same — otherwise the preview is left showing "Loading…" forever. render()
 * preserves the live element across unchanged re-renders, so this normally
 * returns before touching the network. */
function previewKey() {
  const f = currentFile();
  return f ? `${S.resultJob}:${f.index}:${S.previewMode}` : 'none';
}

function syncPreview() {
  const f = currentFile();
  const host = $('#preview');
  if (!host) return;
  renderDetails(f);
  const key = previewKey();
  if (host.dataset.key === key) return;
  host.dataset.key = key;
  if (!f) return;
  if (S.previewMode === 'hex') return loadHex(f, host);
  return loadPreview(f, host);
}

function renderDetails(f) {
  const host = $('#details');
  if (!host) return;
  if (!f) { host.innerHTML = ''; return; }
  let html = kv('Name', f.name) + kv('Path', f.path || '—') +
             kv('Size', fmtSize(f.size)) + kv('Recoverable', fmtSize(f.recoverable)) +
             kv('State', f.deleted ? 'deleted' : 'existing') +
             kv('Confidence', Math.round(f.confidence * 100) + '%') +
             kv('Recovered by', (f.method || '').replace(/_/g, ' ')) +
             kv('Device offset', fmtNum(f.offset)) +
             kv('Modified', (f.mtime_iso || '—').replace('T', ' ').replace('Z', ''));
  host.innerHTML = html + `<div style="padding:8px 11px;display:flex;gap:7px">
      <button class="btn sm" onclick="downloadFile(${f.index})">Download</button>
      <button class="btn sm" onclick="showFileInfo(${f.index})">Details…</button>
    </div>`;
}

const IMG = ['jpg','jpeg','png','gif','bmp','webp','tif','tiff','ico','svg','heic','heif','avif'];
const VID = ['mp4','m4v','mkv','webm','avi','mov','flv','3gp','ts','mpg','mpeg','wmv'];
const AUD = ['mp3','wav','flac','ogg','oga','opus','m4a','aac','aiff','ac3','amr','mid','wma','au'];
const TXT = ['txt','md','log','json','xml','html','htm','csv','yaml','yml','ini','conf','toml',
             'py','sh','js','ts','c','cpp','h','hpp','rs','go','java','rb','php','sql','pem',
             'service','gitconfig','tex','dockerfile','cmake','env','eml','mbox'];

function contentUrl(index, max) {
  // Media tags, iframes and downloads cannot send the X-Ghost-Token header,
  // so the session token rides as a query param as well — the server accepts
  // it on /api/content only.
  return `${API}/content?job=${encodeURIComponent(S.resultJob)}&index=${index}` +
         (max ? `&max=${max}` : '') +
         (sessionToken() ? `&tok=${sessionToken()}` : '');
}

// Decode an ICO entry that is a BMP-style DIB into a canvas. Icon DIBs are
// bottom-up BGRA rows with a trailing monochrome AND mask (transparent where
// the mask bit is 1); paletted entries resolve through the color table.
function dibToCanvas(buf, off) {
  const view = new DataView(buf, off);
  if (buf.length - off < 40 || view.getUint32(0, true) !== 40) return null;
  const bpp = view.getUint16(14, true);
  const w = view.getInt32(4, true);
  const rawH = view.getInt32(8, true);
  const topDown = rawH < 0;
  // Icon DIBs store twice the display height: pixels then the AND mask.
  const h = topDown ? -rawH : Math.floor(rawH / 2);
  if (w <= 0 || h <= 0 || w > 1024 || h > 1024) return null;
  const stride = Math.ceil((w * bpp) / 32) * 4;
  const palSize = bpp <= 8 ? (1 << bpp) * 4 : 0;
  const pxStart = 40 + palSize;
  const pxEnd = pxStart + stride * h;
  const maskStride = Math.ceil(w / 32) * 4;
  const maskStart = pxEnd;
  if (pxEnd + (topDown ? 0 : maskStride * h) > buf.length) return null;
  const pal = [];
  if (bpp <= 8) {
    for (let i = 0; i < (1 << bpp); i++) {
      const o = 40 + i * 4;
      pal.push([buf[off + o + 2], buf[off + o + 1], buf[off + o], buf[off + o + 3]]);
    }
  }
  const c = document.createElement('canvas');
  c.width = w; c.height = h;
  const ctx = c.getContext('2d');
  const img = ctx.createImageData(w, h);
  for (let y = 0; y < h; y++) {
    const sy = topDown ? y : h - 1 - y;
    for (let x = 0; x < w; x++) {
      let r = 0, g = 0, b = 0, a = 255;
      if (bpp === 32) {
        const o = off + pxStart + sy * stride + x * 4;
        b = buf[o]; g = buf[o + 1]; r = buf[o + 2]; a = buf[o + 3];
      } else if (bpp === 24) {
        const o = off + pxStart + sy * stride + x * 3;
        b = buf[o]; g = buf[o + 1]; r = buf[o + 2];
      } else if (bpp <= 8) {
        const o = off + pxStart + sy * stride + ((x * bpp) >> 3);
        const idx = (buf[o] >> (8 - bpp - (x * bpp & 7))) & ((1 << bpp) - 1);
        [r, g, b, a] = pal[idx];
      } else {
        return null;
      }
      if (!topDown) {
        const m = off + maskStart + sy * maskStride + (x >> 3);
        if ((buf[m] >> (7 - (x & 7))) & 1) a = 0;
      }
      const di = (y * w + x) * 4;
      img.data[di] = r; img.data[di + 1] = g; img.data[di + 2] = b; img.data[di + 3] = a;
    }
  }
  ctx.putImageData(img, 0, 0);
  return c;
}

// Fetches a recovered .ico and returns a PNG data URL it can preview with.
// Browsers do not all render ICO files inside <img> (Firefox only uses them
// as favicons), so the best entry — PNG or BMP DIB — is decoded to a canvas.
function icoPngUrl(index) {
  return fetch(contentUrl(index, 0))
    .then(r => {
      if (!r.ok) throw 0;
      return r.arrayBuffer();
    })
    .then(arb => {
      const dv = new DataView(arb);
      const buf = new Uint8Array(arb);
      if (arb.byteLength < 6 || dv.getUint16(0, true) !== 0 || dv.getUint16(2, true) !== 1) throw 0;
      const n = dv.getUint16(4, true);
      if (n === 0 || arb.byteLength < 6 + n * 16) throw 0;
      let best = -1, bestArea = 0;
      for (let i = 0; i < n; i++) {
        const o = 6 + i * 16;
        const w = dv.getUint8(o) || 256, h = dv.getUint8(o + 1) || 256;
        const area = w * h;
        if (area > bestArea) { bestArea = area; best = i; }
      }
      const o = 6 + best * 16;
      const size = dv.getUint32(o + 8, true), entryOff = dv.getUint32(o + 12, true);
      if (entryOff + size > arb.byteLength) throw 0;
      const png = size > 8 && buf[entryOff] === 0x89 && buf[entryOff + 1] === 0x50 &&
                  buf[entryOff + 2] === 0x4E && buf[entryOff + 3] === 0x47;
      const canvas = png ? null : dibToCanvas(buf, entryOff);
      const done = src => {
        const c = document.createElement('canvas');
        c.width = src.naturalWidth || 256; c.height = src.naturalHeight || 256;
        c.getContext('2d').drawImage(src, 0, 0);
        return c.toDataURL('image/png');
      };
      if (canvas) return Promise.resolve(canvas.toDataURL('image/png'));
      const img = new Image();
      const obj = URL.createObjectURL(new Blob([buf.slice(entryOff, entryOff + size)],
                                               {type: 'image/png'}));
      return new Promise((resolve, reject) => {
        img.onload = () => { URL.revokeObjectURL(obj); try { resolve(done(img)); } catch (e) { reject(0); } };
        img.onerror = () => { URL.revokeObjectURL(obj); reject(0); };
        img.src = obj;
      });
    });
}

async function loadPreview(f, host) {
  const ext = (f.ext || '').toLowerCase();
  // Media and PDFs must receive the complete file: the server streams plain
  // files in windows, so there is no reason to cap them — a 64 MB cap meant a
  // recovered video or PDF over that size played only its first third.
  const unlimited = contentUrl(f.index, 0);
  const url = contentUrl(f.index, 256 * 1024 * 1024);
  const bail = () => {
    host.innerHTML = '<div class="empty">This file could not be rendered.<br>Switch to Hex to inspect the bytes.</div>';
  };

  function partialWarn(f) {
    if (f.recoverable >= f.size || f.size <= 0) return '';
    const pct = Math.round(100 * f.recoverable / f.size);
    return `<div class="empty" style="margin-bottom:10px">Recovered ${pct}% of this file — ` +
           `playback may stop early or fail at the missing ${fmtSize(f.size - f.recoverable)}.</div>`;
  }

  if (f.recoverable === 0 && f.size > 0) {
    host.innerHTML = `<div class="empty">No data is recoverable for this file.<br><br>
      Its name and metadata survived, but the blocks that held its contents have been
      released or overwritten.</div>`;
    return;
  }
  if (IMG.includes(ext)) {
    host.innerHTML = '';
    if (ext === 'ico') {
      // ICO is not reliably renderable in <img> across browsers; decode the
      // largest entry to a PNG first, falling back to the raw file if the
      // decode fails (Chrome renders it natively).
      host.innerHTML = '<div class="empty">Loading…</div>';
      icoPngUrl(f.index).then(src => {
        const img = document.createElement('img');
        img.src = src || url;
        img.onerror = bail;
        host.innerHTML = '';
        host.appendChild(img);
      }).catch(() => {
        const img = document.createElement('img');
        img.src = url;
        img.onerror = bail;
        host.innerHTML = '';
        host.appendChild(img);
      });
      return;
    }
    const img = document.createElement('img');
    img.src = url;
    img.onerror = bail;
    host.appendChild(img);
    return;
  }
  if (VID.includes(ext)) {
    const video = document.createElement('video');
    video.src = unlimited;
    video.controls = true;
    video.preload = 'metadata';
    video.onerror = bail;
    host.innerHTML = partialWarn(f);
    host.appendChild(video);
    return;
  }
  if (AUD.includes(ext)) {
    const wrap = document.createElement('div');
    wrap.style.cssText = 'text-align:center;padding:24px;width:100%';
    const note = document.createElement('div');
    note.style.cssText = 'font-size:40px;margin-bottom:14px';
    note.textContent = '♪';
    const muted = document.createElement('div');
    muted.className = 'muted';
    muted.style.cssText = 'margin-bottom:12px;word-break:break-all';
    muted.textContent = f.name;
    const audio = document.createElement('audio');
    audio.src = unlimited;
    audio.controls = true;
    audio.preload = 'metadata';
    audio.onerror = bail;
    wrap.appendChild(note);
    wrap.appendChild(muted);
    wrap.appendChild(audio);
    host.innerHTML = partialWarn(f);
    host.appendChild(wrap);
    return;
  }
  if (ext === 'pdf') {
    const frame = document.createElement('iframe');
    frame.src = unlimited;
    host.appendChild(frame);
    return;
  }
  if (TXT.includes(ext) || !ext) {
    host.innerHTML = '<div class="empty">Loading…</div>';
    try {
      const r = await fetch(contentUrl(f.index, 1024 * 1024));
      let t = await r.text();
      if (t.length > 400000) t = t.slice(0, 400000) + '\n\n[truncated at 400 KB]';
      host.innerHTML = `<pre>${esc(t)}</pre>`;
    } catch (e) {
      host.innerHTML = `<div class="empty">Could not read: ${esc(e.message)}</div>`;
    }
    return;
  }
  loadHex(f, host);
}

async function loadHex(f, host) {
  host.innerHTML = '<div class="empty">Loading…</div>';
  try {
    const r = await apiGet(`/hex?job=${encodeURIComponent(S.resultJob)}&index=${f.index}&offset=0&length=2048`);
    if (!r.ok) throw new Error(r.error || 'no data');
    host.innerHTML = '<div class="hexview">' + (r.lines || []).map(l =>
      `<div class="row"><span class="off">${l.offset.toString(16).padStart(8, '0').toUpperCase()}</span>` +
      `<span class="hx">${esc(l.hex)}</span><span class="as">${esc(l.ascii)}</span></div>`
    ).join('') + `<div class="faint" style="margin-top:9px">showing ${fmtNum(r.length)} of ${fmtNum(r.total_size)} bytes</div></div>`;
  } catch (e) {
    host.innerHTML = `<div class="empty">Hex view failed: ${esc(e.message)}</div>`;
  }
}

function downloadFile(index) {
  const a = document.createElement('a');
  a.href = contentUrl(index, 0);
  a.download = '';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

async function showFileInfo(index) {
  try {
    const r = await apiGet(`/fileinfo?job=${encodeURIComponent(S.resultJob)}&index=${index}`);
    if (!r.ok) throw new Error(r.error);
    const d = r.detail, f = r.file;
    S.modalData = { title: f.name, info: r };
    S.modal = 'fileinfo';
    render();
  } catch (e) { log('details failed: ' + e.message, 'err'); }
}

/* -------------------------------------------------------------- jobs */
async function startJob(kind, extra) {
  if (S.job && (S.job.state === 'running' || S.job.state === 'queued')) return;
  const body = Object.assign({
    image_path: S.source.path,
    offset: S.source.offset || 0,
    partition_size: S.source.length || 0,
    filesystem: kind === 'carve' ? '' : (S.source.fs || '')
  }, extra || {});
  log(`starting ${kind}…`);
  try {
    const r = await apiPost('/' + kind, body);
    if (!r.ok) { log(r.error || 'could not start', 'err'); alert(r.error); return; }
    S.job = { id: r.job, kind, state: 'queued', phase: 'starting', percent: 0 };
    render();
    pollJob(r.job);
  } catch (e) { log('start failed: ' + e.message, 'err'); }
}

function pollJob(id) {
  clearInterval(S.jobPoll);
  S.jobPoll = setInterval(async () => {
    try {
      const r = await apiGet('/job?id=' + encodeURIComponent(id));
      if (!r.ok) throw new Error(r.error);
      S.job = r.job;
      if (['done', 'failed', 'cancelled'].includes(r.job.state)) {
        clearInterval(S.jobPoll);
        S.jobPoll = null;
        onJobFinished(r);
      } else {
        updateJobBar();
      }
    } catch (e) {
      clearInterval(S.jobPoll);
      S.jobPoll = null;
      log('lost track of the job: ' + e.message, 'err');
      render();
    }
  }, 400);
}

async function onJobFinished(r) {
  const j = r.job;
  const kind = j.kind;
  if (j.state === 'failed') {
    log(`${kind} failed: ${j.error || 'unknown error'}`, 'err');
    render();
    return;
  }
  if (j.state === 'cancelled') { log(`${kind} cancelled`, 'warn'); render(); return; }

  const res = r.result || {};
  if (kind === 'extract') {
    log(`recovered ${fmtNum(res.files_written)} file(s), ${res.bytes_human || ''} → ${res.output_dir}`,
        res.ok ? 'ok' : 'err');
    if (res.error) log(res.error, 'err');
    if (res.files_undecoded) {
        log(`${res.files_undecoded} file(s) were written in the filesystem's compressed form ` +
            `and are not usable as-is — see still_compressed in the manifest`, 'warn');
        (res.undecoded || []).slice(0, 10).forEach(f => log('  ' + f, 'warn'));
    }
    (res.failures || []).slice(0, 10).forEach(f => log('  ' + f, 'warn'));
    alert(`Recovered ${fmtNum(res.files_written)} file(s) to\n${res.output_dir}` +
          (res.files_failed ? `\n\n${res.files_failed} file(s) failed — see the log.` : '') +
          (res.files_undecoded
            ? `\n\n${res.files_undecoded} file(s) are still compressed and not usable as-is.`
            : ''));
    render();
    return;
  }
  if (kind === 'image') {
    log(`clone finished: ${fmtSize(res.bytes_copied)} copied, ${fmtSize(res.bytes_bad)} unreadable ` +
        `in ${fmtNum(res.bad_regions)} region(s) → ${res.output_path}`, res.ok ? 'ok' : 'err');
    alert(`Clone written to\n${res.output_path}\n\nCopied ${fmtSize(res.bytes_copied)}` +
          (res.bytes_bad ? `\nUnreadable: ${fmtSize(res.bytes_bad)} in ${res.bad_regions} region(s)` : ''));
    render();
    return;
  }
  if (kind === 'raid') {
    log(`array assembled: ${fmtSize(res.bytes_written)} → ${res.output_path}`, res.ok ? 'ok' : 'err');
    if (res.ok) {
      if (confirm(`Array assembled to\n${res.output_path}\n\nOpen it now?`)) {
        S.modal = null;
        await openSource(res.output_path);
        return;
      }
    } else if (res.error) alert(res.error);
    render();
    return;
  }

  // scan / carve / deep
  S.summary = res;
  S.resultJob = j.id;
  S.page = 0;
  S.selIndex = -1;
  S.selected.clear();
  S.previewKey = null;
  if (res.scan && !res.scan.ok && res.scan.error) log('scan: ' + res.scan.error, 'warn');
  if (res.carve && res.carve.error) log('carve: ' + res.carve.error, 'warn');
  log(`${kind} finished in ${fmtDuration(j.finished_ms - j.started_ms)}: ` +
      `${fmtNum(res.file_count)} file(s)`, 'ok');
  await loadResults();
}

async function cancelJob() {
  if (!S.job) return;
  await apiPost('/job/cancel', { id: S.job.id });
  log('cancelling…', 'warn');
}

async function loadResults() {
  if (!S.resultJob) return;
  const q = new URLSearchParams({
    job: S.resultJob,
    offset: String(S.page * S.pageSize),
    limit: String(S.pageSize),
    q: S.filter.q, ext: S.filter.ext, only: S.filter.only, sort: S.filter.sort
  });
  try {
    const r = await apiGet('/results?' + q.toString());
    if (!r.ok) throw new Error(r.error);
    S.results = r;
    if (S.page * S.pageSize >= r.matched && r.matched > 0) {
      S.page = Math.floor((r.matched - 1) / S.pageSize);
      return loadResults();
    }
  } catch (e) { log('could not load results: ' + e.message, 'err'); }
  render();
}

function backToVolumes() {
  S.screen = S.partitions ? 'partitions' : 'source';
  render();
}

function go(screen) {
  S.screen = screen;
  if (screen === 'source' && !S.disks.length) loadDisks();
  render();
}

function toggleLog() { S.logOpen = !S.logOpen; render(); }

function shutdownEngine() {
  const job = S.job && S.job.state && S.job.state !== 'done' && S.job.state !== 'failed'
    ? '\n\nA job is still running and will be interrupted.'
    : '';
  if (!confirm('Shut down the GHOST//RECOVER engine?' + job)) return;
  fetch('/api/shutdown', { method: 'POST' }).catch(() => {});
  setTimeout(() => {
    document.body.innerHTML = `<div class="center">
      <img class="logo" src="/logo.png" width="128" height="128" alt="GHOST//RECOVER">
      <div class="tag">Engine stopped — you may close this tab.</div>
      <div class="tag">The next launch will start a fresh session.</div>
    </div>`;
  }, 300);
}

function viewLog() {
  return `<div class="logdrawer">
    <div class="pane-h"><span class="grow">Activity log</span>
      <button class="btn sm" onclick="S.logs=[];render()">Clear</button>
      <button class="btn sm" onclick="toggleLog()">Close</button></div>
    <div class="logbody" id="logbody"></div>
  </div>`;
}

/* -------------------------------------------------------------- modals */
function openModal(name) {
  S.modal = name;
  S.modalData = {};
  if (name === 'attach' && !S.browsePath) browseTo('~');
  else if (name === 'about' || name === 'carve') loadAbout();
  else if (name === 'elevate') loadPrivileges();
  else render();
}

function closeModal() { S.modal = null; render(); }

function viewModal() {
  const body = {
    attach: modalAttach, carve: modalCarve, extract: modalExtract,
    image: modalImage, raid: modalRaid, repair: modalRepair,
    about: modalAbout, fileinfo: modalFileInfo, elevate: modalElevate
  }[S.modal];
  if (!body) return '';
  return `<div class="modal-bg" onclick="if(event.target===this)closeModal()">${body()}</div>`;
}

function modalShell(title, inner, footer, width) {
  return `<div class="modal" ${width ? `style="width:${width}px"` : ''}>
    <div class="modal-h"><span>${esc(title)}</span>
      <button class="btn sm" onclick="closeModal()">✕</button></div>
    <div class="modal-b">${inner}</div>
    <div class="modal-f">${footer}</div>
  </div>`;
}

/* ---- attach image ---- */
function modalAttach() {
  const rows = S.browseEntries.map(e => `
    <div class="row" data-path="${esc(joinPath(S.browsePath, e.name))}"
         data-dir="${e.is_dir ? '1' : '0'}" onclick="browsePick(this)">
      <span>${e.is_dir ? '📁' : '📄'}</span>
      <span class="grow nowrap" style="color:${e.is_dir ? 'var(--blue)' : 'var(--fg)'}">${esc(e.name)}</span>
      ${e.is_dir ? '' : `<span class="faint">${fmtSize(e.size)}</span>`}
    </div>`).join('');
  return modalShell('Open a disk image', `
    <div class="field">
      <label>Path to an image file or device</label>
      <input class="input" id="attachPath" placeholder="/path/to/disk.img or /dev/sdb"
        value="${esc(S.modalData.path || '')}" oninput="S.modalData.path=this.value">
      <div class="hint">Raw images (.img, .dd, .raw), ISO files and block devices all work.
        The file is opened read-only.</div>
    </div>
    <div class="browser">
      <div class="path">${esc(S.browsePath || '/')}</div>
      ${rows || '<div class="row faint">empty</div>'}
    </div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button>
     <button class="btn primary" onclick="attachConfirm()">Open</button>`);
}

function joinPath(a, b) {
  if (b === '..') { const p = a.replace(/\/[^/]*$/, ''); return p || '/'; }
  return a.endsWith('/') ? a + b : a + '/' + b;
}

async function browseTo(path) {
  try {
    const r = await apiGet('/browse?path=' + encodeURIComponent(path));
    if (!r.ok) throw new Error(r.error);
    S.browsePath = r.path;
    S.browseEntries = r.entries || [];
  } catch (e) { log('browse failed: ' + e.message, 'err'); }
  render();
}

function pickFile(p) { S.modalData.path = p; render(); }

function browsePick(row) {
  const p = row.dataset.path;
  (row.dataset.dir === '1' ? browseTo : pickFile)(p);
}

async function attachConfirm() {
  const p = (S.modalData.path || '').trim();
  if (!p) return;
  closeModal();
  await openSource(p);
}

/* ---- carve options ---- */
function modalCarve() {
  const cats = (S.carvers && S.carvers.categories) || [];
  const chosen = S.modalData.cats || [];
  return modalShell('Carve signatures', `
    <div class="banner info">Carving reads every sector and identifies files by their contents,
      so it works even when the filesystem is gone. It cannot recover filenames — only data.</div>
    <div class="field">
      <label>Limit to these categories (none selected = all)</label>
      <div style="display:flex;flex-wrap:wrap;gap:6px">
        ${cats.map(c => `<label class="check" style="margin:0">
          <input type="checkbox" data-cat="${esc(c)}" ${chosen.includes(c) ? 'checked' : ''}
            onchange="toggleCat(this.dataset.cat)">
          ${esc(c)}</label>`).join('') || '<span class="faint">loading…</span>'}
      </div>
    </div>
    <label class="check"><input type="checkbox" id="cvUnalloc"
      ${S.modalData.unalloc ? 'checked' : ''} onchange="S.modalData.unalloc=this.checked">
      Only search free space (faster; finds deleted files, skips existing ones)</label>
    <label class="check"><input type="checkbox" id="cvText"
      ${S.modalData.text ? 'checked' : ''} onchange="S.modalData.text=this.checked">
      Also recover loose runs of text</label>
    <label class="check"><input type="checkbox" ${S.modalData.novalidate ? '' : 'checked'}
      onchange="S.modalData.novalidate=!this.checked">
      Validate file structure (recommended — removes most false positives)</label>
    <div class="field" style="margin-top:14px">
      <label>Maximum files</label>
      <input class="input" type="number" value="${S.modalData.max || 20000}"
        oninput="S.modalData.max=parseInt(this.value)||20000">
    </div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button>
     <button class="btn primary" onclick="runCarve()">Start carving</button>`);
}

function toggleCat(c) {
  const cats = S.modalData.cats || (S.modalData.cats = []);
  const i = cats.indexOf(c);
  if (i >= 0) cats.splice(i, 1); else cats.push(c);
  render();
}

async function runCarve() {
  const d = S.modalData;
  closeModal();
  startJob('carve', {
    categories: d.cats || [],
    unallocated_only: !!d.unalloc,
    text_carving: !!d.text,
    validate: !d.novalidate,
    max_files: d.max || 20000
  });
}

/* ---- extract ---- */
function modalExtract() {
  const n = S.selected.size;
  const root = (S.health && S.health.output_root) || '';
  const dest = S.modalData.dest || (root + '/recovered');
  return modalShell('Recover files to disk', `
    <div class="field">
      <label>Destination folder</label>
      <input class="input" value="${esc(dest)}" oninput="S.modalData.dest=this.value">
      <div class="hint">Never write recovered files back onto the disk you are recovering from —
        doing so overwrites the very data you are trying to get back.</div>
    </div>
    <label class="check"><input type="checkbox" ${S.modalData.flat ? '' : 'checked'}
      onchange="S.modalData.flat=!this.checked"> Rebuild the original folder structure</label>
    <label class="check"><input type="checkbox" ${S.modalData.notimes ? '' : 'checked'}
      onchange="S.modalData.notimes=!this.checked"> Restore modification times</label>
    <label class="check"><input type="checkbox" ${S.modalData.nohash ? '' : 'checked'}
      onchange="S.modalData.nohash=!this.checked"> Write a manifest with MD5/SHA-1 hashes</label>
    <div class="banner info" style="margin-top:14px">
      ${n ? `<b>${n}</b> selected file(s) will be recovered.`
          : `All <b>${fmtNum((S.results && S.results.total) || 0)}</b> files in this result set will be recovered.`}
    </div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button>
     <button class="btn go" onclick="runExtract()">Recover</button>`);
}

async function runExtract() {
  const d = S.modalData;
  const dest = (d.dest || ((S.health.output_root || '') + '/recovered')).trim();
  const indices = Array.from(S.selected);
  closeModal();
  log(`recovering ${indices.length || 'all'} file(s) to ${dest}`);
  try {
    const r = await apiPost('/extract', {
      job: S.resultJob, output_dir: dest, indices,
      preserve_paths: !d.flat, preserve_times: !d.notimes,
      write_manifest: !d.nohash, compute_hashes: !d.nohash
    });
    if (!r.ok) { log(r.error, 'err'); alert(r.error); return; }
    S.job = { id: r.job, kind: 'extract', state: 'queued', phase: 'starting', percent: 0 };
    render();
    pollJob(r.job);
  } catch (e) { log('recover failed: ' + e.message, 'err'); }
}

/* ---- imaging ---- */
function modalImage() {
  const root = (S.health && S.health.output_root) || '';
  const src = S.modalData.src || (S.source ? S.source.path : '');
  const out = S.modalData.out || (root + '/images/clone.img');
  return modalShell('Clone a disk to an image', `
    <div class="banner warn">If a drive is failing, image it first and recover from the image.
      Every read from dying media risks making it worse. Unreadable sectors are logged and
      skipped rather than aborting the clone.</div>
    <div class="field"><label>Source device or image</label>
      <input class="input" value="${esc(src)}" oninput="S.modalData.src=this.value"
        placeholder="/dev/sdb"></div>
    <div class="field"><label>Write the image to</label>
      <input class="input" value="${esc(out)}" oninput="S.modalData.out=this.value"></div>
    <div class="field"><label>Retry passes over bad areas</label>
      <input class="input" type="number" value="${S.modalData.retries != null ? S.modalData.retries : 2}"
        oninput="S.modalData.retries=parseInt(this.value)||0"></div>
    <div class="hint">A resumable map file is written alongside the image, so an interrupted
      clone can be continued instead of restarted.</div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button>
     <button class="btn primary" onclick="runImage()">Start clone</button>`);
}

async function runImage() {
  const d = S.modalData;
  const src = (d.src || (S.source ? S.source.path : '')).trim();
  const out = (d.out || '').trim();
  if (!src || !out) return;
  closeModal();
  log(`cloning ${src} → ${out}`);
  try {
    const r = await apiPost('/image', {
      image_path: src, output_path: out,
      retry_passes: d.retries != null ? d.retries : 2
    });
    if (!r.ok) { log(r.error, 'err'); alert(r.error); return; }
    S.job = { id: r.job, kind: 'image', state: 'queued', phase: 'starting', percent: 0 };
    S.screen = S.screen === 'welcome' ? 'source' : S.screen;
    render();
    pollJob(r.job);
  } catch (e) { log('clone failed: ' + e.message, 'err'); }
}

/* ---- RAID ---- */
function modalRaid() {
  const members = S.modalData.members || (S.modalData.members = ['', '']);
  const layout = S.modalData.layout;
  const root = (S.health && S.health.output_root) || '';

  let found = '';
  if (layout) {
    const cls = layout.level === 'unknown' ? 'err' : (layout.ambiguous ? 'warn' : 'info');
    const alts = (layout.alternatives || [])
      .map(a => `<br><span class="faint">also fits: ${esc(a)}</span>`).join('');
    const notes = (layout.notes || [])
      .map(n => `<br><span class="faint">${esc(n)}</span>`).join('');
    found = `<div class="banner ${cls}" style="margin-top:14px">
        <b>${esc(layout.level)}</b> · chunk ${fmtSize(layout.chunk_size)} ·
        ${layout.members} members · ${esc(layout.parity_layout)}<br>
        detected from ${esc(layout.detected_from)}
        (confidence ${Math.round(layout.confidence * 100)}%)
        ${layout.ambiguous ? '<br><b>This is an assumption, not a deduction — verify the result.</b>' : ''}
        ${alts}${notes}
      </div>`;
    if (layout.ambiguous) {
      found += `<div class="field">
        <label>Override the chunk size if you know it</label>
        <input class="input" type="number" value="${layout.chunk_size}"
          oninput="S.modalData.layout.chunk_size=parseInt(this.value)||${layout.chunk_size}">
      </div>`;
    }
    found += `<div class="field"><label>Write the assembled array to</label>
      <input class="input" value="${esc(S.modalData.out || root + '/raid/array.img')}"
        oninput="S.modalData.out=this.value"></div>`;
  }

  return modalShell('Assemble a RAID array', `
    <div class="banner info">Give every member disk or image. If the Linux md superblocks are
      intact the geometry is read from them; otherwise the chunk size, disk order and parity
      layout are worked out by looking for a filesystem in the assembled result and by which
      geometry reconstructs the most intact files.</div>
    ${members.map((m, i) => `<div class="field">
      <label>Member ${i + 1}</label>
      <input class="input" value="${esc(m)}" placeholder="/dev/sdb or /path/member${i}.img"
        oninput="S.modalData.members[${i}]=this.value">
    </div>`).join('')}
    <button class="btn sm" onclick="S.modalData.members.push('');render()">+ Add member</button>
    ${found}`,
    `<button class="btn" onclick="closeModal()">Cancel</button>
     <button class="btn" onclick="detectRaid()">Detect geometry</button>
     <button class="btn primary" ${layout && layout.level !== 'unknown' ? '' : 'disabled'}
       onclick="assembleRaid()">Assemble</button>`);
}

async function detectRaid() {
  const members = (S.modalData.members || []).map(m => m.trim()).filter(Boolean);
  if (members.length < 2) { alert('Give at least two members.'); return; }
  log('detecting RAID geometry…');
  try {
    const r = await apiPost('/raid/detect', { members });
    if (!r.ok) { log(r.error, 'err'); alert(r.error); return; }
    S.modalData.layout = r.layout;
    log(`RAID: ${r.layout.level}, chunk ${fmtSize(r.layout.chunk_size)}, ` +
        `${r.layout.members} members (${r.layout.detected_from})` +
        (r.layout.ambiguous ? ' — AMBIGUOUS, several geometries fit' : ''),
        r.layout.level === 'unknown' ? 'err' : (r.layout.ambiguous ? 'warn' : 'ok'));
  } catch (e) { log('RAID detection failed: ' + e.message, 'err'); }
  render();
}

async function assembleRaid() {
  const l = S.modalData.layout;
  const out = (S.modalData.out || ((S.health.output_root || '') + '/raid/array.img')).trim();
  const members = l.disks.map(d => ({
    path: d.path, data_offset: d.data_offset, size: d.size, present: d.present
  }));
  closeModal();
  log(`assembling ${l.level} array → ${out}`);
  try {
    const r = await apiPost('/raid/assemble', {
      level: l.level, chunk_size: l.chunk_size,
      parity_layout: l.parity_layout, members, output_path: out
    });
    if (!r.ok) { log(r.error, 'err'); alert(r.error); return; }
    S.job = { id: r.job, kind: 'raid', state: 'queued', phase: 'starting', percent: 0 };
    if (S.screen === 'welcome') S.screen = 'source';
    render();
    pollJob(r.job);
  } catch (e) { log('assemble failed: ' + e.message, 'err'); }
}

/* ---- repair ---- */
function modalRepair() {
  const actions = (S.source && S.source.repairs) || [
    'ext_superblock_restore', 'fat_boot_sector_restore', 'ntfs_boot_sector_restore',
    'exfat_boot_region_restore', 'gpt_table_restore', 'partition_table_rebuild'
  ];
  const res = S.modalData.result;
  const writesOn = S.health && S.health.writes_allowed;
  return modalShell('Repair filesystem structures', `
    <div class="banner warn">Repair modifies the device. Clone the disk first — a failed repair
      can make the data harder to recover than it was.
      ${writesOn ? '' : '<br><br><b>Writing is disabled.</b> Restart the engine with <span class="mono">--allow-writes</span> to permit it. You can still run a dry run to see what would be done.'}</div>
    <div class="field">
      <label>Action</label>
      <select class="input" onchange="S.modalData.action=this.value">
        ${actions.map(a => `<option value="${esc(a)}" ${S.modalData.action === a ? 'selected' : ''}>
          ${esc(a.replace(/_/g, ' '))}</option>`).join('')}
      </select>
    </div>
    ${res ? `<div class="banner ${res.ok ? 'info' : 'err'}">
      <b>${esc(res.action)}</b> — ${res.applied ? 'written to disk' : 'dry run'}<br>
      ${esc(res.detail || res.error || '')}
      ${(res.steps || []).map(s => `<br><span class="faint">· ${esc(s)}</span>`).join('')}
    </div>` : ''}`,
    `<button class="btn" onclick="closeModal()">Close</button>
     <button class="btn" onclick="runRepair(false)">Dry run</button>
     <button class="btn warn" ${writesOn ? '' : 'disabled'} onclick="runRepair(true)">Apply</button>`);
}

async function runRepair(apply) {
  const action = S.modalData.action ||
    ((S.source && S.source.repairs && S.source.repairs[0]) || 'auto');
  if (apply && !confirm(`This will write to ${S.source.path}.\n\nProceed?`)) return;
  try {
    const r = await apiPost('/repair', {
      image_path: S.source.path, offset: S.source.offset || 0,
      partition_size: S.source.length || 0, action, apply
    });
    if (!r.ok) { log(r.error, 'err'); alert(r.error); return; }
    S.modalData.result = r.result;
    log(`${r.result.action}: ${r.result.detail || r.result.error}`, r.result.ok ? 'ok' : 'err');
  } catch (e) { log('repair failed: ' + e.message, 'err'); }
  render();
}

/* ---- privilege elevation ---- */
async function loadPrivileges() {
  try { S.privileges = await apiGet('/privileges'); }
  catch (e) { log('could not check privileges: ' + e.message, 'err'); }
  render();
}

function modalElevate() {
  const p = S.privileges;
  const el = S.elevating;

  if (S.health.is_root) {
    return modalShell('Disk access', `
      <div class="banner info">The engine already has full disk access — every physical
        disk can be read.</div>`,
      `<button class="btn" onclick="closeModal()">Close</button>`);
  }

  if (el) {
    const spinner = el.phase === 'failed' ? '✕' : '⟳';
    return modalShell('Unlocking disk access', `
      <div style="text-align:center;padding:26px 10px">
        <div style="font-size:34px;margin-bottom:14px;color:${el.phase === 'failed' ? 'var(--red)' : 'var(--amber)'}">${spinner}</div>
        <div style="font-size:14px;margin-bottom:10px">${esc(el.title || '')}</div>
        <div class="muted" style="line-height:1.7">${esc(el.message || '')}</div>
      </div>`,
      el.phase === 'failed'
        ? `<button class="btn" onclick="S.elevating=null;render()">Back</button>
           <button class="btn" onclick="closeModal()">Close</button>`
        : `<button class="btn" onclick="S.elevating=null;render()">Cancel</button>`);
  }

  if (!p) return modalShell('Unlock disk access', '<div class="muted">Checking…</div>',
                            `<button class="btn" onclick="closeModal()">Close</button>`);

  const blocked = p.inaccessible_disks || 0;
  const why = `<div class="banner warn">
      Reading a physical disk sector by sector requires administrator access, and this
      engine is running as an ordinary user.
      ${blocked ? `<b>${blocked}</b> attached disk${blocked === 1 ? ' is' : 's are'} locked because of it.` : ''}
      <br><br>Everything stays read-only: elevation only grants the ability to <i>read</i>
      raw devices. Repairs still need <span class="mono">--allow-writes</span> as well.
    </div>`;

  if (!p.preferred) {
    return modalShell('Unlock disk access', why + `
      <div class="banner err">${esc(p.note || 'This system offers no way for the program to raise its own privileges.')}</div>
      <div class="field"><label>Run this in a terminal instead</label>
        <input class="input mono" readonly value="sudo ghost_recover" onclick="this.select()"></div>`,
      `<button class="btn" onclick="closeModal()">Close</button>`);
  }

  let options = '';
  if (p.pkexec) {
    options += `<div class="field">
      <button class="btn go" style="width:100%;padding:11px" onclick="elevate('pkexec')">
        Authenticate with the system dialog</button>
      <div class="hint">Recommended. Your desktop's own polkit prompt appears; the password
        never passes through this program.</div>
    </div>`;
  }
  if (p.sudo_nopasswd) {
    options += `<div class="field">
      <button class="btn go" style="width:100%;padding:11px" onclick="elevate('sudo-nopasswd')">
        Restart with administrator access</button>
      <div class="hint">sudo is already authorised for this session, so no password is needed.</div>
    </div>`;
  }
  if (p.sudo && !p.sudo_nopasswd) {
    options += `<div class="field">
      <label>${p.pkexec ? 'Or enter your sudo password' : 'Enter your sudo password'}</label>
      <input class="input" type="password" id="sudopw" autocomplete="off"
        placeholder="your account password"
        onkeydown="if(event.key==='Enter')elevate('sudo-password')">
      <div class="hint">Used once, piped straight to <span class="mono">sudo</span>, and never
        stored or written to the log. Sent only to this engine on localhost.</div>
    </div>`;
  }
  if (p.note) options += `<div class="banner info">${esc(p.note)}</div>`;

  return modalShell('Unlock disk access', why + options,
    `<button class="btn" onclick="closeModal()">Not now</button>
     ${p.sudo && !p.sudo_nopasswd
        ? `<button class="btn warn" onclick="elevate('sudo-password')">Unlock</button>` : ''}`);
}

async function elevate(method) {
  const body = { method };
  if (method === 'sudo-password') {
    const el = $('#sudopw');
    const pw = el ? el.value : '';
    if (!pw) { if (el) el.focus(); return; }
    body.password = pw;
    if (el) el.value = '';
  }
  S.elevating = {
    phase: 'authenticating',
    title: method === 'pkexec' ? 'Waiting for authentication' : 'Restarting with disk access',
    message: method === 'pkexec'
      ? 'Complete the prompt your desktop just opened. If you cannot see it, check behind this window.'
      : 'Starting the privileged engine…'
  };
  render();

  let r;
  try {
    r = await apiPost('/elevate', body);
  } catch (e) {
    // Fetch can be reset by the engine stopping mid-switch, or refused for
    // the few hundred milliseconds where no instance owns the port yet.
    // Losing the request does not mean the elevation failed — the privileged
    // instance may be well on its way — so go straight to the polling path
    // instead of telling the user the unlock broke.
    log('elevation request lost at the network layer (' + e.message + '); polling…', 'warn');
    waitForElevated(method, true);
    return;
  }
  if (!r.ok) {
    if ((r.error || '').indexOf('already in progress') >= 0) {
      log('an elevation is already running — waiting for it', 'warn');
      render();
      waitForElevated(method);
      return;
    }
    S.elevating = { phase: 'failed', title: 'Could not start',
                    message: (r.error || '') + (r.hint ? ' — ' + r.hint : '') };
    log('elevation failed: ' + r.error, 'err');
    render();
    return;
  }
  log('elevation requested via ' + method);
  // The privileged engine will demand the session token; the parent hands it
  // to the browser right here so the session survives the handover.
  if (r.token) sessionStorage.setItem('ghostToken', r.token);
  S.elevating.message = r.message || S.elevating.message;
  render();
  waitForElevated(method);
}

/* The privileged instance takes over this port, so the socket disappears for a
 * moment mid-switch. Both outcomes are detected explicitly rather than waited
 * out: success is the port answering as root, and failure is the engine
 * reporting that the pkexec/sudo child exited without ever claiming the port. */
async function waitForElevated(method) {
  const deadline = Date.now() + 180000;
  let silence = 0;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 600));
    if (!S.elevating) return;                       // the user backed out

    let h = null;
    try { h = await apiGet('/health'); } catch (e) { /* the handover moment */ }
    if (h) silence = 0; else silence++;

    if (h && h.is_root) {
      S.health = h;
      S.privileges = null;
      S.elevating = null;
      S.modal = null;
      log('disk access unlocked — the engine is now running with full privileges', 'ok');
      await loadDisks();
      if (S.screen === 'welcome') S.screen = 'source';
      render();
      return;
    }

    if (h) {
      let st = null;
      try { st = await apiGet('/elevate/status'); } catch (e) { /* ignore */ }
      if (st && st.failed) {
        S.elevating = {
          phase: 'failed',
          title: method === 'pkexec' ? 'Authentication was not completed'
                                     : 'Could not get administrator access',
          message: st.detail || 'The privileged engine did not start.'
        };
        log('elevation failed: ' + (st.detail || 'unknown reason'), 'err');
        render();
        return;
      }
    }

    if (S.elevating && S.elevating.phase !== 'failed') {
      S.elevating.message = method === 'pkexec'
        ? (silence > 20
             ? 'Waiting for the engine to come back after the switch…'
             : 'Waiting for the authentication dialog…')
        : 'Waiting for the privileged engine to take over…';
      render();
    }
  }
  S.elevating = { phase: 'failed', title: 'Timed out',
                  message: 'The authentication was not completed. Try again, or quit and run: ' +
                           'sudo ghost_recover' };
  render();
}

/* ---- about ---- */
async function loadAbout() {
  try {
    if (!S.carvers) S.carvers = await apiGet('/carvers');
    if (!S.filesystems) S.filesystems = await apiGet('/filesystems');
  } catch (e) { /* shown as loading */ }
  render();
}

function modalAbout() {
  const fs = (S.filesystems && S.filesystems.filesystems) || [];
  const cv = (S.carvers && S.carvers.carvers) || [];
  const supported = fs.filter(f => f.supported);
  const byCat = {};
  cv.forEach(c => { byCat[c.category] = (byCat[c.category] || 0) + 1; });
  return modalShell('Capabilities', `
    <h2 style="font-size:13px;margin:0 0 8px">Filesystems with metadata drivers (${supported.length})</h2>
    <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:16px">
      ${supported.map(f => `<span class="tag">${esc(f.name)}</span>`).join('')}
    </div>
    <h2 style="font-size:13px;margin:0 0 8px">Carver signatures (${cv.length})</h2>
    <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:16px">
      ${Object.entries(byCat).sort((a, b) => b[1] - a[1])
        .map(([k, v]) => `<span class="tag">${esc(k)} · ${v}</span>`).join('')}
    </div>
    <div class="hint">
      ${cv.filter(c => c.validated).length} of those signatures also verify the file's internal
      structure and compute its true length, rather than guessing.
    </div>`,
    `<button class="btn" onclick="closeModal()">Close</button>`, 720);
}

function modalFileInfo() {
  const r = S.modalData.info;
  if (!r) return modalShell('Details', 'Loading…', '');
  const f = r.file, d = r.detail;
  const ex = (d.extents || []).map(e =>
    `<tr><td class="mono">${fmtNum(e.offset)}</td><td class="mono right">${fmtSize(e.length)}</td>
     <td>${e.sparse ? '<span class="pill mute">sparse</span>' : ''}</td></tr>`).join('');
  return modalShell(f.name, `
    ${kv('Path', f.path)}${kv('Logical size', fmtSize(f.size))}
    ${kv('Allocated', fmtSize(d.alloc_size))}${kv('Recoverable', fmtSize(f.recoverable))}
    ${kv('Owner', d.uid + ':' + d.gid)}${kv('Mode', '0' + (d.mode || 0).toString(8))}
    ${kv('Links', d.nlink)}${kv('Recovered by', (f.method || '').replace(/_/g, ' '))}
    ${kv('Created', d.crtime_iso || '—')}${kv('Modified', f.mtime_iso || '—')}
    ${kv('Accessed', d.atime_iso || '—')}${kv('Deleted', d.dtime_iso || '—')}
    ${d.codec ? kv('Encoding', d.codec) : ''}
    <h2 style="font-size:12px;margin:14px 0 6px">Data location (${fmtNum(d.extent_count)} extent(s))</h2>
    <table class="grid"><thead><tr><th class="static">Device offset</th>
      <th class="static right">Length</th><th class="static"></th></tr></thead>
      <tbody>${ex || '<tr><td colspan="3" class="faint">resident / no extents</td></tr>'}</tbody></table>`,
    `<button class="btn" onclick="closeModal()">Close</button>`, 640);
}

/* ------------------------------------------------------------------ init */
window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && S.modal) closeModal();
});

// Expose the handlers referenced from inline attributes.
Object.assign(window, {
  S, go, render, loadDisks, pickDisk, mountSelected, openSource, loadPartitions,
  usePartition, useRegion, useWholeDisk, startJob, cancelJob, loadResults, setSort,
  selectFile, toggleSel, selectAllShown, setPreview, downloadFile, showFileInfo,
  openModal, closeModal, browseTo, pickFile, browsePick, attachConfirm, toggleCat, runCarve,
  runExtract, runImage, detectRaid, assembleRaid, runRepair, toggleLog, shutdownEngine,
  backToVolumes,
  loadPrivileges, elevate
});

boot();
