/**
 * The operator dashboard, served as one self-contained page.
 *
 * Deliberately a static shell containing no data: it asks for the admin token,
 * keeps it in localStorage, and fetches /admin/stats and /admin/users itself. So
 * the page being reachable leaks nothing — the data endpoints stay token-gated.
 */

export const ADMIN_PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>diabeto · admin</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #fbfbfa; --panel: #fff; --line: #e6e4e0; --ink: #1a1917;
    --muted: #6b6862; --accent: #2f6f4e; --warn: #9a3412; --radius: 10px;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #14141a; --panel: #1c1c24; --line: #2c2c36; --ink: #ecebe8; --muted: #96938c; --accent: #6ee7a8; --warn: #fca5a5; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.5 ui-sans-serif, -apple-system, system-ui, sans-serif; }
  main { max-width: 1080px; margin: 0 auto; padding: 32px 20px 64px; }
  h1 { font-size: 20px; margin: 0 0 4px; letter-spacing: -0.01em; }
  .sub { color: var(--muted); font-size: 13px; margin-bottom: 28px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 28px; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); padding: 16px; }
  .card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
  .card .value { font-size: 26px; font-variant-numeric: tabular-nums; margin-top: 6px; letter-spacing: -0.02em; }
  .wrap { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; font-size: 14px; }
  th, td { text-align: left; padding: 11px 14px; border-bottom: 1px solid var(--line); white-space: nowrap; }
  th { color: var(--muted); font-weight: 500; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
  tr:last-child td { border-bottom: 0; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  .pill { display: inline-block; padding: 2px 9px; border-radius: 99px; font-size: 12px; border: 1px solid var(--line); }
  .pill.on { color: var(--accent); border-color: color-mix(in oklab, var(--accent) 45%, transparent); }
  .pill.off { color: var(--muted); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: var(--muted); }
  .empty { padding: 40px 16px; text-align: center; color: var(--muted); }
  form { display: flex; gap: 8px; flex-wrap: wrap; }
  input, button { font: inherit; padding: 9px 13px; border-radius: 8px; border: 1px solid var(--line); background: var(--panel); color: var(--ink); }
  input { flex: 1 1 320px; }
  button { cursor: pointer; background: var(--ink); color: var(--bg); border-color: var(--ink); }
  .err { color: var(--warn); margin-top: 12px; font-size: 14px; }
  .foot { margin-top: 22px; color: var(--muted); font-size: 12px; display: flex; gap: 14px; flex-wrap: wrap; }
  .foot a { color: inherit; }
</style>
</head>
<body>
<main>
  <h1>diabeto</h1>
  <div class="sub" id="sub">admin</div>
  <div id="view"></div>
</main>
<script>
const KEY = 'diabeto-admin-token';
const view = document.getElementById('view');
const money = n => '$' + Number(n || 0).toFixed(n >= 1 ? 2 : 4);
const num = n => Number(n || 0).toLocaleString();
const date = ms => ms ? new Date(ms).toISOString().slice(0, 10) : '—';
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

function askForToken(message) {
  view.innerHTML =
    '<form id="f"><input id="t" type="password" placeholder="Admin token" autocomplete="off"><button>Open</button></form>' +
    (message ? '<div class="err">' + esc(message) + '</div>' : '');
  document.getElementById('f').onsubmit = e => {
    e.preventDefault();
    localStorage.setItem(KEY, document.getElementById('t').value.trim());
    load();
  };
}

async function api(path, token) {
  const res = await fetch(path, { headers: { authorization: 'Bearer ' + token } });
  if (!res.ok) throw new Error(res.status === 404 ? 'That token was not accepted.' : 'Request failed (' + res.status + ')');
  return res.json();
}

function row(u) {
  const s = u.subscription;
  const pill = s && s.active
    ? '<span class="pill on">active</span>'
    : s ? '<span class="pill off">lapsed</span>' : '<span class="pill off">free</span>';
  return '<tr>' +
    '<td><div>' + esc(u.email || 'no email') + '</div><div class="mono">' + esc(u.id) + '</div></td>' +
    '<td>' + pill + '</td>' +
    '<td class="num">' + num(u.devices) + '</td>' +
    '<td class="num">' + num(u.month.requests) + '</td>' +
    '<td class="num">' + money(u.month.usd) + '</td>' +
    '<td>' + date(u.createdAt) + '</td>' +
    '<td>' + date(u.lastSeenAt) + '</td>' +
  '</tr>';
}

async function load() {
  const token = localStorage.getItem(KEY);
  if (!token) return askForToken();
  view.innerHTML = '<div class="empty">Loading…</div>';

  let stats, users;
  try {
    [stats, users] = await Promise.all([api('/admin/stats', token), api('/admin/users?limit=200', token)]);
  } catch (err) {
    localStorage.removeItem(KEY);
    return askForToken(err.message);
  }

  const active = users.users.filter(u => u.subscription && u.subscription.active).length;
  document.getElementById('sub').textContent = stats.period + ' · ' + stats.model;

  view.innerHTML =
    '<div class="cards">' +
      '<div class="card"><div class="label">Users</div><div class="value">' + num(stats.users) + '</div></div>' +
      '<div class="card"><div class="label">Subscribed</div><div class="value">' + num(active) + '</div></div>' +
      '<div class="card"><div class="label">Analyses</div><div class="value">' + num(stats.month.requests) + '</div></div>' +
      '<div class="card"><div class="label">Spend</div><div class="value">' + money(stats.month.usd) + '</div></div>' +
      '<div class="card"><div class="label">Today</div><div class="value">' + money(stats.today.usd) + '</div></div>' +
    '</div>' +
    (users.users.length
      ? '<div class="wrap"><table><thead><tr><th>User</th><th>Plan</th><th class="num">Devices</th>' +
        '<th class="num">Analyses</th><th class="num">Cost</th><th>Joined</th><th>Last seen</th></tr></thead><tbody>' +
        users.users.map(row).join('') + '</tbody></table></div>'
      : '<div class="wrap"><div class="empty">No users yet.<br>Sign in with Apple needs a paid Apple Developer Program membership before anyone can register.</div></div>') +
    '<div class="foot"><span>Refreshes on load.</span>' +
      '<a href="#" id="out">Forget token</a>' +
      '<a href="/health" target="_blank">Health</a></div>';

  document.getElementById('out').onclick = e => { e.preventDefault(); localStorage.removeItem(KEY); askForToken(); };
}

load();
</script>
</body>
</html>`;
