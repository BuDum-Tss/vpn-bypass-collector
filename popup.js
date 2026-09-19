const $ = (id) => document.getElementById(id);
let STATE = null;
let VIEW = null; // какой список открыт во вкладке: "vpn" или "direct"

const LIST_TEXT = {
  vpn: "Сайты отсюда должны открываться через VPN.",
  direct: "Сайты отсюда должны открываться без VPN. Российские сети агент пускает напрямую и сам."
};

const KIND_RU = {
  timeout: "таймаут", reset: "соединение сброшено", refused: "отказ в соединении", tls: "ошибка сертификата",
  dns: "не резолвится", error: "ошибка", stub: "заглушка «отключите VPN»", challenge: "проверка браузера",
  legal: "блокировка (451)", "vpn-down": "VPN выключен", "no-path": "нет пути", "route-failed": "нет прав на маршрут"
};

function send(msg) {
  return new Promise((res) => chrome.runtime.sendMessage(msg, res));
}

function toast(text, ms = 3200) {
  const t = $("toast");
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.hidden = true), ms);
}

function fmtAgo(ts) {
  if (!ts) return "—";
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 5) return "только что";
  if (s < 60) return s + " с назад";
  if (s < 3600) return Math.floor(s / 60) + " мин назад";
  if (s < 86400) return Math.floor(s / 3600) + " ч назад";
  return Math.floor(s / 86400) + " дн назад";
}

const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
const isIpLike = (s) => /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(s);
const curEntries = () => Object.values(STATE.lists[VIEW].entries);
const computed = () => (STATE.lists_computed && STATE.lists_computed[VIEW]) || [];
const listName = (k) => (k === "vpn" ? "«Через VPN»" : "«Мимо VPN»");

function btn(cls, text, title, onclick) {
  const b = document.createElement("button");
  b.className = cls;
  b.textContent = text;
  if (title) b.title = title;
  b.onclick = onclick;
  return b;
}

async function act(msg, okToast) {
  const r = await send(msg);
  if (r && r.ok === false && r.error) toast(r.error);
  else if (okToast) toast(okToast);
  await load();
  return r;
}

// ---------- как показать результат проверки ----------
function pathText(p) {
  if (!p) return "—";
  if (p.skipped) return KIND_RU[p.kind] || "не проверялось";
  if (!p.ok) return KIND_RU[p.kind] || p.kind || "не открывается";
  if (p.kind === "challenge") return "проверка браузера";
  const speed = p.kbps == null ? "" : " · " + (p.kbps >= 1000 ? (p.kbps / 1000).toFixed(1) + " Мбит/с" : p.kbps + " кбит/с");
  return "открывается" + (p.ttfb != null ? " · " + p.ttfb + " мс" : "") + speed;
}
function verdictLine(v) {
  if (!v) return "";
  if (!v.d && !v.v) return (v.why || "") + (v.at ? " · " + fmtAgo(v.at) : "");
  return `напрямую: ${pathText(v.d)} · через VPN: ${pathText(v.v)} · ${fmtAgo(v.at)}`;
}

// ---------- отрисовка ----------
function render() {
  const S = STATE.settings;
  if (!VIEW) VIEW = "vpn";

  $("enabled").checked = S.enabled;
  $("autoCheck").checked = S.autoCheck;
  $("groupByBaseDomain").checked = S.groupByBaseDomain;
  $("defaultPath").value = S.defaultPath;

  renderVpn();
  renderApply();
  renderQueueLine();
  renderTabs();
  renderList();
  renderChecks();
  renderIgnore();

  requestIps([
    ...curEntries().map((e) => e.key),
    ...Object.keys(STATE.queue),
    ...Object.keys(STATE.unreachable)
  ]);
}

function renderTabs() {
  const nv = Object.keys(STATE.lists.vpn.entries).length;
  const nd = Object.keys(STATE.lists.direct.entries).length;
  $("cntVpn").textContent = nv ? nv : "";
  $("cntDirect").textContent = nd ? nd : "";
  $("tabVpn").classList.toggle("active", VIEW === "vpn");
  $("tabDirect").classList.toggle("active", VIEW === "direct");
  const other = STATE.settings.defaultPath === "vpn" ? "Остальные сайты идут через VPN." : "Остальные сайты идут напрямую.";
  $("modeHint").textContent = LIST_TEXT[VIEW] + " " + other;
}

function renderVpn() {
  const a = STATE.agent || {};
  const v = a.status;
  const dot = $("vpnDot");
  const st = $("vpnState");
  const geo = $("vpnGeo");
  const ip = $("vpnIp");
  const btnEl = $("vpnBtn");

  if (!v) {
    dot.className = "dot gray";
    st.textContent = a.failStreak ? "агент не отвечает" : "проверяю агента…";
    geo.textContent = "";
    ip.textContent = "запусти задачу «VPN Bypass Agent»";
    btnEl.hidden = true;
    return;
  }
  if (!a.reachable) {
    // Связи нет уже несколько проверок подряд — показываем последние известные данные, но честно помечаем.
    dot.className = "dot gray";
    st.textContent = "агент не отвечает";
    geo.textContent = "";
    ip.textContent = `последние данные ${fmtAgo(a.lastOkAt)}: VPN ${v.vpnUp ? "был включён" : "был выключен"}`;
    btnEl.hidden = true;
    return;
  }
  dot.className = "dot " + (v.vpnUp ? "green" : "red");
  st.textContent = v.vpnUp ? "VPN включён" : "VPN выключен";
  const g = v.geo || {};
  geo.textContent = [g.flag, g.country, g.city].filter(Boolean).join(" ");
  ip.textContent = [g.ip, g.isp].filter(Boolean).join(" · ") + (a.failStreak ? " · обновляю…" : "");

  if (v.vpnControl) {
    btnEl.hidden = false;
    btnEl.textContent = v.vpnUp ? "Отключить" : "Подключить";
    btnEl.className = "vpn-btn " + (v.vpnUp ? "off" : "on");
    btnEl.disabled = false;
  } else {
    btnEl.hidden = true;
  }
}

// Строка «что сейчас с применением списков» — вместо загадочного «агент не отвечает».
function renderApply() {
  const el = $("applyLine");
  const a = STATE.agent || {};
  const v = a.status;
  let cls = "";
  let text = "";
  if (!v) {
    el.textContent = "";
    el.className = "apply-line";
    return;
  }
  const ap = v.apply || {};
  const def = ap.default || (ap.mode === "whitelist" ? "direct" : "vpn"); // прежний агент присылает mode
  if (!a.reachable) {
    cls = "warn";
    text = "Списки не применяются: нет связи с агентом";
  } else if (ap.busy) {
    text = "⏳ Агент применяет списки…";
  } else if (v.sig !== STATE.sig) {
    cls = "warn";
    text = "⏳ Есть изменения — отправляю агенту…";
  } else if (ap.ok === false) {
    cls = "err";
    text = `⚠ Не применено: ${ap.error || "ошибка"}`;
  } else if (!v.vpnUp) {
    text = `✓ Списки у агента (мимо VPN: ${ap.entriesDirect ?? "?"}, через VPN: ${ap.entriesVpn ?? "?"}). VPN выключен — маршруты не нужны`;
  } else if (def === "vpn") {
    const ru = ap.regionTargets ? ` (в т.ч. ${ap.regionTargets} российских сетей)` : "";
    text = `✓ Применено: мимо VPN ${ap.routes ?? 0} маршрутов${ru}, остальное через VPN · ${fmtAgo(ap.at)}`;
  } else {
    text = `✓ Применено: через VPN ${ap.routes ?? 0} маршрутов, остальное напрямую · ${fmtAgo(ap.at)}`;
  }
  const s = a.sync;
  if (s && s.ok === false && s.error && a.reachable && !cls) {
    cls = "err";
    text = "⚠ Последняя отправка не удалась: " + s.error;
  }
  el.className = "apply-line " + cls;
  el.textContent = text;
}

function renderQueueLine() {
  const el = $("queueLine");
  const q = Object.values(STATE.queue);
  const a = STATE.agent || {};
  const vpnOn = a.reachable && a.status && a.status.vpnUp;
  if (!q.length) {
    el.textContent = "";
    el.className = "apply-line";
    return;
  }
  const now = q.find((x) => x.checking);
  el.className = "apply-line" + (vpnOn ? "" : " warn");
  el.textContent = vpnOn
    ? `🔎 На проверке: ${q.length}${now ? " · сейчас " + now.key : ""}`
    : `🔎 В очереди на проверку: ${q.length} — ждут включения VPN и агента`;
}

// ---------- IP-адреса записей (резолвит агент) ----------
const IPS = {}; // имя -> { ips, ts }
let resolving = false;

function requestIps(names) {
  const need = [...new Set(names)].filter((n) => !isIpLike(n) && !(IPS[n] && Date.now() - IPS[n].ts < 5 * 60 * 1000));
  if (!need.length || resolving) return;
  resolving = true;
  send({ type: "resolveIps", names: need.slice(0, 150) })
    .then((r) => {
      if (r && r.ips) {
        for (const n of need) if (n in r.ips) IPS[n] = { ips: r.ips[n] || [], ts: Date.now() };
        render();
      }
    })
    .finally(() => (resolving = false));
}

// Строка с адресами под записью: IP домена и, для заглушек, вычисленные диапазоны.
function addressLine(key, ranges) {
  const parts = [];
  if ((ranges || []).length) parts.push("диапазоны: " + ranges.join("  "));
  if (!isIpLike(key)) {
    const e = IPS[key];
    if (e && e.ips.length) parts.push("IP: " + e.ips.slice(0, 4).join(", ") + (e.ips.length > 4 ? " +" + (e.ips.length - 4) : ""));
    else if (e) parts.push("IP: не резолвится");
  }
  if (!parts.length) return null;
  const d = document.createElement("div");
  d.className = "ips";
  d.textContent = parts.join("\n");
  if (IPS[key] && IPS[key].ips.length > 4) d.title = IPS[key].ips.join(", ");
  return d;
}

const badge = (text, cls, title) => {
  const b = document.createElement("span");
  b.className = "badge" + (cls ? " " + cls : "");
  b.textContent = text;
  if (title) b.title = title;
  return b;
};

// ---------- «В списке» ----------
function entryRow(e) {
  const kind = VIEW;
  const ch = kind === "direct" ? STATE.challenges[e.key] : null;
  const li = document.createElement("li");
  li.className = "entry" + (e.both ? " resolved" : "");
  const name = document.createElement("span");
  name.className = "domain";
  name.textContent = e.key;
  const tags = document.createElement("span");
  tags.className = "tags";
  tags.append(badge(e.source === "manual" ? "вручную" : e.source === "stub" ? "заглушка" : "авто"));
  if (e.both) tags.append(badge("работает везде", "soft", "Открывается и так, и так — маршрут не нужен, сайт идёт по умолчанию"));
  if (e.stub || ch) tags.append(badge("🚫 блокирует VPN", "block", "Сайт открывается, но не пускает через VPN — обход идёт по IP-диапазонам его сети"));
  const x = btn("iconbtn", "×", "Убрать из списка", () => act({ type: "removeEntry", list: kind, key: e.key }));
  li.append(name, tags, x);

  const line = verdictLine(e.verdict);
  if (line) {
    const meta = document.createElement("span");
    meta.className = "meta";
    meta.textContent = line;
    li.append(meta);
  }
  const ips = addressLine(e.key, ch && ch.ranges);
  if (ips) li.append(ips);

  const actions = document.createElement("div");
  actions.className = "ch-actions";
  actions.append(
    btn("mini", kind === "vpn" ? "→ мимо VPN" : "→ через VPN", "Перенести в другой список", () =>
      act({ type: "moveEntry", key: e.key, to: kind === "vpn" ? "direct" : "vpn" })
    )
  );
  if (!isIpLike(e.key)) {
    actions.append(
      btn("mini", "проверить", "Заново проверить напрямую и через VPN", async () => {
        await send({ type: "recheck", key: e.key });
        toast("Поставлено на проверку");
        await load();
      })
    );
  }
  if (ch) actions.append(btn("mini", "пересчитать диапазоны", "", () => act({ type: "rederiveChallenge", host: e.key }, "Пересчитываю диапазоны…")));
  li.append(actions);
  return li;
}

function renderList() {
  const ul = $("entries");
  ul.innerHTML = "";
  const all = curEntries();
  const defaults = all.filter((e) => e.default);
  const own = all
    .filter((e) => !e.default)
    .sort((a, b) => (a.both ? 1 : 0) - (b.both ? 1 : 0) || (b.addedAt || 0) - (a.addedAt || 0));
  const total = all.length;
  $("entriesCount").textContent = total ? `(${total})` : "";
  $("entriesEmpty").hidden = total > 0;

  for (const e of own) ul.append(entryRow(e));

  if (defaults.length) {
    const li = document.createElement("li");
    li.className = "entry";
    const name = document.createElement("span");
    name.className = "domain";
    name.textContent = "Стартовый набор";
    const tag = badge(defaults.length + " записей");
    tag.title = defaults.slice(0, 40).map((e) => e.key).join("\n") + (defaults.length > 40 ? "\n…" : "");
    const x = btn("iconbtn", "×", "Убрать весь стартовый набор", () => {
      if (confirm("Убрать весь стартовый набор (" + defaults.length + " записей: Claude, Google, YouTube, Facebook, Instagram и др.)?"))
        act({ type: "removeEntries", list: VIEW, keys: defaults.map((e) => e.key) });
    });
    li.append(name, tag, x);
    const d = document.createElement("div");
    d.className = "ips";
    d.textContent = "Claude, Google, YouTube, Facebook, Instagram, ИИ-сервисы, X, Discord, LinkedIn, мессенджеры и др., плюс IP-диапазоны Google, Meta и Telegram целиком";
    li.append(d);
    ul.append(li);
  }
}

// ---------- «Проверки»: очередь и «не открывается нигде» ----------
const REASON_RU = {
  new: "новый сайт", conflict: "был сразу в обоих списках — выясняю, где открывается",
  "failed-listed": "сайт из списка перестал открываться", manual: "по вашей просьбе"
};

function renderChecks() {
  const q = Object.values(STATE.queue).sort((a, b) => (a.addedAt || 0) - (b.addedAt || 0));
  const un = Object.values(STATE.unreachable).sort((a, b) => (b.at || 0) - (a.at || 0));
  $("checksCount").textContent = q.length + un.length ? `(${q.length + un.length})` : "";
  $("checksEmpty").hidden = q.length + un.length > 0;
  const a = STATE.agent || {};
  const vpnOn = a.reachable && a.status && a.status.vpnUp;

  const uq = $("queue");
  uq.innerHTML = "";
  for (const it of q) {
    const li = document.createElement("li");
    li.className = "entry";
    const name = document.createElement("span");
    name.className = "domain";
    name.textContent = it.key;
    const st = it.checking ? "проверяется…" : it.error ? "ошибка: " + it.error : !vpnOn ? "ждёт VPN и агента" : "в очереди";
    const x = btn("iconbtn", "×", "Не проверять этот сайт", () => act({ type: "dismissUnreachable", key: it.key }));
    li.append(name, badge(st, it.checking ? "" : "soft"), x);
    const meta = document.createElement("span");
    meta.className = "meta";
    meta.textContent = REASON_RU[it.reason] || it.reason || "";
    li.append(meta);
    uq.append(li);
  }

  const uu = $("unreach");
  uu.innerHTML = "";
  for (const it of un) {
    const li = document.createElement("li");
    li.className = "entry";
    const name = document.createElement("span");
    name.className = "domain";
    name.textContent = it.key;
    li.append(name, badge("не открывается нигде", "block"), document.createElement("span"));
    const meta = document.createElement("span");
    meta.className = "meta";
    meta.textContent = `напрямую: ${pathText(it.d)} · через VPN: ${pathText(it.v)} · ${fmtAgo(it.at)} · попыток: ${it.tries || 1}`;
    li.append(meta);
    const ips = addressLine(it.key);
    if (ips) li.append(ips);
    const actions = document.createElement("div");
    actions.className = "ch-actions";
    actions.append(
      btn("mini", "→ через VPN", "Всё равно добавить в этот список", () => act({ type: "moveEntry", key: it.key, to: "vpn" })),
      btn("mini", "→ мимо VPN", "Всё равно добавить в этот список", () => act({ type: "moveEntry", key: it.key, to: "direct" })),
      btn("mini", "проверить", "", async () => {
        await send({ type: "recheck", key: it.key });
        toast("Поставлено на проверку");
        await load();
      }),
      btn("mini", "не проверять", "", () => act({ type: "dismissUnreachable", key: it.key }))
    );
    li.append(actions);
    uu.append(li);
  }
}

function renderIgnore() {
  const ul = $("ignoreList");
  ul.innerHTML = "";
  const list = STATE.ignore || [];
  $("exceptCount").textContent = list.length ? `(${list.length})` : "";
  for (const d of list.slice().sort()) {
    const li = document.createElement("li");
    li.className = "ignore-item";
    const name = document.createElement("span");
    name.textContent = d;
    const x = btn("iconbtn", "×", "Снова проверять", () => act({ type: "removeIgnore", domain: d }));
    li.append(name, x);
    ul.append(li);
  }
}

async function load() {
  STATE = await send({ type: "getState" });
  render();
}

// ---------- события ----------
const setting = (id, key) =>
  ($(id).onchange = async (e) => {
    await send({ type: "setSettings", settings: { [key]: e.target.checked } });
    await load();
  });
setting("enabled", "enabled");
setting("autoCheck", "autoCheck");
setting("groupByBaseDomain", "groupByBaseDomain");
$("defaultPath").onchange = async (e) => {
  await send({ type: "setSettings", settings: { defaultPath: e.target.value } });
  toast(e.target.value === "vpn" ? "Остальные сайты — через VPN" : "Остальные сайты — напрямую (менее надёжно)");
  await load();
};

for (const tab of [$("tabVpn"), $("tabDirect")]) {
  tab.onclick = () => {
    VIEW = tab.dataset.list;
    render();
  };
}

async function addEntryFromInput() {
  const v = $("entryInput").value;
  if (!v.trim()) return;
  const r = await act({ type: "addEntry", list: VIEW, value: v });
  if (r && r.ok) $("entryInput").value = "";
}
$("entryAddBtn").onclick = addEntryFromInput;
$("entryInput").onkeydown = (e) => {
  if (e.key === "Enter") addEntryFromInput();
};

async function addIgnoreFromInput() {
  const v = $("ignoreInput").value;
  if (!v.trim()) return;
  const r = await act({ type: "addIgnore", domain: v });
  if (r && r.ok) $("ignoreInput").value = "";
}
$("ignoreAddBtn").onclick = addIgnoreFromInput;
$("ignoreInput").onkeydown = (e) => {
  if (e.key === "Enter") addIgnoreFromInput();
};

$("vpnBtn").onclick = async () => {
  const v = (STATE.agent && STATE.agent.status) || {};
  const action = v.vpnUp ? "disconnect" : "connect";
  $("vpnBtn").disabled = true;
  $("vpnBtn").textContent = action === "disconnect" ? "отключаю…" : "подключаю…";
  const r = await send({ type: "vpnControl", action });
  if (!r || !r.ok) toast("Не вышло: " + ((r && r.error) || "нет ответа"));
  setTimeout(load, 3500);
};

$("settingsBtn").onclick = () => {
  $("settings").hidden = !$("settings").hidden;
};

// «+ текущий сайт»: проверить в обоих путях и положить в нужный список.
$("addCurrent").onclick = async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let host = "";
  try {
    if (/^https?:/.test(tab.url)) host = new URL(tab.url).hostname;
  } catch (_) {}
  if (!host) return toast("Нет подходящего URL во вкладке");
  const b = $("addCurrent");
  b.disabled = true;
  toast("Проверяю напрямую и через VPN…", 20000);
  const r = await send({ type: "addCurrentSite", host });
  b.disabled = false;
  await load();
  if (!r || !r.ok) return toast((r && r.error) || "Не вышло");
  const k = r.key;
  const moved = r.moved ? ` (перенесён из ${listName(r.moved)})` : "";
  if (r.result === "vpn") { VIEW = "vpn"; toast(`${k} → «Через VPN»: ${r.why}${moved}`); }
  else if (r.result === "direct") { VIEW = "direct"; toast(`${k} → «Мимо VPN»: ${r.why}${r.stub ? ". Определяю IP-диапазоны…" : ""}${moved}`); }
  else if (r.result === "both") { VIEW = "vpn"; toast(`${k} работает и так, и так — в «Через VPN», маршрут не нужен${moved}`); }
  else if (r.result === "none") toast(`${k} не открывается ни напрямую, ни через VPN — см. «Проверки»`);
  else if (r.result === "unknown") toast(`${k}: ${r.why}. Проверю позже`);
  else toast(`Не удалось проверить: ${r.error || "агент не ответил"}`);
  render();
  setTimeout(load, 3000); // подтянуть определённые диапазоны
};

// Принудительно: отправить списки и дождаться, пока агент их применит.
$("forceBtn").onclick = async () => {
  const b = $("forceBtn");
  b.disabled = true;
  const old = b.textContent;
  b.textContent = "Применяю…";
  const r = await send({ type: "forceSync" });
  b.disabled = false;
  b.textContent = old;
  if (!r || !r.ok) {
    toast("Не применено: " + ((r && r.error) || "нет ответа от агента"));
  } else {
    const s = r.summary || {};
    toast(
      s.vpnUp === false
        ? "Списки отправлены. VPN выключен — маршруты появятся при подключении"
        : `Применено: ${s.routes ?? 0} маршрутов (+${s.added ?? 0} −${s.removed ?? 0}), ${((s.ms ?? 0) / 1000).toFixed(1)} с`
    );
  }
  await load();
};

// ---- сворачиваемые блоки: запоминаем, какие свёрнуты ----
for (const id of ["entriesDetails", "checksDetails", "exceptDetails"]) {
  const el = $(id);
  try {
    const saved = localStorage.getItem("fold." + id);
    if (saved !== null) el.open = saved === "1";
  } catch (_) {}
  el.addEventListener("toggle", () => {
    try {
      localStorage.setItem("fold." + id, el.open ? "1" : "0");
    } catch (_) {}
  });
}

// ---- резервная копия состояния ----
const FULL_TAB = location.search.includes("full=1");
if (FULL_TAB) {
  document.body.classList.add("full");
  $("settings").hidden = false;
}
$("exportBtn").onclick = async () => {
  const r = await send({ type: "exportState" });
  if (!r || !r.ok) return toast("Не удалось получить состояние");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(r.state, null, 2)], { type: "application/json" }));
  a.download = "vpn-bypass-state.json";
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  toast("Состояние сохранено в Загрузки");
};
$("importBtn").onclick = () => {
  // Окно выбора файла закрывает popup расширения — поэтому выбор делаем в отдельной вкладке.
  if (FULL_TAB) $("importFile").click();
  else chrome.tabs.create({ url: chrome.runtime.getURL("popup.html?full=1") });
};
$("importFile").onchange = async (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  let obj;
  try {
    obj = JSON.parse((await file.text()).replace(/^﻿/, ""));
  } catch (_) {
    return toast("Файл не читается как JSON");
  }
  if (!confirm("Заменить текущие данные расширения данными из файла «" + file.name + "»?")) return;
  const r = await send({ type: "importState", state: obj });
  if (!r || !r.ok) return toast((r && r.error) || "Не удалось загрузить");
  VIEW = null;
  await load();
  toast(`Загружено: ${r.count} записей, на проверке: ${r.queued}. Отправляю агенту…`);
};

$("downloadBtn").onclick = async () => {
  const r = await send({ type: "downloadList", list: VIEW });
  toast(r && r.count ? `Файл сохранён: ${r.count} записей` : "Список пуст");
};

$("clearBtn").onclick = async () => {
  if (!confirm("Очистить очередь проверки и список «не открывается нигде»? (списки «Через VPN» и «Мимо VPN» не тронем)")) return;
  await act({ type: "clearChecks" });
};

chrome.storage.onChanged.addListener((changes) => {
  if (changes.state || changes.agent) load();
});

load();
send({ type: "vpnStatus" }).then(load);
setInterval(() => send({ type: "vpnStatus" }), 4000);
