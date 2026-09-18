const $ = (id) => document.getElementById(id);
let STATE = null;
let VIEW = null; // какой список сейчас открыт во вкладке (не обязательно активный)

const LIST_TEXT = {
  blacklist: {
    hint: "Чёрный список: сайты отсюда идут МИМО VPN, всё остальное — через VPN.",
    autoAdd: "Автодобавлять сайты, которые не открываются при включённом VPN",
    exceptNote: "Сайты отсюда не попадут в чёрный список автоматически (только при включённом автодобавлении; вручную добавить можно всегда).",
    candEmpty: "Пока ничего не поймано. Полазайте по сайтам с включённым VPN."
  },
  whitelist: {
    hint: "Белый список: через VPN идут ТОЛЬКО сайты отсюда, всё остальное — напрямую.",
    autoAdd: "Автодобавлять сайты, которые не открываются напрямую",
    exceptNote: "Сайты отсюда не попадут в белый список автоматически (только при включённом автодобавлении; вручную добавить можно всегда).",
    candEmpty: "Пока ничего не поймано. Полазайте по сайтам, которые не открываются без VPN."
  }
};

function send(msg) {
  return new Promise((res) => chrome.runtime.sendMessage(msg, res));
}

function toast(text) {
  const t = $("toast");
  t.textContent = text;
  t.hidden = false;
  setTimeout(() => (t.hidden = true), 2600);
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

const curList = () => STATE.lists[VIEW];
const computed = () => (STATE.lists_computed && STATE.lists_computed[VIEW]) || [];

function sortedSites() {
  return Object.values(curList().sites).sort((a, b) => {
    const rank = (x) => (x.status === "resolved" ? 1 : 0);
    return rank(a) - rank(b) || b.hits - a.hits || b.lastSeen - a.lastSeen;
  });
}

const isExcepted = (key, ex) => (ex || []).some((d) => key === d || key.endsWith("." + d));

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

// ---------- отрисовка ----------
function render() {
  const S = STATE.settings;
  if (!VIEW) VIEW = S.mode;

  $("enabled").checked = S.enabled;
  $("mainFrameOnly").checked = S.mainFrameOnly;
  $("groupByBaseDomain").checked = S.groupByBaseDomain;
  $("detectChallenges").checked = S.detectChallenges;
  $("skipWhenVpnOff").checked = S.skipWhenVpnOff;
  $("minHits").value = S.minHits;

  renderVpn();
  renderApply();
  renderTabs();
  renderList();
  renderCandidates();
  renderExceptions();
  const L2 = curList();
  requestIps([
    ...computed(),
    ...Object.keys(L2.sites),
    ...Object.keys(L2.entries),
    ...challengeList().map((c) => c.host)
  ]);
}

function renderTabs() {
  for (const m of ["blacklist", "whitelist"]) {
    const tab = $(m === "blacklist" ? "tabBlacklist" : "tabWhitelist");
    const chip = $(m === "blacklist" ? "chipBlacklist" : "chipWhitelist");
    tab.classList.toggle("active", VIEW === m);
    chip.textContent = STATE.settings.mode === m ? "● активен" : "";
    chip.hidden = STATE.settings.mode !== m;
  }
  $("modeHint").textContent = LIST_TEXT[VIEW].hint;
  $("inactiveBanner").hidden = STATE.settings.mode === VIEW;
  $("autoAddLabel").textContent = LIST_TEXT[VIEW].autoAdd;
  $("autoAdd").checked = curList().autoAdd;
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
  ip.textContent =
    [g.ip, g.isp].filter(Boolean).join(" · ") + (a.failStreak ? " · обновляю…" : "");

  if (v.vpnControl) {
    btnEl.hidden = false;
    btnEl.textContent = v.vpnUp ? "Отключить" : "Подключить";
    btnEl.className = "vpn-btn " + (v.vpnUp ? "off" : "on");
    btnEl.disabled = false;
  } else {
    btnEl.hidden = true;
  }
}

// Строка «что сейчас с применением списка» — вместо загадочного «агент не отвечает».
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
  const modeName = ap.mode === "whitelist" ? "белый список" : "чёрный список";
  if (!a.reachable) {
    cls = "warn";
    text = "Список не применяется: нет связи с агентом";
  } else if (ap.busy) {
    text = "⏳ Агент применяет список…";
  } else if (v.sig !== STATE.sig) {
    cls = "warn";
    text = "⏳ Есть изменения — отправляю агенту…";
  } else if (ap.ok === false) {
    cls = "err";
    text = `⚠ Не применено (${modeName}): ${ap.error || "ошибка"}`;
  } else if (!v.vpnUp) {
    text = `✓ ${cap(modeName)} у агента (${ap.entries ?? 0} записей). VPN выключен — маршруты не нужны`;
  } else if (ap.mode === "whitelist") {
    text = `✓ Применено: через VPN ${ap.routes ?? 0} адр. из ${ap.entries ?? 0} записей, остальное напрямую · ${fmtAgo(ap.at)}`;
  } else {
    text = `✓ Применено: мимо VPN ${ap.routes ?? 0} адр. из ${ap.entries ?? 0} записей · ${fmtAgo(ap.at)}`;
  }
  const s = a.sync;
  if (s && s.ok === false && s.error && a.reachable && !cls) {
    cls = "err";
    text = "⚠ Последняя отправка не удалась: " + s.error;
  }
  el.className = "apply-line " + cls;
  el.textContent = text;
}
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

// ---------- IP-адреса записей (резолвит агент) ----------
const IPS = {}; // имя -> { ips, ts }
let resolving = false;
const isIpLike = (s) => /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(s);

function requestIps(names) {
  const need = [...new Set(names)].filter((n) => !isIpLike(n) && !(IPS[n] && Date.now() - IPS[n].ts < 5 * 60 * 1000));
  if (!need.length || resolving) return;
  resolving = true;
  send({ type: "resolveIps", names: need })
    .then((r) => {
      if (r && r.ips) {
        for (const n of need) IPS[n] = { ips: r.ips[n] || [], ts: Date.now() };
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

const challengeList = () => (VIEW === "blacklist" ? Object.values(STATE.challenges || {}) : []);
const challengeInList = (c) => c.status !== "ignored" && (STATE.lists.blacklist.autoAdd || c.confirmed);

// Запись-заглушка: сайт открывается, но блокирует VPN → обход идёт по IP-диапазонам.
function challengeRow(c, inList) {
  const li = document.createElement("li");
  li.className = "entry" + (c.status === "ignored" ? " resolved" : "");
  const name = document.createElement("span");
  name.className = "domain";
  name.textContent = c.host;
  const tag = document.createElement("span");
  tag.className = "badge block";
  tag.textContent = "🚫 блокирует VPN";
  tag.title = "Сайт открывается, но не пускает через VPN — обход идёт по IP-диапазонам сайта";
  const x = btn("iconbtn", "×", inList ? "Убрать из списка (игнорировать)" : "Удалить", () =>
    act({ type: inList ? "ignoreChallenge" : "removeChallenge", host: c.host })
  );
  li.append(name, tag, x);

  const meta = document.createElement("span");
  meta.className = "meta";
  const st =
    c.status === "applied"
      ? `${(c.ranges || []).length} диапазон(ов)` + (c.asns && c.asns.length ? ` · AS${c.asns.join(", AS")}` : "")
      : c.status === "ignored"
      ? "игнор"
      : "определяю диапазоны…";
  meta.textContent = `${c.signal || "?"} · ×${c.count} · ${fmtAgo(c.lastSeen)} · ${st}`;
  li.append(meta);

  const ips = addressLine(c.host, c.ranges);
  if (ips) li.append(ips);

  const actions = document.createElement("div");
  actions.className = "ch-actions";
  actions.append(
    btn("mini", "пересчитать", "Заново определить IP-диапазоны", async () => {
      await send({ type: "rederiveChallenge", host: c.host });
      toast("Пересчитываю диапазоны…");
    })
  );
  if (c.status === "ignored") actions.append(btn("mini", "вернуть", "", () => act({ type: "rederiveChallenge", host: c.host })));
  else if (!inList) actions.append(btn("mini", "в список", "", () => act({ type: "confirmChallenge", host: c.host })));
  li.append(actions);
  return li;
}

// «В списке»: ручные записи + автодобавленные кандидаты + заглушки VPN.
function renderList() {
  const L = curList();
  const ul = $("entries");
  ul.innerHTML = "";
  const chal = challengeList();
  const chalHosts = new Set(chal.map((c) => c.host));
  const inChal = chal.filter(challengeInList);
  const all = computed().filter((k) => (L.entries[k] || L.sites[k]) && !chalHosts.has(k));
  // Диапазоны из стартового набора (сотни CIDR Google/Meta) — одной строкой, а не сотнями.
  const defRanges = all.filter((k) => L.entries[k] && L.entries[k].default && isIpLike(k));
  const defSet = new Set(defRanges);
  const keys = all.filter((k) => !defSet.has(k));
  const total = keys.length + inChal.length + defRanges.length;
  $("entriesCount").textContent = total ? `(${total})` : "";
  $("entriesEmpty").hidden = total > 0;

  for (const c of inChal) ul.append(challengeRow(c, true));
  for (const k of keys) {
    const manual = !!L.entries[k];
    const li = document.createElement("li");
    li.className = "entry";
    const name = document.createElement("span");
    name.className = "domain";
    name.textContent = k;
    const tag = document.createElement("span");
    tag.className = "badge";
    tag.textContent = manual ? "вручную" : "авто ×" + L.sites[k].hits;
    const x = btn(
      "iconbtn",
      "×",
      manual ? "Убрать из списка" : "Убрать и добавить в исключения",
      () => act(manual ? { type: "removeEntry", list: VIEW, key: k } : { type: "ignoreKey", list: VIEW, key: k })
    );
    li.append(name, tag, x);
    const ips = addressLine(k);
    if (ips) li.append(ips);
    ul.append(li);
  }

  if (defRanges.length) {
    const li = document.createElement("li");
    li.className = "entry";
    const name = document.createElement("span");
    name.className = "domain";
    name.textContent = "IP-диапазоны по умолчанию";
    const tag = document.createElement("span");
    tag.className = "badge";
    tag.textContent = defRanges.length + " шт.";
    tag.title = defRanges.slice(0, 40).join("\n") + (defRanges.length > 40 ? "\n…" : "");
    const x = btn("iconbtn", "×", "Убрать все диапазоны по умолчанию", () => {
      if (confirm("Убрать все " + defRanges.length + " IP-диапазонов по умолчанию (Google, Meta, Telegram)?"))
        act({ type: "removeEntries", list: VIEW, keys: defRanges });
    });
    li.append(name, tag, x);
    const d = document.createElement("div");
    d.className = "ips";
    d.textContent = "Google (в т.ч. YouTube), Meta (Facebook, Instagram, WhatsApp), Telegram — целиком, чтобы не терять адреса, которые они меняют";
    li.append(d);
    ul.append(li);
  }
}

function renderCandidates() {
  const L = curList();
  const min = STATE.settings.minHits || 1;
  const inList = new Set(computed());
  const chal = challengeList();
  const chalHosts = new Set(chal.map((c) => c.host));
  const ul = $("list");
  ul.innerHTML = "";
  // В «в списке» уже показаны — здесь только те, что ещё не в списке.
  const sites = sortedSites().filter((s) => !inList.has(s.key) && !chalHosts.has(s.key));
  const pendingChal = chal.filter((c) => !challengeInList(c));
  const total = sites.length + pendingChal.length;
  $("candCount").textContent = total ? `(${total})` : "";
  const empty = $("empty");
  empty.hidden = total > 0;
  empty.textContent = LIST_TEXT[VIEW].candEmpty;

  for (const c of pendingChal) ul.append(challengeRow(c, false));
  for (const s of sites) {
    const li = document.createElement("li");
    li.className = s.status === "resolved" ? "resolved" : "";

    const domain = document.createElement("span");
    domain.className = "domain";
    domain.textContent = s.key;

    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent = "×" + s.hits;

    const add = btn("mini", "в список", "Добавить в список", () => act({ type: "promoteSite", list: VIEW, key: s.key }));
    const ex = btn("iconbtn", "×", "В исключения (не добавлять автоматически)", () =>
      act({ type: "ignoreKey", list: VIEW, key: s.key })
    );

    const meta = document.createElement("span");
    meta.className = "meta";
    const err = (s.lastError || "").replace("net::ERR_", "");
    let why = "";
    if (s.status === "resolved") why = " · снова открывается";
    else if (s.hits < min) why = ` · ещё ${min - s.hits} до порога`;
    else if (L.autoAdd && isExcepted(s.key, L.exceptions)) why = " · в исключениях";
    else if (!L.autoAdd) why = " · автодобавление выключено";
    meta.textContent = `${err} · последний раз ${fmtAgo(s.lastSeen)}${why}`;

    li.append(domain, badge, add, ex, meta);
    const ips = addressLine(s.key);
    if (ips) li.append(ips);
    ul.append(li);
  }
}

function renderExceptions() {
  const L = curList();
  const ul = $("ignoreList");
  ul.innerHTML = "";
  $("exceptCount").textContent = L.exceptions.length ? `(${L.exceptions.length})` : "";
  $("exceptNote").textContent = LIST_TEXT[VIEW].exceptNote + (L.autoAdd ? "" : " Сейчас автодобавление выключено — исключения не действуют.");
  for (const d of L.exceptions.slice().sort()) {
    const li = document.createElement("li");
    li.className = "ignore-item";
    const name = document.createElement("span");
    name.textContent = d;
    const x = btn("iconbtn", "×", "Убрать из исключений", () => act({ type: "removeException", list: VIEW, domain: d }));
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
setting("mainFrameOnly", "mainFrameOnly");
setting("groupByBaseDomain", "groupByBaseDomain");
setting("detectChallenges", "detectChallenges");
setting("skipWhenVpnOff", "skipWhenVpnOff");

$("minHits").onchange = async (e) => {
  const v = Math.max(1, Math.min(50, parseInt(e.target.value, 10) || 1));
  await send({ type: "setSettings", settings: { minHits: v } });
  await load();
};

$("autoAdd").onchange = (e) => act({ type: "setListSettings", list: VIEW, autoAdd: e.target.checked });

for (const tab of [$("tabBlacklist"), $("tabWhitelist")]) {
  tab.onclick = () => {
    VIEW = tab.dataset.list;
    render();
  };
}
$("activateBtn").onclick = () => act({ type: "setMode", mode: VIEW }, "Режим переключён — применяю…");

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

async function addExceptionFromInput() {
  const v = $("ignoreInput").value;
  if (!v.trim()) return;
  const r = await act({ type: "addException", list: VIEW, domain: v });
  if (r && r.ok) $("ignoreInput").value = "";
}
$("ignoreAddBtn").onclick = addExceptionFromInput;
$("ignoreInput").onkeydown = (e) => {
  if (e.key === "Enter") addExceptionFromInput();
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

$("addCurrent").onclick = async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let host = "";
  try {
    if (/^https?:/.test(tab.url)) host = new URL(tab.url).hostname;
  } catch (_) {}
  if (!host) {
    toast("Нет подходящего URL во вкладке");
    return;
  }
  const b = $("addCurrent");
  b.disabled = true;
  if (VIEW === "blacklist") toast("Проверяю, открывается ли сайт…");
  const r = await send({ type: "addCurrentSite", list: VIEW, host });
  b.disabled = false;
  await load();
  if (!r || !r.ok) return toast((r && r.error) || "Не вышло");
  if (r.kind === "vpn-block") toast(r.key + " открывается — значит блокирует VPN. Определяю IP-диапазоны…");
  else if (r.reason === "unreachable") toast(r.key + " не открывается — добавлен в чёрный список");
  else if (r.reason === "vpn-off") toast("Добавлено: " + r.key + ". VPN выключен — блокировку VPN проверить нельзя");
  else toast("Добавлено в " + (VIEW === "blacklist" ? "чёрный" : "белый") + " список: " + r.key);
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
        : `Применено: ${s.entries ?? 0} записей → ${s.routes ?? 0} адр. (+${s.added ?? 0} −${s.removed ?? 0}), ${s.ms ?? 0} мс`
    );
  }
  await load();
};

// ---- сворачиваемые блоки: запоминаем, какие свёрнуты ----
for (const id of ["entriesDetails", "candDetails", "exceptDetails"]) {
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
  toast(`Загружено: ${r.count} записей, заглушек: ${r.challenges}. Отправляю агенту…`);
};

$("downloadBtn").onclick = async () => {
  const r = await send({ type: "downloadList" });
  toast(r && r.count ? `Файл сохранён: ${r.count} записей` : "Список пуст");
};

$("clearBtn").onclick = async () => {
  if (!confirm("Очистить собранных кандидатов этого списка? (ручные записи и заглушки VPN останутся)")) return;
  await act({ type: "clearAll", list: VIEW, challengesToo: false });
};

chrome.storage.onChanged.addListener((changes) => {
  if (changes.state || changes.agent) load();
});

load();
send({ type: "vpnStatus" }).then(load);
setInterval(() => send({ type: "vpnStatus" }), 4000);
