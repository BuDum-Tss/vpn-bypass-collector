const fs = require("fs"), vm = require("vm"), path = require("path");
// Тесты логики background.js на подставном chrome-API (без браузера): node test/background.test.js
const store = {}; const listeners = {}; let fetches = [];
const chrome = {
  storage: { local: {
    get: async (k) => (typeof k === "string" ? { [k]: store[k] } : { ...store }),
    set: async (o) => Object.assign(store, JSON.parse(JSON.stringify(o))),
  }, onChanged: { addListener() {} } },
  alarms: { create() {}, onAlarm: { addListener() {} } },
  action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} },
  webNavigation: { onErrorOccurred: { addListener: (f) => (listeners.navErr = f) }, onCompleted: { addListener: (f) => (listeners.navOk = f) } },
  webRequest: { onErrorOccurred: { addListener() {} } },
  runtime: { onInstalled: { addListener() {} }, onMessage: { addListener: (f) => (listeners.msg = f) } },
  downloads: { download: async () => {} },
};
const ctx = { chrome, console, URL, AbortSignal, setTimeout, clearTimeout, Promise, JSON, Math, Date, Object, Set, Map, Array, String, Number, Error,
  fetch: async (u, o) => { fetches.push({ u: String(u), body: o && o.body ? JSON.parse(o.body) : null });
    if (String(u).endsWith("/apply")) return { ok: true, json: async () => ({ ok: true, summary: { entries: 1, routes: 1, added: 1, removed: 0, ms: 5, vpnUp: true } }) };
    return { ok: true, json: async () => ({ vpnUp: true, sig: "x", apply: {} }) }; } };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "background.js"), "utf8"), ctx);
const msg = (m) => new Promise((res) => listeners.msg(m, null, res));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let fails = 0; const t = (name, ok, extra) => { console.log((ok ? "PASS " : "FAIL ") + name + (ok ? "" : "  " + JSON.stringify(extra))); if (!ok) fails++; };

(async () => {
  await sleep(50);
  // --- миграция старого (v1) состояния
  store.state = { settings: { enabled: true, minHits: 2, autoExport: true, ignoreList: ["sentry.io", "mysite.ru"], groupByBaseDomain: true, mainFrameOnly: true },
    sites: { "old.ru": { key: "old.ru", hits: 3, lastSeen: Date.now(), status: "new", errors: {} } }, challenges: {}, vpn: {} };
  let s = await msg({ type: "getState" });
  t("v1 -> v2: sites -> blacklist.sites", !!s.lists.blacklist.sites["old.ru"], s.lists);
  t("v1 -> v2: ignoreList -> blacklist.exceptions", s.lists.blacklist.exceptions.includes("mysite.ru"));
  t("v1 -> v2: whitelist пуст и независим", Object.keys(s.lists.whitelist.sites).length === 0 && s.lists.whitelist.exceptions.includes("sentry.io"));
  t("авто-кандидат old.ru (3>=2) попал в чёрный список", s.lists_computed.blacklist.includes("old.ru"), s.lists_computed);
  t("в белый список он не попал", !s.lists_computed.whitelist.includes("old.ru"));

  // --- ручные записи и валидация
  let r = await msg({ type: "addEntry", list: "whitelist", value: "https://www.YouTube.com/watch?v=1" });
  t("addEntry нормализует URL -> youtube.com", r.ok && r.key === "youtube.com", r);
  r = await msg({ type: "addEntry", list: "whitelist", value: "185.73.192.0/21" });
  t("addEntry принимает CIDR", r.ok && r.key === "185.73.192.0/21", r);
  r = await msg({ type: "addEntry", list: "whitelist", value: "не домен" });
  t("addEntry отклоняет мусор", r.ok === false, r);

  // --- исключения работают только при autoAdd
  await msg({ type: "addException", list: "blacklist", domain: "old.ru" });
  s = await msg({ type: "getState" });
  t("addException убирает кандидата", !s.lists.blacklist.sites["old.ru"]);
  const nav = (url) => listeners.navErr({ url, error: "net::ERR_CONNECTION_RESET", frameId: 0 });
  nav("https://old.ru/"); await sleep(30);
  s = await msg({ type: "getState" });
  t("autoAdd ВКЛ + исключение -> сайт не собирается", !s.lists.blacklist.sites["old.ru"], s.lists.blacklist.sites);
  await msg({ type: "setListSettings", list: "blacklist", autoAdd: false });
  nav("https://old.ru/"); await sleep(30);
  s = await msg({ type: "getState" });
  t("autoAdd ВЫКЛ -> исключения не действуют, кандидат собран", !!s.lists.blacklist.sites["old.ru"], s.lists.blacklist.sites);
  nav("https://old.ru/"); await sleep(30); s = await msg({ type: "getState" });
  t("autoAdd ВЫКЛ -> без подтверждения в список не попадает", !s.lists_computed.blacklist.includes("old.ru"), s.lists_computed);
  await msg({ type: "promoteSite", list: "blacklist", key: "old.ru" });
  s = await msg({ type: "getState" });
  t("«в список» -> ручная запись, попадает в список", s.lists_computed.blacklist.includes("old.ru") && !s.lists.blacklist.sites["old.ru"]);
  t("сайт из чёрного не «течёт» в белый", !s.lists_computed.whitelist.includes("old.ru"));

  // --- whitelist: сбор по своим правилам
  await msg({ type: "setMode", mode: "whitelist" });
  await msg({ type: "setListSettings", list: "whitelist", autoAdd: true });
  nav("https://blocked.example.org/"); await sleep(30); nav("https://blocked.example.org/"); await sleep(30);
  s = await msg({ type: "getState" });
  t("whitelist: неработающий сайт собран в whitelist.sites", s.lists.whitelist.sites["example.org"]?.hits === 2, s.lists.whitelist.sites);
  t("whitelist: он в итоговом белом списке", s.lists_computed.whitelist.includes("example.org"));
  t("whitelist: чёрный список не тронут", !s.lists_computed.blacklist.includes("example.org"));
  // сайт уже в белом списке, VPN включён, но не грузится -> VPN не поможет, не копим
  store.agent = { reachable: true, failStreak: 0, lastOkAt: Date.now(), status: { vpnUp: true } };
  const before = s.lists.whitelist.sites["example.org"].hits;
  nav("https://example.org/"); await sleep(30); s = await msg({ type: "getState" });
  t("whitelist: сайт уже через VPN и падает -> хиты не растут", s.lists.whitelist.sites["example.org"].hits === before, s.lists.whitelist.sites["example.org"]);
  // успех после ошибки в whitelist не убирает сайт
  listeners.navOk({ url: "https://example.org/", frameId: 0 }); await sleep(30); s = await msg({ type: "getState" });
  t("whitelist: успех после ошибки не «решает» кандидата", s.lists.whitelist.sites["example.org"].status === "new");

  // --- blacklist + VPN выключен -> не собираем
  await msg({ type: "setMode", mode: "blacklist" });
  await msg({ type: "setListSettings", list: "blacklist", autoAdd: true });
  store.agent = { reachable: true, failStreak: 0, lastOkAt: Date.now(), status: { vpnUp: false } };
  nav("https://novpn.site.ru/"); await sleep(30); s = await msg({ type: "getState" });
  t("blacklist: VPN выключен -> сайт не собирается", !s.lists.blacklist.sites["site.ru"], s.lists.blacklist.sites);

  // --- синхронизация: тело запроса к агенту
  fetches = []; store.agent = { reachable: true, failStreak: 0, lastOkAt: Date.now(), status: { vpnUp: true } };
  r = await msg({ type: "forceSync" });
  const ap = fetches.find((f) => f.u.endsWith("/apply"));
  t("forceSync шлёт /apply с обоими списками, режимом и sig", ap && ap.body.mode === "blacklist" && Array.isArray(ap.body.blacklist) && Array.isArray(ap.body.whitelist) && !!ap.body.sig, ap);
  t("forceSync возвращает итог применения", r.ok && r.summary && r.summary.routes === 1, r);
  t("whitelist в теле содержит youtube.com и CIDR", ap.body.whitelist.includes("youtube.com") && ap.body.whitelist.includes("185.73.192.0/21"), ap.body.whitelist);
  // --- единая кнопка «+ текущий сайт»
  const baseFetch = ctx.fetch;
  ctx.fetch = async (u, o) => {
    const s = String(u);
    if (/^https?:\/\/reach\.example\.com\//.test(s)) return { ok: true, type: "opaque" };
    if (/^https?:\/\/down\.example\.com\//.test(s)) throw new Error("net::ERR_CONNECTION_RESET");
    if (s.endsWith("/resolve")) return { ok: true, json: async () => ({ ok: true, ips: { "reach.example.com": ["1.2.3.4", "1.2.3.5"] } }) };
    return baseFetch(u, o);
  };
  store.agent = { reachable: true, failStreak: 0, lastOkAt: Date.now(), status: { vpnUp: true } };
  await msg({ type: "setMode", mode: "blacklist" });
  r = await msg({ type: "addCurrentSite", list: "blacklist", host: "reach.example.com" });
  s = await msg({ type: "getState" });
  t("чёрный+VPN вкл+сайт открывается -> заглушка (vpn-block)", r.ok && r.kind === "vpn-block" && !!s.challenges["reach.example.com"] && s.challenges["reach.example.com"].confirmed === true, r);
  t("заглушка попала в итоговый список (хост)", s.lists_computed.blacklist.includes("reach.example.com"));
  t("заглушка НЕ в ручных записях", !s.lists.blacklist.entries["reach.example.com"]);
  r = await msg({ type: "addCurrentSite", list: "blacklist", host: "down.example.com" });
  s = await msg({ type: "getState" });
  t("чёрный+VPN вкл+сайт не открывается -> обычная запись", r.ok && r.kind === "domain" && r.reason === "unreachable" && !!s.lists.blacklist.entries["down.example.com"], r);
  t("обычная запись не создаёт заглушку", !s.challenges["down.example.com"]);
  store.agent = { reachable: true, failStreak: 0, lastOkAt: Date.now(), status: { vpnUp: false } };
  r = await msg({ type: "addCurrentSite", list: "blacklist", host: "reach.example.com/x" });
  r = await msg({ type: "addCurrentSite", list: "blacklist", host: "vpnoff.example.com" });
  s = await msg({ type: "getState" });
  t("VPN выключен -> проверка блокировки невозможна, обычная запись", r.ok && r.kind === "domain" && r.reason === "vpn-off" && !s.challenges["vpnoff.example.com"], r);
  store.agent = { reachable: true, failStreak: 0, lastOkAt: Date.now(), status: { vpnUp: true } };
  r = await msg({ type: "addCurrentSite", list: "whitelist", host: "reach.example.com" });
  s = await msg({ type: "getState" });
  t("белый: без проверок, обычная запись", r.ok && r.kind === "domain" && r.reason === "whitelist" && !!s.lists.whitelist.entries["reach.example.com"], r);
  r = await msg({ type: "addCurrentSite", list: "blacklist", host: "1.2.3.4" });
  t("IP вместо домена -> отказ", r.ok === false, r);
  r = await msg({ type: "resolveIps", names: ["reach.example.com"] });
  t("resolveIps отдаёт IP от агента", r.ok && r.ips["reach.example.com"].length === 2, r);
  ctx.fetch = baseFetch;

  // --- «агент не отвечает» не мигает от одного сбоя
  ctx.fetch = async () => { throw new Error("timeout"); };
  await msg({ type: "vpnStatus" }); let a = (await chrome.storage.local.get("agent")).agent;
  t("1 сбой: reachable остаётся true, данные сохранены", a.reachable === true && a.failStreak === 1 && a.status.vpnUp === true, a);
  await msg({ type: "vpnStatus" }); await msg({ type: "vpnStatus" }); a = (await chrome.storage.local.get("agent")).agent;
  t("3 сбоя подряд: reachable=false, последние данные не потеряны", a.reachable === false && !!a.status && a.failStreak === 3, a);
  // --- защита от затирания списка агента «чистым» расширением
  for (const k of Object.keys(store)) delete store[k];
  fetches = [];
  ctx.fetch = async (u, o) => { const s2 = String(u); fetches.push({ u: s2, body: o && o.body ? JSON.parse(o.body) : null });
    if (s2.includes("/list?mode=blacklist")) return { ok: true, json: async () => ({ entries: ["ozon.ru", "185.73.192.0/21"] }) };
    if (s2.includes("/list?mode=whitelist")) return { ok: true, json: async () => ({ entries: ["youtube.com"] }) };
    if (s2.endsWith("/apply")) return { ok: true, json: async () => ({ ok: true, summary: { entries: 3, routes: 3, ms: 1 } }) };
    return { ok: true, json: async () => ({}) }; };
  r = await msg({ type: "forceSync" });
  const apply2 = fetches.find((f) => f.u.endsWith("/apply"));
  const listIdx = fetches.findIndex((f) => f.u.includes("/list?mode=blacklist")), applyIdx = fetches.findIndex((f) => f.u.endsWith("/apply"));
  t("чистое расширение: сначала читает список агента, потом шлёт", listIdx >= 0 && applyIdx > listIdx, fetches.map((f) => f.u));
  t("чистое расширение: /apply содержит списки агента, а не пустоту", apply2 && apply2.body.blacklist.includes("ozon.ru") && apply2.body.whitelist.includes("youtube.com"), apply2 && apply2.body);
  for (const k of Object.keys(store)) delete store[k];
  fetches = [];
  ctx.fetch = async (u, o) => { fetches.push({ u: String(u) }); throw new Error("agent down"); };
  r = await msg({ type: "forceSync" });
  t("чистое расширение + агент недоступен: НИЧЕГО не отправляется", r.ok === false && !fetches.some((f) => f.u.endsWith("/apply")), { r, fetches });

  // --- импорт реального восстановленного состояния (формат v1 из профиля Edge)
  // синтетическое состояние формата v1 (как у расширения 1.0): 95 сайтов, 7 заглушек, 14 исключений
  const rec = { settings: { enabled: false, minHits: 4, autoExport: true, groupByBaseDomain: true, mainFrameOnly: true,
      ignoreList: ["google-analytics.com", "googletagmanager.com", "doubleclick.net", "googlesyndication.com", "facebook.net", "hotjar.com", "sentry.io", "claude.com", "hh.ru", "ozon.ru", "stackoverflow.com", "a.example", "b.example", "c.example"] },
    sites: {}, challenges: {} };
  const site = (key, hits, status) => (rec.sites[key] = { key, hits, status, lastSeen: Date.now(), errors: {} });
  site("itmo.ru", 51, "exported"); site("habr.com", 28, "exported"); site("kinopoisk.ru", 21, "resolved");
  for (let i = 0; i < 92; i++) site("site" + i + ".ru", 1, "new");
  const ch = (host, status, ranges) => (rec.challenges[host] = { host, status, ranges, asns: [], count: 1, lastSeen: Date.now() });
  ch("itmo.ktalk.ru", "applied", ["185.161.180.0/24", "46.17.200.0/24"]); ch("openrouter.ai", "applied", ["8.47.69.0/24"]);
  ch("ozon.ru", "ignored", []); ch("c1.example", "applied", ["10.1.0.0/24"]); ch("c2.example", "applied", ["10.2.0.0/24"]);
  ch("c3.example", "applied", ["10.3.0.0/24"]); ch("c4.example", "new", []);
  ctx.fetch = async () => ({ ok: true, json: async () => ({ ok: true, summary: {} }) });
  r = await msg({ type: "importState", state: rec });
  s = await msg({ type: "getState" });
  t("импорт: 95 сайтов и 7 заглушек", r.ok && Object.keys(s.lists.blacklist.sites).length === 95 && Object.keys(s.challenges).length === 7, r);
  t("импорт: исключения (14) перенесены в чёрный список", s.lists.blacklist.exceptions.length === 14 && s.lists.blacklist.exceptions.includes("hh.ru"));
  t("импорт: минимум попаданий и «сбор выключен» сохранены", s.settings.minHits === 4 && s.settings.enabled === false, s.settings);
  const bl = s.lists_computed.blacklist;
  t("импорт: itmo.ru, habr.com в списке; resolved (kinopoisk.ru) — нет", bl.includes("itmo.ru") && bl.includes("habr.com") && !bl.includes("kinopoisk.ru"), bl.length);
  t("импорт: диапазоны заглушек попали в список", bl.includes("185.161.180.0/24") && bl.includes("8.47.69.0/24"));
  t("импорт: игнорируемая заглушка ozon.ru не в списке", !bl.includes("ozon.ru"));
  t("импорт: в белом списке только стартовый набор", Object.values(s.lists.whitelist.entries).every((e) => e.default) && s.lists_computed.whitelist.length > 20, s.lists_computed.whitelist.length);
  t("стартовый набор: claude, youtube, instagram, facebook, google", ["claude.ai", "youtube.com", "googlevideo.com", "instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net", "google.com"].every((d) => s.lists_computed.whitelist.includes(d)));
  t("стартовый набор не попал в чёрный список", !s.lists_computed.blacklist.includes("youtube.com"));
  await msg({ type: "removeEntry", list: "whitelist", key: "facebook.com" });
  await msg({ type: "setSettings", settings: { minHits: 4 } });
  s = await msg({ type: "getState" });
  t("удалённая запись набора не возвращается", !s.lists_computed.whitelist.includes("facebook.com") && s.lists.whitelist.seeded.includes("facebook.com"));
  t("набор 2: ИИ, X, Discord, LinkedIn, Twitch, мессенджеры, прочее", ["chatgpt.com", "x.com", "discord.com", "linkedin.com", "twitch.tv", "signal.org", "whatsapp.com", "t.me", "149.154.160.0/20", "spotify.com", "netflix.com", "speedtest.net", "medium.com", "reddit.com", "notion.so", "bbc.com", "rutracker.org"].every((d) => s.lists_computed.whitelist.includes(d)));
  // миграция: у кого уже есть набор 1 (старый флаг) — досеивается только набор 2, удалённое не возвращается
  store.state = { settings: { enabled: true, minHits: 2 }, lists: { blacklist: { autoAdd: true, exceptions: [], entries: { "a.ru": { key: "a.ru" } }, sites: {} },
    whitelist: { autoAdd: true, exceptions: [], sites: {}, defaultsSeeded: true, entries: { "youtube.com": { key: "youtube.com", default: true } } } }, challenges: {} };
  s = await msg({ type: "getState" });
  t("миграция: набор 2 досеян", s.lists_computed.whitelist.includes("chatgpt.com") && s.lists_computed.whitelist.includes("x.com"));
  t("миграция: удалённое из набора 1 (facebook.com) не вернулось", !s.lists_computed.whitelist.includes("facebook.com") && !s.lists_computed.whitelist.includes("claude.ai"));
  t("миграция: старый флаг заменён на seeded", s.lists.whitelist.defaultsSeeded === undefined && s.lists.whitelist.seeded.length > 100, s.lists.whitelist.seeded.length);
  console.log("   размер белого списка по умолчанию:", s.lists_computed.whitelist.length);
  await msg({ type: "addEntry", list: "whitelist", value: "youtube.com" });
  s = await msg({ type: "getState" });
  t("ручное добавление записи набора снимает пометку default", s.lists.whitelist.entries["youtube.com"].default !== true);
  
  r = await msg({ type: "importState", state: { foo: 1 } });
  t("импорт мусора отклоняется", r.ok === false, r);
  console.log(fails ? `\n${fails} FAILED` : "\nВСЕ ПРОВЕРКИ ПРОЙДЕНЫ");
  process.exit(fails ? 1 : 0);
})();
