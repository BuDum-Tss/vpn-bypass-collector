// Тесты логики background.js на подставном chrome-API (без браузера): node test/background.test.js
const fs = require("fs"), vm = require("vm"), path = require("path");

const store = {};
const L = {};
let fetches = [];
const chrome = {
  storage: {
    local: {
      get: async (k) => (typeof k === "string" ? { [k]: store[k] } : { ...store }),
      set: async (o) => Object.assign(store, JSON.parse(JSON.stringify(o)))
    },
    onChanged: { addListener() {} }
  },
  alarms: { create() {}, onAlarm: { addListener: (f) => (L.alarm = f) } },
  action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} },
  webNavigation: { onErrorOccurred: { addListener: (f) => (L.navErr = f) }, onCompleted: { addListener: (f) => (L.navOk = f) } },
  runtime: { onInstalled: { addListener() {} }, onMessage: { addListener: (f) => (L.msg = f) } },
  downloads: { download: async () => {} }
};

// Ответы агента для тестов: что «видит» проверка по каждому сайту
const PROBES = {
  "vpnonly.example": { direct: { reached: false, kind: "timeout" }, vpn: { reached: true, ok: true, status: 200, ttfb: 300, kbps: 4000 } },
  "directonly.example": { direct: { reached: true, ok: true, status: 200, ttfb: 200, kbps: 4000 }, vpn: { reached: false, kind: "reset" } },
  "stub.example": { direct: { reached: true, ok: true, status: 200, ttfb: 200, kbps: 4000 }, vpn: { reached: true, ok: false, stub: true, status: 200, ttfb: 300 } },
  "both.example": { direct: { reached: true, ok: true, status: 200, ttfb: 200, kbps: 4000 }, vpn: { reached: true, ok: true, status: 200, ttfb: 300, kbps: 4000 } },
  "dead.example": { direct: { reached: false, kind: "timeout" }, vpn: { reached: false, kind: "timeout" } },
  "slow.example": { direct: { reached: true, ok: true, status: 200, ttfb: 500, kbps: 90 }, vpn: { reached: true, ok: true, status: 200, ttfb: 300, kbps: 5000 } },
  "cf.example": { direct: { reached: true, ok: true, challenge: true, status: 403, ttfb: 300 }, vpn: { reached: true, ok: true, challenge: true, status: 403, ttfb: 300 } },
  "ozonlike.example": { direct: { reached: true, ok: true, status: 200, ttfb: 200, kbps: 4000 }, vpn: { reached: true, ok: true, challenge: true, status: 403, ttfb: 300 } }
};
let agentAlive = true;
let vpnSkipped = false;
const ctx = {
  chrome, console, URL, AbortSignal, setTimeout: (f, ms, ...a) => setTimeout(f, Math.min(ms || 0, 5), ...a), clearTimeout,
  Promise, JSON, Math, Date, Object, Set, Map, Array, String, Number, Error, encodeURIComponent,
  fetch: async (u, o) => {
    const s = String(u);
    fetches.push({ u: s, body: o && o.body ? JSON.parse(o.body) : null });
    if (!agentAlive && s.includes("127.0.0.1")) throw new Error("agent down");
    if (s.endsWith("/probe")) {
      const host = JSON.parse(o.body).host;
      const p = PROBES[host];
      if (!p) return { ok: true, json: async () => ({ ok: true, host, ips: [], direct: { reached: false, kind: "dns" }, vpn: { reached: false, kind: "dns" } }) };
      return { ok: true, json: async () => ({ ok: true, host, ips: ["1.2.3.4"], direct: p.direct, vpn: vpnSkipped ? { skipped: true } : p.vpn }) };
    }
    if (s.endsWith("/apply")) return { ok: true, json: async () => ({ ok: true, summary: { entries: 3, routes: 3, ms: 5, vpnUp: true } }) };
    if (s.includes("/list?kind=")) return { ok: true, json: async () => ({ kind: s.includes("kind=vpn") ? "vpn" : "direct", entries: s.includes("kind=vpn") ? ["youtube.com"] : ["ozon.ru", "185.73.192.0/21"] }) };
    if (s.endsWith("/status")) return { ok: true, json: async () => ({ vpnUp: true, sig: "x", apply: {} }) };
    return { ok: true, json: async () => ({}) };
  }
};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "background.js"), "utf8"), ctx);
const msg = (m) => new Promise((res) => L.msg(m, null, res));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const state = async () => msg({ type: "getState" });
let fails = 0;
const t = (name, ok, extra) => {
  console.log((ok ? "PASS " : "FAIL ") + name + (ok ? "" : "  " + JSON.stringify(extra)));
  if (!ok) fails++;
};
const live = () => { store.agent = { reachable: true, failStreak: 0, lastOkAt: Date.now(), status: { vpnUp: true } }; };
const fresh = () => { for (const k of Object.keys(store)) delete store[k]; fetches = []; agentAlive = true; vpnSkipped = false; live(); };
async function drain() { for (let i = 0; i < 8; i++) { await ctx.pumpQueue(); await sleep(20); } }

(async () => {
  await sleep(30);

  // ---------- classify: решение по замерам двух путей ----------
  const cl = (d, v) => ctx.classify(d, v).result;
  t("classify: напрямую нет, через VPN да -> vpn", cl(PROBES["vpnonly.example"].direct, PROBES["vpnonly.example"].vpn) === "vpn");
  t("classify: напрямую да, через VPN нет -> direct", cl(PROBES["directonly.example"].direct, PROBES["directonly.example"].vpn) === "direct");
  t("classify: заглушка «отключите VPN» на VPN -> direct (stub)", ctx.classify(PROBES["stub.example"].direct, PROBES["stub.example"].vpn).stub === true);
  t("classify: работает и так и так -> both", cl(PROBES["both.example"].direct, PROBES["both.example"].vpn) === "both");
  t("classify: не открывается нигде -> none", cl(PROBES["dead.example"].direct, PROBES["dead.example"].vpn) === "none");
  t("classify: медленно напрямую (замедление) -> vpn", cl(PROBES["slow.example"].direct, PROBES["slow.example"].vpn) === "vpn");
  t("classify: проверка браузера на обоих путях -> both (не доказательство блокировки VPN)", cl(PROBES["cf.example"].direct, PROBES["cf.example"].vpn) === "both");
  t("classify: проверка браузера только на VPN -> direct", cl(PROBES["ozonlike.example"].direct, PROBES["ozonlike.example"].vpn) === "direct");
  t("classify: VPN выключен -> unknown (не решаем)", cl(PROBES["both.example"].direct, { skipped: true }) === "unknown");

  // ---------- миграция с v2 ----------
  fresh();
  store.state = {
    version: 2,
    settings: { enabled: true, mode: "whitelist", minHits: 2, groupByBaseDomain: true },
    lists: {
      blacklist: { autoAdd: true, exceptions: ["sentry.io", "mysite.ru"], entries: { "hh.ru": { key: "hh.ru" }, "yandex.ru": { key: "yandex.ru" } },
        sites: { "ozon.ru": { key: "ozon.ru", hits: 3, status: "new" }, "kinopoisk.ru": { key: "kinopoisk.ru", hits: 9, status: "resolved" }, "rare.ru": { key: "rare.ru", hits: 1, status: "new" } } },
      whitelist: { autoAdd: true, exceptions: [], entries: { "youtube.com": { key: "youtube.com" }, "yandex.ru": { key: "yandex.ru" } }, sites: {}, defaultsSeeded: true }
    },
    challenges: { "ozon-stub.ru": { host: "ozon-stub.ru", status: "applied", ranges: ["185.73.192.0/21"], confirmed: true }, "ignored-stub.ru": { host: "ignored-stub.ru", status: "ignored", ranges: [] } }
  };
  let s = await state();
  t("v2→v3: «чёрный» (обход VPN) стал списком «мимо VPN»", !!s.lists.direct.entries["hh.ru"] && !!s.lists.direct.entries["ozon.ru"]);
  t("v2→v3: авто-кандидат ниже порога и resolved не попали", !s.lists.direct.entries["rare.ru"] && !s.lists.direct.entries["kinopoisk.ru"]);
  t("v2→v3: «белый» стал списком «через VPN»", !!s.lists.vpn.entries["youtube.com"]);
  t("v2→v3: сайт в обоих списках снят с обоих и отправлен на проверку", !s.lists.direct.entries["yandex.ru"] && !s.lists.vpn.entries["yandex.ru"] && s.queue["yandex.ru"] && s.queue["yandex.ru"].reason === "conflict", s.queue);
  t("v2→v3: заглушка попала в «мимо VPN», игнорируемая нет", !!s.lists.direct.entries["ozon-stub.ru"] && !s.lists.direct.entries["ignored-stub.ru"]);
  t("v2→v3: исключения стали списком «не проверять»", s.ignore.includes("mysite.ru") && s.ignore.includes("sentry.io"));
  t("v2→v3: путь по умолчанию — VPN", s.settings.defaultPath === "vpn");
  t("стартовый набор добавлен в «через VPN» и помечен default", !!s.lists.vpn.entries["chatgpt.com"] && s.lists.vpn.entries["chatgpt.com"].default === true);
  t("ранее посеянное не удваивается, конфликтное не возвращается", !s.lists.vpn.entries["yandex.ru"]);
  t("диапазоны заглушки и её хост уходят агенту в «мимо VPN»", s.lists_computed.direct.includes("185.73.192.0/21") && s.lists_computed.direct.includes("ozon-stub.ru"));

  // ---------- миграция с v1 ----------
  fresh();
  store.state = { settings: { enabled: false, minHits: 4, autoExport: true, ignoreList: ["a.example"] }, sites: { "itmo.ru": { key: "itmo.ru", hits: 51, status: "exported" }, "k.ru": { key: "k.ru", hits: 21, status: "resolved" } }, challenges: {} };
  s = await state();
  t("v1→v3: накопленные сайты в «мимо VPN», resolved нет", !!s.lists.direct.entries["itmo.ru"] && !s.lists.direct.entries["k.ru"]);
  t("v1→v3: настройки и исключения перенесены", s.settings.enabled === false && s.ignore.includes("a.example"));

  // ---------- ручные действия ----------
  fresh();
  let r = await msg({ type: "addEntry", list: "direct", value: "https://www.Ozon.RU/x" });
  t("addEntry нормализует URL и кладёт в выбранный список", r.ok && r.key === "ozon.ru", r);
  r = await msg({ type: "addEntry", list: "vpn", value: "185.73.192.0/21" });
  t("addEntry принимает CIDR", r.ok && r.key === "185.73.192.0/21");
  r = await msg({ type: "addEntry", list: "vpn", value: "не домен" });
  t("addEntry отклоняет мусор", r.ok === false);
  await msg({ type: "addEntry", list: "vpn", value: "ozon.ru" });
  s = await state();
  t("сайт не может быть в двух списках сразу: ручная запись переносит", !s.lists.direct.entries["ozon.ru"] && !!s.lists.vpn.entries["ozon.ru"]);
  await msg({ type: "moveEntry", key: "ozon.ru", to: "direct" });
  s = await state();
  t("moveEntry переносит между списками", !!s.lists.direct.entries["ozon.ru"] && !s.lists.vpn.entries["ozon.ru"]);
  await msg({ type: "removeEntry", list: "direct", key: "ozon.ru" });
  s = await state();
  t("removeEntry удаляет", !s.lists.direct.entries["ozon.ru"]);

  // ---------- «+ текущий сайт»: проверка и размещение ----------
  fresh();
  r = await msg({ type: "addCurrentSite", host: "www.vpnonly.example" });
  s = await state();
  t("+сайт: не открывается напрямую -> «через VPN»", r.result === "vpn" && !!s.lists.vpn.entries["vpnonly.example"] && s.lists.vpn.entries["vpnonly.example"].verdict.d.kind === "timeout", r);
  r = await msg({ type: "addCurrentSite", host: "directonly.example" });
  s = await state();
  t("+сайт: не открывается через VPN -> «мимо VPN»", r.result === "direct" && !!s.lists.direct.entries["directonly.example"]);
  r = await msg({ type: "addCurrentSite", host: "stub.example" });
  s = await state();
  t("+сайт: заглушка VPN -> «мимо VPN» и вывод IP-диапазонов", r.result === "direct" && r.stub === true && !!s.challenges["stub.example"], r);
  r = await msg({ type: "addCurrentSite", host: "both.example" });
  s = await state();
  t("+сайт: работает везде -> «через VPN» с пометкой both", r.result === "both" && s.lists.vpn.entries["both.example"].both === true);
  t("both-записи агенту не отправляются (маршрут не нужен)", !s.lists_computed.vpn.includes("both.example"));
  r = await msg({ type: "addCurrentSite", host: "dead.example" });
  s = await state();
  t("+сайт: не открывается нигде -> в «не открывается нигде», в списки не попадает", r.result === "none" && !!s.unreachable["dead.example"] && !s.lists.vpn.entries["dead.example"] && !s.lists.direct.entries["dead.example"]);
  await msg({ type: "addEntry", list: "direct", value: "vpnonly.example" });
  r = await msg({ type: "addCurrentSite", host: "vpnonly.example" });
  s = await state();
  t("+сайт: повторная проверка исправляет неверный список", r.result === "vpn" && r.moved === "direct" && !!s.lists.vpn.entries["vpnonly.example"] && !s.lists.direct.entries["vpnonly.example"], r);
  vpnSkipped = true;
  r = await msg({ type: "addCurrentSite", host: "both.example" });
  t("+сайт при выключенном VPN: решение откладывается", r.result === "unknown", r);
  vpnSkipped = false;
  agentAlive = false;
  r = await msg({ type: "addCurrentSite", host: "vpnonly.example" });
  t("+сайт без агента: понятная ошибка, списки не тронуты", r.result === "error", r);
  agentAlive = true;

  // ---------- автообнаружение новых сайтов ----------
  fresh();
  L.navOk({ url: "https://newsite.vpnonly.example/page", frameId: 0 });
  L.navOk({ url: "https://sub.frame.example/", frameId: 3 });
  L.navOk({ url: "http://192.168.1.5/", frameId: 0 });
  L.navOk({ url: "https://google-analytics.com/", frameId: 0 });
  await sleep(50);
  s = await state();
  t("автообнаружение: новый сайт основной страницы попадает в очередь (по базовому домену)", !!s.queue["vpnonly.example"], s.queue);
  t("автообнаружение: подфреймы, IP-адреса и «не проверять» пропускаются", !s.queue["frame.example"] && !s.queue["192.168.1.5"] && !s.queue["google-analytics.com"], Object.keys(s.queue));
  await drain();
  s = await state();
  t("очередь разобрана: сайт разложен по списку", !!s.lists.vpn.entries["vpnonly.example"] && !s.queue["vpnonly.example"], { q: s.queue });
  fetches = [];
  L.navOk({ url: "https://vpnonly.example/again", frameId: 0 });
  await sleep(30);
  s = await state();
  t("уже разложенный открывающийся сайт повторно не проверяется", !s.queue["vpnonly.example"]);
  L.navErr({ url: "https://vpnonly.example/", error: "net::ERR_CONNECTION_RESET", frameId: 0 });
  await sleep(30);
  // (5 мин на повтор уведомления — проверим отдельным ключом)
  L.navErr({ url: "https://directonly.example/", error: "net::ERR_CONNECTION_RESET", frameId: 0 });
  L.navErr({ url: "https://directonly.example/", error: "net::ERR_ABORTED", frameId: 0 });
  await sleep(30);
  s = await state();
  t("ошибка загрузки нового сайта ставит его на проверку, посторонние ошибки нет", !!s.queue["directonly.example"] && Object.keys(s.queue).length >= 1);
  await msg({ type: "setSettings", settings: { autoCheck: false } });
  L.navOk({ url: "https://both.example/", frameId: 0 });
  await sleep(30);
  s = await state();
  t("автопроверка выключена — очередь не пополняется", !s.queue["both.example"]);
  await msg({ type: "setSettings", settings: { autoCheck: true } });

  // очередь ждёт VPN: пока он выключен, ничего не решаем
  fresh();
  store.agent = { reachable: true, failStreak: 0, lastOkAt: Date.now(), status: { vpnUp: false } };
  L.navOk({ url: "https://both.example/", frameId: 0 });
  await sleep(30);
  fetches = [];
  await drain();
  s = await state();
  t("VPN выключен: очередь не разбирается, проверок не отправлено", !!s.queue["both.example"] && !fetches.some((f) => f.u.endsWith("/probe")), fetches.map((f) => f.u));

  // «не открывается нигде»: повторная проверка не раньше срока
  fresh();
  await msg({ type: "addCurrentSite", host: "dead.example" });
  L.navOk({ url: "https://dead.example/", frameId: 0 });
  await sleep(30);
  s = await state();
  t("«не открывается нигде» не ставится в очередь до срока повтора", !s.queue["dead.example"]);
  await msg({ type: "recheck", key: "dead.example" });
  s = await state();
  t("recheck ставит в очередь принудительно", !!s.queue["dead.example"]);
  await msg({ type: "dismissUnreachable", key: "dead.example" });
  s = await state();
  t("dismissUnreachable: больше не проверять", !s.unreachable["dead.example"] && s.ignore.includes("dead.example"));

  // ---------- заглушка, увиденная на странице (content.js) ----------
  fresh();
  r = await msg({ type: "challengeDetected", host: "www.hh.example", url: "https://hh.example/", signal: "text" });
  s = await state();
  t("страница «отключите VPN» при включённом VPN -> «мимо VPN» + диапазоны", r.ok && !!s.lists.direct.entries["hh.example"] && !!s.challenges["hh.example"]);
  store.agent = { reachable: true, failStreak: 0, lastOkAt: Date.now(), status: { vpnUp: false } };
  r = await msg({ type: "challengeDetected", host: "other.example", url: "https://other.example/", signal: "text" });
  s = await state();
  t("та же страница при выключенном VPN игнорируется (дело не в VPN)", r.ok === false && !s.lists.direct.entries["other.example"]);

  // ---------- отправка агенту ----------
  fresh();
  await msg({ type: "addEntry", list: "direct", value: "ozon.ru" });
  await msg({ type: "addCurrentSite", host: "both.example" });
  fetches = [];
  r = await msg({ type: "forceSync" });
  const ap = fetches.find((f) => f.u.endsWith("/apply"));
  t("forceSync шлёт /apply: путь по умолчанию, оба списка и sig", ap && ap.body.default === "vpn" && Array.isArray(ap.body.direct) && Array.isArray(ap.body.vpn) && !!ap.body.sig, ap);
  t("в «мимо VPN» — ozon.ru; в «через VPN» — стартовый набор, но не both-запись", ap.body.direct.includes("ozon.ru") && ap.body.vpn.includes("youtube.com") && !ap.body.vpn.includes("both.example"));
  t("forceSync возвращает итог применения", r.ok && r.summary && r.summary.routes === 3, r);
  await msg({ type: "setSettings", settings: { defaultPath: "direct" } });
  fetches = [];
  await msg({ type: "forceSync" });
  t("смена пути по умолчанию доходит до агента", fetches.find((f) => f.u.endsWith("/apply")).body.default === "direct");
  await msg({ type: "setSettings", settings: { defaultPath: "vpn" } });

  // ---------- защита списка агента ----------
  fresh();
  fetches = [];
  r = await msg({ type: "forceSync" });
  const ap2 = fetches.find((f) => f.u.endsWith("/apply"));
  const li = fetches.findIndex((f) => f.u.includes("/list?kind=")), ai = fetches.findIndex((f) => f.u.endsWith("/apply"));
  t("чистое расширение сначала читает списки агента, потом шлёт", li >= 0 && ai > li);
  t("списки агента попали в нужные стороны и не потеряны", ap2 && ap2.body.direct.includes("ozon.ru") && ap2.body.vpn.includes("youtube.com"), ap2 && ap2.body);
  fresh();
  agentAlive = false;
  fetches = [];
  r = await msg({ type: "forceSync" });
  t("чистое расширение и агент недоступен: ничего не отправляется", r.ok === false && !fetches.some((f) => f.u.endsWith("/apply")), r);
  agentAlive = true;

  // ---------- «агент не отвечает» не мигает от одного сбоя ----------
  fresh();
  agentAlive = false;
  await msg({ type: "vpnStatus" });
  let a = (await chrome.storage.local.get("agent")).agent;
  t("1 сбой: агент считается доступным, данные сохранены", a.reachable === true && a.failStreak === 1 && a.status.vpnUp === true, a);
  await msg({ type: "vpnStatus" }); await msg({ type: "vpnStatus" });
  a = (await chrome.storage.local.get("agent")).agent;
  t("3 сбоя подряд: недоступен, последние данные не потеряны", a.reachable === false && !!a.status && a.failStreak === 3, a);
  agentAlive = true;

  // ---------- резервная копия ----------
  fresh();
  await msg({ type: "addEntry", list: "direct", value: "ozon.ru" });
  const ex = await msg({ type: "exportState" });
  t("exportState отдаёт состояние без кэша RIPE", ex.ok && !ex.state.ripeCache && ex.state.lists.direct.entries["ozon.ru"]);
  fresh();
  r = await msg({ type: "importState", state: ex.state });
  s = await state();
  t("importState восстанавливает списки", r.ok && !!s.lists.direct.entries["ozon.ru"]);
  r = await msg({ type: "importState", state: { foo: 1 } });
  t("импорт мусора отклоняется", r.ok === false);
  fresh();
  r = await msg({ type: "importState", state: { version: 2, settings: { enabled: true, minHits: 2 }, lists: { blacklist: { autoAdd: true, exceptions: [], entries: { "a.ru": { key: "a.ru" } }, sites: {} }, whitelist: { autoAdd: true, exceptions: [], entries: {}, sites: {} } }, challenges: {} } });
  s = await state();
  t("importState понимает файл прежней версии (v2)", r.ok && !!s.lists.direct.entries["a.ru"]);

  console.log(fails ? `\n${fails} FAILED` : "\nВСЕ ПРОВЕРКИ ПРОЙДЕНЫ");
  process.exit(fails ? 1 : 0);
})();
