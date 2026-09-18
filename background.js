// VPN Bypass Collector — service worker.
// Два независимых режима работы:
//   blacklist — «чёрный список»: эти сайты идут МИМО VPN (собираются те, что не грузятся при VPN);
//   whitelist — «белый список»:  ТОЛЬКО эти сайты идут через VPN (собираются те, что не грузятся напрямую).
// У каждого списка свои: ручные записи, кандидаты (собранные сайты), исключения и флаг автодобавления.
// Исключения работают только при включённом автодобавлении: это «никогда не добавлять автоматически».

const MODES = ["blacklist", "whitelist"];

const BLOCKING_ERRORS = new Set([
  "net::ERR_CONNECTION_RESET",
  "net::ERR_CONNECTION_TIMED_OUT",
  "net::ERR_TIMED_OUT",
  "net::ERR_CONNECTION_REFUSED",
  "net::ERR_CONNECTION_CLOSED",
  "net::ERR_CONNECTION_ABORTED",
  "net::ERR_CONNECTION_FAILED",
  "net::ERR_TUNNEL_CONNECTION_FAILED",
  "net::ERR_PROXY_CONNECTION_FAILED",
  "net::ERR_SOCKS_CONNECTION_FAILED",
  "net::ERR_EMPTY_RESPONSE",
  "net::ERR_SSL_PROTOCOL_ERROR",
  "net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH",
  "net::ERR_ADDRESS_UNREACHABLE",
  "net::ERR_NAME_NOT_RESOLVED",
  "net::ERR_NAME_RESOLUTION_FAILED",
  "net::ERR_ICANN_NAME_COLLISION",
  "net::ERR_HTTP2_PROTOCOL_ERROR",
  "net::ERR_QUIC_PROTOCOL_ERROR",
  "net::ERR_HTTP2_SERVER_REFUSED_STREAM",
  "net::ERR_TOO_MANY_REDIRECTS"
]);

// Мусорные хосты, которые почти всегда ломаются не из-за VPN (трекеры/аналитика/реклама).
const DEFAULT_IGNORE = [
  "google-analytics.com",
  "googletagmanager.com",
  "doubleclick.net",
  "googlesyndication.com",
  "facebook.net",
  "hotjar.com",
  "sentry.io"
];

// Двухуровневые TLD для наивного вычисления базового домена (eTLD+1).
const MULTI_TLD = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
  "com.ua", "net.ua", "org.ua", "co.nz", "com.br", "com.tr", "com.cn",
  "co.jp", "co.kr", "com.mx", "com.sg", "com.hk", "co.in", "co.za"
]);

// Стартовый набор белого списка (сервисы, которые обычно нужны через VPN). Добавляется один раз;
// удалить любую запись можно — она не вернётся. Агент резолвит только перечисленные имена,
// поэтому поддомены с отдельными адресами перечислены явно.
const WHITELIST_DEFAULTS_V1 = [
  // Claude / Anthropic
  "claude.ai", "claude.com", "anthropic.com", "api.anthropic.com", "console.anthropic.com", "docs.anthropic.com",
  // Google
  "google.com", "accounts.google.com", "apis.google.com", "gstatic.com", "ssl.gstatic.com", "fonts.gstatic.com",
  "googleapis.com", "fonts.googleapis.com", "googleusercontent.com", "lh3.googleusercontent.com", "ggpht.com",
  // YouTube
  "youtube.com", "youtu.be", "ytimg.com", "i.ytimg.com", "youtube-nocookie.com", "googlevideo.com",
  "youtubei.googleapis.com", "yt3.ggpht.com",
  // Facebook
  "facebook.com", "m.facebook.com", "graph.facebook.com", "connect.facebook.net", "facebook.net", "fb.com",
  "fbcdn.net", "static.xx.fbcdn.net", "fbsbx.com",
  // Instagram
  "instagram.com", "i.instagram.com", "graph.instagram.com", "cdninstagram.com", "scontent.cdninstagram.com"
];
// Второй набор: досеивается тем, у кого уже есть первый (удалённое вручную не возвращается).
const WHITELIST_DEFAULTS_V2 = [
  // ИИ-сервисы (часть сама не пускает российские IP)
  "openai.com", "chatgpt.com", "api.openai.com", "auth.openai.com", "cdn.oaistatic.com", "oaiusercontent.com",
  "gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com",
  "copilot.microsoft.com", "bing.com", "x.ai", "grok.com", "perplexity.ai",
  // X / Twitter
  "x.com", "twitter.com", "t.co", "twimg.com", "abs.twimg.com", "pbs.twimg.com", "video.twimg.com", "api.x.com",
  // Discord
  "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "cdn.discordapp.com", "media.discordapp.net",
  "gateway.discord.gg", "discord.media",
  // LinkedIn
  "linkedin.com", "licdn.com", "media.licdn.com", "static.licdn.com",
  // Twitch
  "twitch.tv", "ttvnw.net", "usher.ttvnw.net", "jtvnw.net", "static-cdn.jtvnw.net", "twitchcdn.net",
  // Мессенджеры: Signal, Viber, WhatsApp, Telegram (для клиента Telegram — его сети, он ходит по IP)
  "signal.org", "cdn.signal.org", "textsecure-service.whispersystems.org", "whispersystems.org", "viber.com",
  "whatsapp.com", "web.whatsapp.com", "whatsapp.net", "wa.me",
  "telegram.org", "web.telegram.org", "t.me", "telegram.me", "telegra.ph",
  "149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22",
  "91.108.56.0/22", "91.105.192.0/23", "185.76.151.0/24",
  // Музыка и видео
  "spotify.com", "open.spotify.com", "scdn.co", "spotifycdn.com",
  "netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net",
  // Прочее
  "speedtest.net", "ookla.com", "medium.com", "patreon.com", "patreonusercontent.com",
  "tinder.com", "gotinder.com", "pinterest.com", "pinimg.com",
  "reddit.com", "redd.it", "redditmedia.com", "redditstatic.com",
  "notion.so", "notion.com", "notion-static.com",
  "bbc.com", "bbc.co.uk", "bbci.co.uk", "dw.com", "rutracker.org"
];
// Третий набор: IP-диапазоны Google и Meta целиком. Агент маршрутизирует по IP, а эти сервисы отдают сотни
// меняющихся адресов — маршруты «по домену» пропускают часть (сайт то работает, то нет). Снимок от 2026-09-18:
// Google — официальный goog.json, Meta — префиксы AS32934 (RIPE). Обновляются при обновлении расширения.
const WHITELIST_DEFAULTS_V3 = [
  // Google (включая YouTube)
  "8.8.4.0/24", "8.8.8.0/24", "8.34.208.0/20", "8.35.192.0/20", "8.228.0.0/14", "8.232.0.0/14", "8.236.0.0/15",
  "23.236.48.0/20", "23.251.128.0/19", "34.0.0.0/15", "34.2.0.0/16", "34.3.0.0/23", "34.3.3.0/24", "34.3.4.0/24",
  "34.3.8.0/21", "34.3.16.0/20", "34.3.32.0/19", "34.3.64.0/18", "34.4.0.0/14", "34.8.0.0/13", "34.16.0.0/12",
  "34.32.0.0/11", "34.64.0.0/10", "34.128.0.0/10", "35.184.0.0/13", "35.192.0.0/14", "35.196.0.0/15",
  "35.198.0.0/16", "35.199.0.0/17", "35.199.128.0/18", "35.200.0.0/13", "35.208.0.0/12", "35.224.0.0/12",
  "35.240.0.0/13", "35.252.0.0/14", "64.15.112.0/20", "64.233.160.0/19", "66.102.0.0/20", "66.249.64.0/19",
  "70.32.128.0/19", "72.14.192.0/18", "74.114.24.0/21", "74.125.0.0/16", "104.154.0.0/15", "104.196.0.0/14",
  "104.237.160.0/19", "107.167.160.0/19", "107.178.192.0/18", "108.59.80.0/20", "108.170.192.0/18", "108.177.0.0/17",
  "130.211.0.0/16", "136.22.2.0/23", "136.22.4.0/23", "136.22.8.0/22", "136.22.160.0/20", "136.22.176.0/21",
  "136.22.184.0/23", "136.22.186.0/24", "136.23.39.0/24", "136.23.48.0/20", "136.23.64.0/18", "136.64.0.0/11",
  "136.107.0.0/16", "136.108.0.0/14", "136.112.0.0/13", "136.120.0.0/22", "136.121.8.0/21", "136.124.0.0/15",
  "142.250.0.0/15", "146.148.0.0/17", "152.238.0.0/16", "152.239.128.0/17", "162.120.128.0/17", "162.216.148.0/22",
  "162.222.176.0/21", "172.110.32.0/21", "172.217.0.0/16", "172.253.0.0/16", "173.194.0.0/16", "173.255.112.0/20",
  "177.176.0.0/16", "177.178.0.0/15", "177.208.0.0/15", "179.67.0.0/17", "179.69.128.0/17", "179.193.128.0/17",
  "179.199.0.0/17", "186.242.0.0/17", "186.245.0.0/16", "187.78.0.0/17", "187.79.0.0/17", "187.126.128.0/17",
  "189.24.128.0/17", "189.48.0.0/16", "189.49.128.0/17", "189.70.0.0/15", "189.82.0.0/15", "189.105.128.0/17",
  "189.106.0.0/15", "191.0.128.0/17", "191.2.0.0/15", "191.40.128.0/17", "191.44.128.0/17", "191.45.128.0/17",
  "191.46.0.0/15", "191.212.0.0/15", "191.216.128.0/17", "191.218.0.0/17", "191.220.0.0/15", "192.104.160.0/23",
  "192.158.28.0/22", "192.178.0.0/15", "193.186.4.0/24", "199.36.154.0/23", "199.36.156.0/24", "199.192.112.0/22",
  "199.223.232.0/21", "200.226.0.0/16", "207.175.0.0/16", "207.223.160.0/20", "208.65.152.0/22", "208.68.108.0/22",
  "208.81.188.0/22", "208.117.224.0/19", "209.85.128.0/17", "216.58.192.0/19", "216.73.80.0/20", "216.239.32.0/19",
  "216.252.220.0/22",
  // Meta (Facebook, Instagram, WhatsApp)
  "163.77.136.0/24", "57.144.214.0/23", "157.240.14.0/24", "57.144.110.0/23", "57.144.74.0/23", "57.144.148.0/23",
  "157.240.211.0/24", "31.13.83.0/24", "57.144.186.0/23", "157.240.5.0/24", "57.145.20.0/23", "129.134.29.0/24",
  "129.134.26.0/24", "31.13.66.0/24", "157.240.226.0/24", "57.144.152.0/23", "102.132.99.0/24", "69.171.224.0/19",
  "57.145.4.0/23", "163.70.131.0/24", "185.60.218.0/24", "69.63.176.0/21", "57.144.120.0/23", "173.252.64.0/19",
  "57.144.72.0/23", "57.144.38.0/23", "57.144.138.0/23", "31.13.91.0/24", "57.141.17.0/24", "57.141.0.0/24",
  "57.144.64.0/23", "57.144.202.0/23", "57.141.3.0/24", "57.144.92.0/23", "185.89.218.0/23", "57.144.16.0/23",
  "163.70.130.0/24", "57.144.238.0/23", "157.240.17.0/24", "57.144.50.0/23", "57.144.124.0/23", "57.144.244.0/23",
  "129.134.27.0/24", "57.145.2.0/23", "57.144.192.0/23", "129.134.31.0/24", "31.13.89.0/24", "157.240.209.0/24",
  "31.13.80.0/24", "66.220.152.0/21", "69.171.240.0/20", "57.144.204.0/23", "185.89.219.0/24", "185.60.216.0/22",
  "57.141.14.0/24", "163.77.132.0/23", "157.240.197.0/24", "69.171.224.0/20", "179.60.195.0/24", "31.13.82.0/24",
  "57.144.84.0/23", "163.70.128.0/17", "69.171.250.0/24", "57.145.8.0/23", "57.144.78.0/23", "157.240.253.0/24",
  "31.13.76.0/24", "57.144.104.0/23", "157.240.30.0/24", "57.144.228.0/23", "103.4.96.0/22", "57.144.116.0/23",
  "57.144.218.0/23", "57.144.162.0/23", "57.144.150.0/23", "57.144.42.0/23", "66.220.144.0/21", "57.144.206.0/23",
  "102.132.96.0/20", "157.240.234.0/24", "31.13.64.0/18", "31.13.71.0/24", "57.144.194.0/23", "157.240.26.0/24",
  "57.144.54.0/23", "57.144.210.0/23", "57.144.128.0/23", "157.240.215.0/24", "31.13.94.0/24", "129.134.26.0/23",
  "57.144.86.0/23", "57.141.6.0/24", "157.240.223.0/24", "57.141.12.0/24", "57.144.112.0/23", "57.144.20.0/23",
  "57.141.2.0/24", "157.240.192.0/18", "102.132.104.0/24", "157.240.24.0/24", "57.141.10.0/24", "57.144.144.0/23",
  "57.144.22.0/23", "57.145.6.0/23", "163.77.136.0/23", "185.60.217.0/24", "57.144.212.0/23", "57.144.70.0/23",
  "129.134.28.0/23", "157.240.200.0/24", "57.144.178.0/23", "57.144.160.0/23", "57.145.16.0/23", "69.63.184.0/21",
  "57.144.216.0/23", "157.240.241.0/24", "74.119.76.0/22", "157.240.3.0/24", "185.89.216.0/22", "157.240.244.0/24",
  "57.145.12.0/23", "157.240.254.0/24", "31.13.24.0/21", "57.141.24.0/24", "57.145.10.0/23", "57.144.62.0/23",
  "57.141.22.0/24", "57.144.136.0/23", "57.144.154.0/23", "57.144.80.0/23", "57.144.172.0/23", "69.63.176.0/20",
  "157.240.238.0/24", "157.240.12.0/24", "57.144.56.0/23", "204.15.20.0/22", "57.144.198.0/23", "57.144.98.0/23",
  "179.60.192.0/22", "157.240.212.0/24", "57.144.76.0/23", "157.240.29.0/24", "31.13.73.0/24", "57.144.8.0/23",
  "57.144.184.0/23", "129.134.24.0/23", "57.144.134.0/23", "57.144.254.0/23", "157.240.224.0/24", "157.240.0.0/24",
  "57.141.13.0/24", "185.89.218.0/24", "57.144.180.0/23", "157.240.15.0/24", "57.141.5.0/24", "157.240.27.0/24",
  "31.13.72.0/24", "57.144.18.0/23", "57.144.248.0/23", "57.144.126.0/23", "163.77.137.0/24", "57.144.252.0/23",
  "57.144.250.0/23", "157.240.25.0/24", "57.144.236.0/23", "57.144.14.0/23", "57.144.246.0/23", "57.141.16.0/24",
  "57.144.4.0/23", "173.252.88.0/21", "163.77.133.0/24", "129.134.25.0/24", "129.134.0.0/17", "31.13.69.0/24",
  "57.145.0.0/23", "129.134.30.0/23", "129.134.30.0/24", "31.13.84.0/24", "157.240.22.0/24", "31.13.87.0/24",
  "57.141.18.0/24", "157.240.0.0/17", "57.144.234.0/23", "57.144.182.0/23", "57.144.176.0/23", "173.252.96.0/19",
  "57.141.20.0/24", "57.144.142.0/23", "157.240.13.0/24", "57.144.222.0/23", "157.240.231.0/24", "163.70.151.0/24",
  "157.240.8.0/24", "45.64.40.0/22", "157.240.233.0/24", "57.144.96.0/23", "157.240.227.0/24", "57.141.19.0/24",
  "57.144.164.0/23", "157.240.196.0/24", "57.141.4.0/24", "163.70.144.0/24", "57.144.0.0/14", "57.144.132.0/23",
  "157.240.243.0/24", "57.144.114.0/23", "57.144.88.0/23", "157.240.210.0/24", "57.141.8.0/24", "31.13.64.0/24",
  "57.144.44.0/23", "31.13.86.0/24", "57.144.220.0/23", "157.240.203.0/24", "57.144.66.0/23", "57.144.196.0/23",
  "57.144.36.0/23", "31.13.96.0/19", "57.144.208.0/23", "163.77.132.0/24", "129.134.28.0/24", "57.144.100.0/23",
  "157.240.225.0/24", "66.220.144.0/20", "157.240.31.0/24", "57.144.140.0/23", "57.144.200.0/23", "57.144.24.0/23",
  "57.144.188.0/23", "157.240.9.0/24", "57.145.18.0/23", "157.240.11.0/24", "57.144.108.0/23", "57.144.68.0/23",
  "57.144.232.0/23", "157.240.205.0/24", "57.144.242.0/23", "57.144.102.0/23", "163.77.160.0/20", "163.77.160.0/24"
];
const WHITELIST_DEFAULTS = [...WHITELIST_DEFAULTS_V1, ...WHITELIST_DEFAULTS_V2, ...WHITELIST_DEFAULTS_V3];

function defaultList() {
  return {
    autoAdd: true,                  // автоматически добавлять неработающие сайты
    exceptions: DEFAULT_IGNORE.slice(), // никогда не добавлять автоматически
    entries: {},                    // ручные записи: key -> { key, addedAt }
    sites: {}                       // кандидаты: key -> { key, hits, firstSeen, lastSeen, lastError, errors, lastUrl, mainFrame, lastSuccess, status }
  };
}

// Расширение «чистое»: ничего не собрано и не добавлено (например, только что установлено под новым ID).
function isPristine(state) {
  return (
    // записи из стартового набора не в счёт — иначе «чистое» расширение перестало бы быть чистым
    MODES.every(
      (m) =>
        !Object.values(state.lists[m].entries).some((e) => !e.default) && !Object.keys(state.lists[m].sites).length
    ) &&
    !Object.keys(state.challenges || {}).length
  );
}

function defaultState() {
  return {
    version: 2,
    imported: false, // списки агента уже подтянуты в расширение (или расширение не «чистое»)
    settings: {
      enabled: true,
      mode: "blacklist",     // активный режим — именно он применяется агентом
      mainFrameOnly: true,   // считать только страницы, которые пользователь открывал сам
      minHits: 2,            // порог, после которого сайт считается «неработающим»
      groupByBaseDomain: true,
      detectChallenges: true, // (только blacklist) ловить страницы-заглушки VPN и выводить IP-диапазоны
      skipWhenVpnOff: true,   // (только blacklist) не собирать сайты, когда VPN выключен
      agentUrl: "http://127.0.0.1:35777"
    },
    lists: { blacklist: defaultList(), whitelist: defaultList() },
    challenges: {}, // host -> { host, count, firstSeen, lastSeen, url, title, signal, ranges:[], asns:[], status, confirmed }
    ripeCache: {}   // ip|ASxxx -> { v, ts }
  };
}

// Приводит сохранённое состояние к текущей схеме (в т.ч. из версии 1.0: sites/ignoreList/autoExport).
function normalizeState(raw) {
  const base = defaultState();
  const s = raw && typeof raw === "object" ? raw : {};
  const out = {
    ...base,
    ...s,
    settings: { ...base.settings, ...(s.settings || {}) },
    challenges: s.challenges || {},
    ripeCache: s.ripeCache || {}
  };
  out.lists = { blacklist: defaultList(), whitelist: defaultList() };
  if (s.lists) {
    for (const m of MODES) out.lists[m] = { ...defaultList(), ...(s.lists[m] || {}) };
  } else {
    // миграция с v1: всё накопленное — это чёрный список
    const old = s.settings || {};
    out.lists.blacklist.sites = s.sites || {};
    if (Array.isArray(old.ignoreList)) out.lists.blacklist.exceptions = old.ignoreList.slice();
    if (old.autoExport === false) out.lists.blacklist.autoAdd = false;
  }
  for (const m of MODES) {
    const L = out.lists[m];
    L.entries ||= {};
    L.sites ||= {};
    L.exceptions ||= [];
  }
  if (!MODES.includes(out.settings.mode)) out.settings.mode = "blacklist";
  const W = out.lists.whitelist;
  // seeded — какие имена набора уже добавлялись; так удалённое вручную не возвращается,
  // а новые записи набора досеиваются. Старый флаг defaultsSeeded означал «добавлен первый набор».
  const seeded = new Set(W.seeded || (W.defaultsSeeded ? WHITELIST_DEFAULTS_V1 : []));
  for (const d of WHITELIST_DEFAULTS) {
    if (seeded.has(d)) continue;
    if (!W.entries[d]) W.entries[d] = { key: d, addedAt: 0, default: true };
    seeded.add(d);
  }
  W.seeded = [...seeded];
  delete W.defaultsSeeded;
  // Есть данные (в т.ч. из v1) — подтягивать нечего. Иначе флаг остаётся как есть.
  out.imported = !!s.imported || !isPristine(out);
  delete out.sites;
  delete out.vpn;
  delete out.settings.ignoreList;
  delete out.settings.autoExport;
  out.version = 2;
  return out;
}

async function loadState() {
  const { state } = await chrome.storage.local.get("state");
  return normalizeState(state);
}

// ---- сериализованный доступ к storage ----
let writeChain = Promise.resolve();
function updateStore(mutator) {
  writeChain = writeChain
    .then(async () => {
      const s = await loadState();
      await mutator(s);
      await chrome.storage.local.set({ state: s });
      await refreshBadge(s);
      scheduleSync(s);
    })
    .catch((e) => console.error("[VPN Bypass Collector]", e));
  return writeChain;
}

// ---- вычисление списков ----
const isIp = (s) => /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(s);

function normalizeEntry(text) {
  let d = String(text || "").toLowerCase().trim();
  if (isIp(d)) return d;
  d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, "").replace(/^www\./, "").replace(/[/:?#].*$/, "");
  if (isIp(d)) return d;
  return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d) ? d : null;
}

function isExcepted(key, exceptions) {
  return (exceptions || []).some((d) => key === d || key.endsWith("." + d));
}

function isCandidateReady(site, min) {
  return site.status !== "resolved" && site.status !== "ignored" && site.hits >= min;
}

// Итоговый список записей для агента по режиму.
function computeList(state, mode) {
  const L = state.lists[mode];
  const min = state.settings.minHits || 1;
  const set = new Set(Object.keys(L.entries));
  if (L.autoAdd) {
    for (const s of Object.values(L.sites)) {
      if (isCandidateReady(s, min) && !isExcepted(s.key, L.exceptions)) set.add(s.key);
    }
  }
  if (mode === "blacklist") {
    for (const c of Object.values(state.challenges || {})) {
      if (c.status === "ignored") continue;
      if (!(L.autoAdd || c.confirmed)) continue;
      set.add(c.host);
      for (const r of c.ranges || []) set.add(r);
    }
  }
  return [...set].sort();
}

function hashStr(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16);
}

function currentSig(state) {
  return hashStr(
    state.settings.mode + "|" + computeList(state, "blacklist").join(",") + "|" + computeList(state, "whitelist").join(",")
  );
}

// ---- агент: состояние связи (отдельный ключ storage, чтобы не гонять updateStore) ----
let agentChain = Promise.resolve();
function patchAgent(patch) {
  agentChain = agentChain
    .then(async () => {
      const { agent } = await chrome.storage.local.get("agent");
      const next = { reachable: false, failStreak: 0, ...(agent || {}), ...(typeof patch === "function" ? patch(agent || {}) : patch) };
      await chrome.storage.local.set({ agent: next });
    })
    .catch((e) => console.error("[VPN Bypass Collector]", e));
  return agentChain;
}
async function getAgent() {
  const { agent } = await chrome.storage.local.get("agent");
  return agent || { reachable: false, failStreak: 0 };
}

function agentBase(state) {
  return (state.settings && state.settings.agentUrl) || "http://127.0.0.1:35777";
}

// 'on' | 'off' | 'unknown' — по свежему (< 5 мин) ответу агента.
function vpnState(agent) {
  const st = agent && agent.status;
  if (!st || !agent.lastOkAt || Date.now() - agent.lastOkAt > 5 * 60 * 1000) return "unknown";
  return st.vpnUp ? "on" : "off";
}

// ---- отправка списков агенту ----
// «Чистое» расширение не должно затирать список агента пустым: сначала забираем то, что у агента уже есть.
async function importFromAgent(state) {
  try {
    const got = {};
    for (const m of MODES) {
      const r = await fetch(agentBase(state) + "/list?mode=" + m + "&fileOnly=1", { signal: AbortSignal.timeout(8000) });
      if (!r.ok) throw new Error("HTTP " + r.status);
      got[m] = (await r.json()).entries || [];
    }
    await updateStore((s) => {
      for (const m of MODES) {
        for (const e of got[m]) {
          const key = normalizeEntry(e);
          if (key) s.lists[m].entries[key] = { key, addedAt: Date.now() };
        }
      }
      s.imported = true;
    });
    return true;
  } catch (e) {
    console.warn("[VPN Bypass Collector] не удалось прочитать списки агента:", e.message);
    return false;
  }
}

let syncing = null;
// Отправить оба списка и активный режим; агент применяет и возвращает итог. Ждёт применения.
function syncAgent(state) {
  if (syncing) return syncing;
  syncing = (async () => {
    if (!state.imported) {
      if (!(await importFromAgent(state))) {
        return { ok: false, error: "не удалось прочитать список агента — отправка отложена, чтобы его не затереть" };
      }
      state = await loadState();
    }
    const body = {
      mode: state.settings.mode,
      blacklist: computeList(state, "blacklist"),
      whitelist: computeList(state, "whitelist"),
      sig: currentSig(state)
    };
    try {
      const r = await fetch(agentBase(state) + "/apply", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(60000)
      });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const j = await r.json();
      await patchAgent({
        reachable: true,
        failStreak: 0,
        lastOkAt: Date.now(),
        sync: {
          ok: !!j.ok,
          at: Date.now(),
          sig: body.sig,
          error: j.ok ? null : (j.summary && j.summary.error) || "агент не смог применить список",
          summary: j.summary || null
        }
      });
      return { ok: !!j.ok, summary: j.summary || null, error: j.ok ? null : j.summary && j.summary.error };
    } catch (e) {
      console.warn("[VPN Bypass Collector] agent /apply недоступен:", e.message);
      await patchAgent({ sync: { ok: false, at: Date.now(), sig: body.sig, error: e.message, summary: null } });
      return { ok: false, error: e.message };
    } finally {
      syncing = null;
    }
  })();
  return syncing;
}

// Ручной экспорт в файл (для другого VPN / Proxifier) — список активного режима.
async function downloadList(state) {
  const mode = state.settings.mode;
  const list = computeList(state, mode);
  const body =
    "# vpn-bypass-collector (" + mode + ") — " + new Date().toISOString() + "\n" + list.join("\n") + "\n";
  const url = "data:text/plain;charset=utf-8," + encodeURIComponent(body);
  await chrome.downloads.download({ url, filename: "vpn-bypass-" + mode + ".txt", saveAs: true });
  return list.length;
}

let lastSyncSig = null;
let lastSyncAt = 0;
function scheduleSync(state) {
  const sig = currentSig(state);
  if (sig === lastSyncSig) return; // ничего не менялось — не дёргать агента
  lastSyncSig = sig;
  chrome.alarms.create("sync", { delayInMinutes: 0.05 });
}

// ---- статус VPN и применения от агента ----
let polling = null;
function pollAgentStatus() {
  if (polling) return polling;
  polling = (async () => {
    const state = await loadState();
    try {
      const r = await fetch(agentBase(state) + "/status", { signal: AbortSignal.timeout(8000) });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const v = await r.json();
      await patchAgent({ reachable: true, failStreak: 0, lastOkAt: Date.now(), fetchedAt: Date.now(), status: v });
      // Агент запущен заново или рассинхронизирован с расширением — отправить списки.
      if (v.sig !== currentSig(state) && Date.now() - lastSyncAt > 30000) {
        lastSyncAt = Date.now();
        syncAgent(state);
      }
    } catch (e) {
      // Один сбой — ещё не «агент не отвечает»: показываем последние данные и считаем неудачи подряд.
      await patchAgent((a) => ({
        failStreak: (a.failStreak || 0) + 1,
        fetchedAt: Date.now(),
        reachable: (a.failStreak || 0) + 1 < 3
      }));
    }
  })().finally(() => (polling = null));
  return polling;
}

// ---- детектор страниц-заглушек VPN → вывод IP-диапазонов для агента ----
const DOH = "https://dns.google/resolve";
const RIPE_NETINFO = "https://stat.ripe.net/data/network-info/data.json";
const RIPE_ANN = "https://stat.ripe.net/data/announced-prefixes/data.json";
const RIPE_TTL = 7 * 24 * 3600 * 1000;

// ASN, которые нельзя расширять целиком (общий хостинг/CDN) — для них берём /24.
const CLOUD_ASNS = new Set([
  13335, 16509, 14618, 8987, 15169, 396982, 8075, 8068, 8069, 16276, 24940,
  14061, 20473, 63949, 54113, 13238, 202015, 200350, 13335, 209242, 132892,
  14907, 32934, 54994, 19551, 20940, 16625, 12222
]);
const MAX_ASN_ADDR = 262144; // ~/14 суммарно
const MAX_ASN_PREFIXES = 80;
const MIN_PREFIX_LEN = 16; // никогда не добавлять шире /16

async function jget(url, params) {
  const u = new URL(url);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  const r = await fetch(u, { credentials: "omit" });
  if (!r.ok) throw new Error(url + " -> " + r.status);
  return r.json();
}

async function cached(state, key, fn) {
  const hit = state.ripeCache[key];
  if (hit && Date.now() - hit.ts < RIPE_TTL) return hit.v;
  const v = await fn();
  await updateStore((s) => {
    s.ripeCache[key] = { v, ts: Date.now() };
  });
  return v;
}

async function dohA(name) {
  try {
    const j = await jget(DOH, { name, type: "A" });
    return (j.Answer || []).filter((a) => a.type === 1).map((a) => a.data);
  } catch {
    return [];
  }
}
const ipSlash24 = (ip) => ip.split(".").slice(0, 3).join(".") + ".0/24";
const prefLen = (c) => +c.split("/")[1];
const prefSize = (c) => 2 ** (32 - prefLen(c));

async function deriveRanges(host) {
  const state = await loadState();
  const base = baseDomain(host.replace(/^www\./, ""));
  const names = new Set([host, base, "www." + base]);
  const ips = new Set();
  for (const n of names) for (const ip of await dohA(n)) ips.add(ip);
  if (!ips.size) return { ranges: [], asns: [] };

  const out = new Set();
  const asns = new Set();
  for (const ip of ips) {
    let info;
    try {
      info = await cached(state, ip, async () => {
        const j = await jget(RIPE_NETINFO, { resource: ip });
        return { prefix: j.data.prefix, asns: (j.data.asns || []).map(Number) };
      });
    } catch {
      out.add(ipSlash24(ip));
      continue;
    }
    const asn = info.asns[0];
    const safePrefix =
      info.prefix && prefLen(info.prefix) >= MIN_PREFIX_LEN ? info.prefix : ipSlash24(ip);
    if (!asn || CLOUD_ASNS.has(asn)) {
      out.add(safePrefix);
      continue;
    }
    if (asns.has(asn)) continue;
    asns.add(asn);
    let prefixes = [];
    try {
      prefixes = await cached(state, "AS" + asn, async () => {
        const j = await jget(RIPE_ANN, { resource: "AS" + asn });
        return (j.data.prefixes || []).map((p) => p.prefix).filter((p) => p.includes("."));
      });
    } catch {}
    const total = prefixes.reduce((s, p) => s + prefSize(p), 0);
    const expandAll =
      prefixes.length &&
      prefixes.length <= MAX_ASN_PREFIXES &&
      total <= MAX_ASN_ADDR &&
      prefixes.every((p) => prefLen(p) >= MIN_PREFIX_LEN);
    if (expandAll) prefixes.forEach((p) => out.add(p));
    else out.add(safePrefix);
  }
  return { ranges: [...out].sort(), asns: [...asns] };
}

async function runDerive() {
  const state = await loadState();
  for (const host of Object.keys(state.challenges)) {
    const c = state.challenges[host];
    if (c.status === "ignored") continue;
    if (c.status === "applied" && c.ranges && c.ranges.length) continue;
    const { ranges, asns } = await deriveRanges(host);
    await updateStore((s) => {
      const cc = s.challenges[host];
      if (!cc) return;
      cc.ranges = ranges;
      cc.asns = asns;
      cc.status = ranges.length ? "applied" : "new";
    });
  }
}

chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name === "sync") {
    lastSyncAt = Date.now();
    await syncAgent(await loadState());
  } else if (a.name === "derive") {
    await runDerive();
  } else if (a.name === "vpnpoll") {
    await pollAgentStatus();
  }
});
chrome.alarms.create("vpnpoll", { periodInMinutes: 1 });
pollAgentStatus();

function baseDomain(hostname) {
  const parts = hostname.split(".").filter(Boolean);
  if (parts.length <= 2) return hostname;
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_TLD.has(lastTwo)) return parts.slice(-3).join(".");
  return lastTwo;
}

function toKey(hostname, groupByBaseDomain) {
  let h = hostname.toLowerCase().replace(/^www\./, "");
  return groupByBaseDomain ? baseDomain(h) : h;
}

async function refreshBadge(state) {
  const L = state.lists[state.settings.mode];
  const now = Object.values(L.sites).filter(
    (x) => x.status === "new" && x.hits >= (state.settings.minHits || 1)
  ).length;
  try {
    await chrome.action.setBadgeText({ text: now ? String(now) : "" });
    await chrome.action.setBadgeBackgroundColor({ color: "#c0392b" });
  } catch (_) {}
}

// Открывается ли сайт вообще. no-cors: любой HTTP-ответ (200, 403, страница-заглушка) — это «открывается»;
// ошибкой считаются только сетевые сбои (сброс, таймаут, DNS).
async function probeReachable(host) {
  const tries = ["https", "http"].map((scheme) =>
    fetch(`${scheme}://${host}/`, {
      mode: "no-cors",
      cache: "no-store",
      credentials: "omit",
      signal: AbortSignal.timeout(7000)
    }).then(() => true)
  );
  try {
    return await Promise.any(tries); // достаточно, чтобы ответил хотя бы один из двух
  } catch (_) {
    return false;
  }
}

// Пометить хост как «блокирует VPN» и запустить вывод IP-диапазонов.
async function markVpnBlock(host) {
  await updateStore(async (state) => {
    const c = state.challenges[host] || {
      host, count: 0, firstSeen: Date.now(), ranges: [], asns: [], status: "new"
    };
    c.count += 1;
    c.lastSeen = Date.now();
    c.signal = "добавлен вручную: сайт открывается";
    c.status = "new";
    c.confirmed = true; // добавлен руками — в список без ожидания автодобавления
    state.challenges[host] = c;
  });
  chrome.alarms.create("derive", { delayInMinutes: 0.02 });
}

// Запись списка покрывает сайт: тот же домен или его поддомен.
function covers(entry, key) {
  return key === entry || key.endsWith("." + entry);
}

async function recordFailure({ url, error, isMainFrame }) {
  let host;
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return;
    host = u.hostname;
  } catch (_) {
    return;
  }
  if (!host || !BLOCKING_ERRORS.has(error)) return;

  const vpn = vpnState(await getAgent());

  await updateStore(async (state) => {
    if (!state.settings.enabled) return;
    if (state.settings.mainFrameOnly && !isMainFrame) return;

    const mode = state.settings.mode;
    const L = state.lists[mode];
    const key = toKey(host, state.settings.groupByBaseDomain);
    if (L.autoAdd && isExcepted(key, L.exceptions)) return;

    if (mode === "blacklist") {
      // VPN выключен, а сайт всё равно не грузится — проблема не в VPN.
      if (state.settings.skipWhenVpnOff && vpn === "off") {
        if (L.sites[key]) {
          delete L.sites[key];
          if (!L.exceptions.includes(key)) L.exceptions.push(key);
        }
        return;
      }
    } else {
      // whitelist: сайт уже идёт через VPN и всё равно не грузится — VPN тут не поможет.
      if (vpn === "on" && computeList(state, "whitelist").some((e) => covers(e, key))) return;
    }

    const ts = Date.now();
    const site = L.sites[key] || {
      key,
      hits: 0,
      firstSeen: ts,
      lastSeen: ts,
      errors: {},
      lastError: error,
      lastUrl: url,
      mainFrame: false,
      lastSuccess: 0,
      status: "new"
    };
    site.hits += 1;
    site.lastSeen = ts;
    site.lastError = error;
    site.lastUrl = url;
    site.mainFrame = site.mainFrame || isMainFrame;
    site.errors[error] = (site.errors[error] || 0) + 1;
    if (site.status === "resolved") site.status = "new"; // снова упал — вернуть в список
    L.sites[key] = site;
  });
}

async function recordSuccess(url) {
  let host;
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return;
    host = u.hostname;
  } catch (_) {
    return;
  }
  await updateStore(async (state) => {
    // Только blacklist: там успешное открытие после ошибки означает «обход сработал».
    // В whitelist успех после ошибки — это как раз работа VPN, кандидата из списка убирать нельзя.
    if (state.settings.mode !== "blacklist") return;
    const L = state.lists.blacklist;
    const key = toKey(host, state.settings.groupByBaseDomain);
    const site = L.sites[key];
    if (!site) return;
    site.lastSuccess = Date.now();
    // Если после последней ошибки страница успешно открылась — пометить как «возможно решено».
    if (site.lastSuccess > site.lastSeen && site.status === "new") {
      site.status = "resolved";
    }
  });
}

// ---- слушатели ----
chrome.webNavigation.onErrorOccurred.addListener((d) => {
  recordFailure({ url: d.url, error: d.error, isMainFrame: d.frameId === 0 });
});

chrome.webNavigation.onCompleted.addListener((d) => {
  if (d.frameId === 0) recordSuccess(d.url);
});

chrome.webRequest.onErrorOccurred.addListener(
  (d) => {
    recordFailure({
      url: d.url,
      error: d.error,
      isMainFrame: d.type === "main_frame"
    });
  },
  { urls: ["<all_urls>"] }
);

chrome.runtime.onInstalled.addListener(async () => {
  // Записать нормализованное (и при обновлении — мигрированное) состояние.
  await chrome.storage.local.set({ state: await loadState() });
});

// ---- сообщения от popup ----
const okList = (msg) => (MODES.includes(msg.list) ? msg.list : null);

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    if (msg.type === "getState") {
      const state = await loadState();
      sendResponse({ ...state, agent: await getAgent(), sig: currentSig(state), lists_computed: {
        blacklist: computeList(state, "blacklist"),
        whitelist: computeList(state, "whitelist")
      } });
      return;
    }
    // Принудительно: отправить списки и дождаться, пока агент их применит.
    if (msg.type === "forceSync") {
      const state = await loadState();
      lastSyncAt = Date.now();
      sendResponse(await syncAgent(state));
      return;
    }
    // Резервная копия / перенос: всё состояние расширения одним файлом.
    if (msg.type === "exportState") {
      const state = await loadState();
      delete state.ripeCache;
      sendResponse({ ok: true, state });
      return;
    }
    if (msg.type === "importState") {
      const raw = msg.state;
      if (!raw || typeof raw !== "object" || !raw.settings || !(raw.lists || raw.sites)) {
        return sendResponse({ ok: false, error: "это не файл состояния расширения" });
      }
      const next = normalizeState(raw); // понимает и формат v1
      next.imported = true;
      await updateStore((s) => {
        for (const k of Object.keys(s)) delete s[k];
        Object.assign(s, next);
      });
      const n = MODES.reduce((a, m) => a + Object.keys(next.lists[m].sites).length + Object.keys(next.lists[m].entries).length, 0);
      sendResponse({ ok: true, count: n, challenges: Object.keys(next.challenges).length });
      return;
    }
    if (msg.type === "downloadList") {
      const n = await downloadList(await loadState());
      sendResponse({ ok: true, count: n });
      return;
    }
    if (msg.type === "vpnStatus") {
      await pollAgentStatus();
      sendResponse(await getAgent());
      return;
    }
    if (msg.type === "vpnControl") {
      const state = await loadState();
      try {
        const r = await fetch(agentBase(state) + "/vpn", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ action: msg.action }),
          signal: AbortSignal.timeout(30000)
        });
        const j = await r.json();
        setTimeout(pollAgentStatus, 3000);
        sendResponse(j);
      } catch (e) {
        sendResponse({ ok: false, error: e.message });
      }
      return;
    }
    if (msg.type === "setMode") {
      if (!MODES.includes(msg.mode)) return sendResponse({ ok: false });
      await updateStore((state) => {
        state.settings.mode = msg.mode;
      });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "setListSettings") {
      const list = okList(msg);
      if (!list) return sendResponse({ ok: false });
      await updateStore((state) => {
        if (typeof msg.autoAdd === "boolean") state.lists[list].autoAdd = msg.autoAdd;
      });
      sendResponse({ ok: true });
      return;
    }
    // Ручная запись в список (домен, IP или IP/CIDR). Исключения на неё не действуют.
    if (msg.type === "addEntry") {
      const list = okList(msg);
      const key = normalizeEntry(msg.value);
      if (!list || !key) return sendResponse({ ok: false, error: "не похоже на домен или IP" });
      await updateStore((state) => {
        const L = state.lists[list];
        L.entries[key] = { key, addedAt: Date.now() };
        delete L.sites[key]; // кандидат стал ручной записью
      });
      sendResponse({ ok: true, key });
      return;
    }
    // «+ текущий сайт». Чёрный список при включённом VPN: если сайт при этом открывается — значит,
    // он не сломан, а блокирует VPN (заглушка) → помечаем и выводим IP-диапазоны. Иначе — обычная запись.
    if (msg.type === "addCurrentSite") {
      const list = okList(msg);
      const key = normalizeEntry(msg.host);
      if (!list || !key || isIp(key)) return sendResponse({ ok: false, error: "нет подходящего сайта во вкладке" });
      if (list === "blacklist") {
        const vpn = vpnState(await getAgent());
        if (vpn === "off") {
          await updateStore((s) => {
            s.lists.blacklist.entries[key] = { key, addedAt: Date.now() };
            delete s.lists.blacklist.sites[key];
          });
          return sendResponse({ ok: true, key, kind: "domain", reason: "vpn-off" });
        }
        if (await probeReachable(key)) {
          await markVpnBlock(key);
          return sendResponse({ ok: true, key, kind: "vpn-block", reason: "reachable" });
        }
      }
      await updateStore((s) => {
        s.lists[list].entries[key] = { key, addedAt: Date.now() };
        delete s.lists[list].sites[key];
      });
      sendResponse({ ok: true, key, kind: "domain", reason: list === "blacklist" ? "unreachable" : "whitelist" });
      return;
    }
    // IP-адреса записей (резолвит агент тем же DNS, что и для маршрутов).
    if (msg.type === "resolveIps") {
      const state = await loadState();
      try {
        const r = await fetch(agentBase(state) + "/resolve", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ names: msg.names || [] }),
          signal: AbortSignal.timeout(20000)
        });
        if (!r.ok) throw new Error("HTTP " + r.status);
        sendResponse(await r.json());
      } catch (e) {
        sendResponse({ ok: false, error: e.message });
      }
      return;
    }
    if (msg.type === "removeEntry") {
      const list = okList(msg);
      if (!list) return sendResponse({ ok: false });
      await updateStore((state) => {
        delete state.lists[list].entries[msg.key];
      });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "removeEntries") {
      const list = okList(msg);
      if (!list || !Array.isArray(msg.keys)) return sendResponse({ ok: false });
      await updateStore((state) => {
        for (const k of msg.keys) delete state.lists[list].entries[k];
      });
      sendResponse({ ok: true });
      return;
    }
    // Кандидат → ручная запись («в список»).
    if (msg.type === "promoteSite") {
      const list = okList(msg);
      if (!list) return sendResponse({ ok: false });
      await updateStore((state) => {
        const L = state.lists[list];
        L.entries[msg.key] = { key: msg.key, addedAt: Date.now() };
        delete L.sites[msg.key];
      });
      sendResponse({ ok: true });
      return;
    }
    // Кандидат → исключение (никогда не добавлять автоматически).
    if (msg.type === "ignoreKey") {
      const list = okList(msg);
      if (!list) return sendResponse({ ok: false });
      await updateStore((state) => {
        const L = state.lists[list];
        if (!L.exceptions.includes(msg.key)) L.exceptions.push(msg.key);
        delete L.sites[msg.key];
      });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "removeKey") {
      const list = okList(msg);
      if (!list) return sendResponse({ ok: false });
      await updateStore((state) => {
        delete state.lists[list].sites[msg.key];
      });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "addException") {
      const list = okList(msg);
      const d = normalizeEntry(msg.domain);
      if (!list || !d) return sendResponse({ ok: false, error: "не похоже на домен или IP" });
      await updateStore((state) => {
        const L = state.lists[list];
        if (!L.exceptions.includes(d)) L.exceptions.push(d);
        for (const k of Object.keys(L.sites)) if (covers(d, k)) delete L.sites[k];
        if (list === "blacklist") {
          for (const h of Object.keys(state.challenges)) {
            if (covers(d, h)) state.challenges[h].status = "ignored";
          }
        }
      });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "removeException") {
      const list = okList(msg);
      if (!list) return sendResponse({ ok: false });
      await updateStore((state) => {
        const L = state.lists[list];
        L.exceptions = L.exceptions.filter((x) => x !== msg.domain);
      });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "challengeDetected") {
      const host = (msg.host || "").toLowerCase().replace(/^www\./, "");
      if (!host || !host.includes(".")) {
        sendResponse({ ok: false });
        return;
      }
      let willDerive = false;
      const vpn = vpnState(await getAgent());
      await updateStore(async (state) => {
        // Заглушка «отключите VPN» имеет смысл только в режиме «чёрный список».
        if (state.settings.mode !== "blacklist" || !state.settings.detectChallenges) return;
        const L = state.lists.blacklist;
        const c = state.challenges[host] || {
          host,
          count: 0,
          firstSeen: Date.now(),
          ranges: [],
          asns: [],
          status: "new"
        };
        c.count += 1;
        c.lastSeen = Date.now();
        c.url = msg.url;
        c.title = msg.title;
        c.signal = msg.signal;
        if (L.autoAdd && isExcepted(host, L.exceptions)) c.status = "ignored";
        // Заглушка показана при выключенном VPN — сайт блокирует и без VPN, обход не поможет.
        if (state.settings.skipWhenVpnOff && vpn === "off") {
          c.status = "ignored";
          c.signal = (c.signal || "") + " (VPN был выключен)";
          if (!L.exceptions.includes(host)) L.exceptions.push(host);
        }
        state.challenges[host] = c;
        willDerive = c.status !== "ignored" && !(c.status === "applied" && c.ranges.length);
      });
      if (willDerive) chrome.alarms.create("derive", { delayInMinutes: 0.02 });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "confirmChallenge") {
      await updateStore(async (state) => {
        const c = state.challenges[msg.host];
        if (c) c.confirmed = true;
      });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "rederiveChallenge") {
      await updateStore(async (state) => {
        const c = state.challenges[msg.host];
        if (c) {
          c.status = "new";
          c.ranges = [];
        }
      });
      chrome.alarms.create("derive", { delayInMinutes: 0.02 });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "ignoreChallenge") {
      await updateStore(async (state) => {
        const c = state.challenges[msg.host];
        if (c) c.status = "ignored";
      });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "removeChallenge") {
      await updateStore(async (state) => {
        delete state.challenges[msg.host];
      });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "setSettings") {
      await updateStore(async (state) => {
        Object.assign(state.settings, msg.settings);
      });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "clearAll") {
      const list = okList(msg);
      if (!list) return sendResponse({ ok: false });
      await updateStore(async (state) => {
        state.lists[list].sites = {};
        if (msg.challengesToo && list === "blacklist") state.challenges = {};
      });
      sendResponse({ ok: true });
      return;
    }
  })();
  return true; // async
});
