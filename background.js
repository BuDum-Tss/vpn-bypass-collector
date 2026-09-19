// VPN Bypass Collector — service worker.
// Два списка (оба всегда действуют): «через VPN» и «мимо VPN». Каждый новый сайт проверяется агентом в обоих
// путях (открывается ли напрямую, открывается ли через VPN) и попадает в один из списков; путь для остального
// — VPN по умолчанию, российские сети агент пускает напрямую сам.

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

// Стартовый набор списка «через VPN» (сервисы, которые обычно нужны через VPN). Добавляется один раз;
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

// ============================================================================================
// Модель (версия 3): ДВА списка, оба всегда действуют.
//   vpn    — сайты, которые должны открываться ЧЕРЕЗ VPN;
//   direct — сайты, которые должны открываться МИМО VPN.
// Путь для всего остального (settings.defaultPath) — "vpn": так безопаснее (замедление, скрытое от ошибок,
// не ловится, а российские сети агент и так пускает напрямую).
// Каждый новый сайт проверяется агентом в обоих путях и попадает в один из списков (classify).
// ============================================================================================

const KINDS = ["vpn", "direct"];
const OTHER = { vpn: "direct", direct: "vpn" };

function defaultState() {
  return {
    version: 3,
    imported: false, // списки агента уже подтянуты в расширение (или расширение не «чистое»)
    settings: {
      enabled: true,
      autoCheck: true,        // проверять каждый новый сайт и раскладывать по спискам
      defaultPath: "vpn",     // путь для сайтов вне списков (рекомендуется vpn)
      groupByBaseDomain: true,
      agentUrl: "http://127.0.0.1:35777"
    },
    lists: { vpn: { entries: {}, seeded: [] }, direct: { entries: {} } },
    ignore: DEFAULT_IGNORE.slice(), // домены, которые никогда не проверяются автоматически
    queue: {},        // key -> { key, addedAt, nextAt, tries, reason } — ждут проверки
    unreachable: {},  // key -> { key, at, tries, nextAt, d, v } — не открылись ни напрямую, ни через VPN
    challenges: {},   // host -> { host, ranges, asns, status, ... } — IP-диапазоны сайтов, блокирующих VPN
    ripeCache: {}
  };
}

// Расширение «чистое»: ничего не собрано и не добавлено (например, только что установлено под новым ID).
function isPristine(state) {
  return (
    KINDS.every((k) => !Object.values(state.lists[k].entries).some((e) => !e.default)) &&
    !Object.keys(state.challenges || {}).length &&
    !Object.keys(state.queue || {}).length
  );
}

const isExcepted = (key, list) => (list || []).some((d) => key === d || key.endsWith("." + d));

// Приводит любое сохранённое состояние (v1, v2, v3) к текущей схеме.
function normalizeState(raw) {
  const base = defaultState();
  const s = raw && typeof raw === "object" ? raw : {};
  const out = { ...base, settings: { ...base.settings }, ripeCache: s.ripeCache || {}, challenges: s.challenges || {} };

  if (s.version >= 3 && s.lists && s.lists.vpn) {
    Object.assign(out.settings, s.settings || {});
    out.imported = !!s.imported;
    for (const k of KINDS) out.lists[k] = { ...out.lists[k], ...(s.lists[k] || {}) };
    out.ignore = Array.isArray(s.ignore) ? s.ignore : out.ignore;
    out.queue = s.queue || {};
    out.unreachable = s.unreachable || {};
  } else {
    // ---- миграция с v1/v2: «чёрный» список (обход VPN) → direct, «белый» (только через VPN) → vpn ----
    const old = s.settings || {};
    Object.assign(out.settings, {
      enabled: old.enabled !== false,
      groupByBaseDomain: old.groupByBaseDomain !== false,
      agentUrl: old.agentUrl || out.settings.agentUrl
    });
    const bl = (s.lists && s.lists.blacklist) || {
      entries: {}, sites: s.sites || {}, exceptions: old.ignoreList || [], autoAdd: old.autoExport !== false
    };
    const wl = (s.lists && s.lists.whitelist) || { entries: {}, sites: {}, exceptions: [], autoAdd: true };
    const min = old.minHits || 1;
    const auto = (L) =>
      L.autoAdd === false
        ? []
        : Object.values(L.sites || {}).filter(
            (x) => x.status !== "resolved" && x.status !== "ignored" && x.hits >= min && !isExcepted(x.key, L.exceptions)
          );
    const put = (kind, key, e) => (out.lists[kind].entries[key] = { key, addedAt: e.addedAt || 0, source: e.default ? "default" : e.source || "manual", ...(e.default ? { default: true } : {}) });
    for (const [k, e] of Object.entries(bl.entries || {})) put("direct", k, e);
    for (const x of auto(bl)) put("direct", x.key, { source: "auto", addedAt: x.firstSeen });
    for (const [k, e] of Object.entries(wl.entries || {})) put("vpn", k, e);
    for (const x of auto(wl)) put("vpn", x.key, { source: "auto", addedAt: x.firstSeen });
    // заглушки VPN: сайт открывается, но блокирует VPN → он в списке «мимо VPN»
    for (const c of Object.values(out.challenges)) {
      if (c.status === "ignored") continue;
      if (bl.autoAdd !== false || c.confirmed) put("direct", c.host, { source: "stub", addedAt: c.firstSeen });
    }
    out.ignore = [...new Set([...(bl.exceptions || []), ...(wl.exceptions || []), ...DEFAULT_IGNORE])];
    out.lists.vpn.seeded = wl.seeded || (wl.defaultsSeeded ? WHITELIST_DEFAULTS_V1.slice() : []);
    // Сайт сразу в обоих списках (например, youtube.com в «мимо VPN» и в «через VPN») — какой из них верный,
    // покажет проверка: убираем из обоих и ставим в очередь на проверку.
    for (const key of Object.keys(out.lists.direct.entries)) {
      if (!out.lists.vpn.entries[key]) continue;
      const wasDefault = !!out.lists.vpn.entries[key].default;
      delete out.lists.direct.entries[key];
      delete out.lists.vpn.entries[key];
      out.queue[key] = { key, addedAt: Date.now(), nextAt: 0, tries: 0, reason: "conflict" };
      if (wasDefault) out.lists.vpn.seeded = out.lists.vpn.seeded.filter((x) => x !== key); // не досеивать заново
    }
  }
  for (const k of KINDS) out.lists[k].entries ||= {};
  // Стартовый набор «через VPN»: seeded — какие имена уже добавлялись, чтобы удалённое не возвращалось.
  const seeded = new Set(out.lists.vpn.seeded || []);
  for (const d of WHITELIST_DEFAULTS) {
    if (seeded.has(d)) continue;
    if (!out.lists.vpn.entries[d] && !out.lists.direct.entries[d] && !out.queue[d]) {
      out.lists.vpn.entries[d] = { key: d, addedAt: 0, source: "default", default: true };
    }
    seeded.add(d);
  }
  out.lists.vpn.seeded = [...seeded];
  if (s.version >= 3) out.imported = !!s.imported || !isPristine(out);
  else out.imported = !isPristine(out);
  if (!["vpn", "direct"].includes(out.settings.defaultPath)) out.settings.defaultPath = "vpn";
  out.version = 3;
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

// Запись списка покрывает сайт: тот же домен или его поддомен.
const covers = (entry, key) => key === entry || key.endsWith("." + entry);

// Записи со «работает везде» агенту не отправляются: маршрут им не нужен, а в широком диапазоне «мимо VPN» он
// только вытолкнул бы российский сайт в VPN.
function computeList(state, kind) {
  const set = new Set();
  for (const [k, e] of Object.entries(state.lists[kind].entries)) if (!e.both) set.add(k);
  if (kind === "direct") {
    for (const c of Object.values(state.challenges || {})) {
      if (c.status === "ignored") continue;
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
  return hashStr(state.settings.defaultPath + "|" + computeList(state, "direct").join(",") + "|" + computeList(state, "vpn").join(","));
}

// ---- решение: в какой список? По замерам агента для двух путей. ----
// Оценка пути: 2 — открывается нормально, 1 — открывается, но плохо (проверка браузера или медленно),
// 0 — не открывается / заглушка «отключите VPN» / блокировка по закону, null — путь не проверяли.
function pathScore(p) {
  if (!p || p.skipped) return null;
  if (!p.reached || p.stub || p.blocked451) return 0;
  if (p.challenge) return 1;
  if ((p.kbps != null && p.kbps < 300) || (p.ttfb != null && p.ttfb > 6000)) return 1;
  return 2;
}

function classify(direct, vpn) {
  const sd = pathScore(direct);
  const sv = pathScore(vpn);
  if (sv == null) return { result: "unknown", why: "VPN выключен — проверить путь через VPN нельзя" };
  if (sd == null) return { result: "unknown", why: "нет данных о прямом пути" };
  if (sd === 0 && sv === 0) return { result: "none", why: "не открывается ни напрямую, ни через VPN" };
  if (sd > sv) {
    const stub = vpn && (vpn.stub || vpn.challenge);
    return { result: "direct", stub: !!stub, why: sv === 0 ? "через VPN не открывается" : "через VPN хуже (проверка браузера или медленно)" };
  }
  if (sv > sd) return { result: "vpn", why: sd === 0 ? "напрямую не открывается" : "напрямую хуже (проверка браузера или медленно)" };
  return { result: "both", why: "работает и так, и так" };
}

const brief = (p) => (p ? { ok: !!p.ok, kind: p.kind || null, status: p.status ?? null, ms: p.ms ?? null, ttfb: p.ttfb ?? null, kbps: p.kbps ?? null, skipped: !!p.skipped } : null);

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
    for (const k of KINDS) {
      const r = await fetch(agentBase(state) + "/list?kind=" + k + "&fileOnly=1", { signal: AbortSignal.timeout(8000) });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const j = await r.json();
      // старый агент (расширение 2.x) не знает kind и отдаёт «чёрный» список — не подмешиваем его в «через VPN»
      if (j.kind && j.kind !== k) throw new Error("agent does not support kind=" + k);
      got[k] = j.entries || [];
    }
    await updateStore((s) => {
      for (const k of KINDS) {
        for (const e of got[k]) {
          const key = normalizeEntry(e);
          if (key && !s.lists[OTHER[k]].entries[key]) s.lists[k].entries[key] = { key, addedAt: Date.now(), source: "manual" };
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
// Отправить оба списка и путь по умолчанию; агент применяет и возвращает итог. Ждёт применения.
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
      default: state.settings.defaultPath,
      direct: computeList(state, "direct"),
      vpn: computeList(state, "vpn"),
      sig: currentSig(state)
    };
    try {
      const r = await fetch(agentBase(state) + "/apply", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(300000) // первое применение тысяч российских подсетей может идти минуту-другую
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

// Ручной экспорт в файл (для другого VPN / Proxifier) — выбранный список.
async function downloadList(state, kind) {
  const list = computeList(state, kind);
  const body = "# vpn-bypass-collector (" + kind + ") — " + new Date().toISOString() + "\n" + list.join("\n") + "\n";
  const url = "data:text/plain;charset=utf-8," + encodeURIComponent(body);
  await chrome.downloads.download({ url, filename: "vpn-bypass-" + kind + ".txt", saveAs: true });
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
      if (Object.keys(state.queue).length) chrome.alarms.create("pump", { delayInMinutes: 0.02 });
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

// ---- проверка сайтов: очередь и классификация ----
const RETRY_NONE_MS = 60 * 60 * 1000; // «не открывается нигде» — повторить через час
const MAX_QUEUE = 60;

async function agentProbe(state, host) {
  try {
    const r = await fetch(agentBase(state) + "/probe", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ host }),
      signal: AbortSignal.timeout(60000)
    });
    if (!r.ok) throw new Error("HTTP " + r.status);
    return await r.json();
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// Проверить сайт в обоих путях и положить в нужный список. Возвращает решение.
async function checkAndPlace(key, opts = {}) {
  const state = await loadState();
  const r = await agentProbe(state, key);
  if (!r || r.ok === false) return { result: "error", error: (r && r.error) || "агент не ответил", key };
  const c = classify(r.direct, r.vpn);
  const verdict = { at: Date.now(), d: brief(r.direct), v: brief(r.vpn), why: c.why, ips: (r.ips || []).slice(0, 4) };
  let moved = null;
  await updateStore((s) => {
    delete s.queue[key];
    const inList = KINDS.find((k) => s.lists[k].entries[key]);
    if (c.result === "vpn" || c.result === "both") {
      moved = inList && inList !== "vpn" ? inList : null;
      if (inList === "direct") delete s.lists.direct.entries[key];
      const prev = s.lists.vpn.entries[key];
      s.lists.vpn.entries[key] = { ...(prev || {}), key, addedAt: (prev && prev.addedAt) || Date.now(), source: (prev && prev.source) || opts.source || "auto", verdict, ...(c.result === "both" ? { both: true } : { both: false }) };
      delete s.unreachable[key];
    } else if (c.result === "direct") {
      moved = inList && inList !== "direct" ? inList : null;
      if (inList === "vpn") delete s.lists.vpn.entries[key];
      const prev = s.lists.direct.entries[key];
      s.lists.direct.entries[key] = { ...(prev || {}), key, addedAt: (prev && prev.addedAt) || Date.now(), source: (prev && prev.source) || opts.source || "auto", verdict, stub: !!c.stub };
      delete s.unreachable[key];
    } else if (c.result === "none") {
      const prev = s.unreachable[key];
      const tries = ((prev && prev.tries) || 0) + 1;
      s.unreachable[key] = { key, at: Date.now(), tries, nextAt: Date.now() + RETRY_NONE_MS * Math.min(tries, 6), d: verdict.d, v: verdict.v, why: c.why };
    } else if (c.result === "unknown") {
      // VPN выключен: оставляем в очереди, проверим позже
      s.queue[key] = { ...(s.queue[key] || { key, addedAt: Date.now(), tries: 0, reason: opts.reason || "new" }), nextAt: Date.now() + 2 * 60 * 1000 };
    }
  });
  // сайт открывается, но блокирует VPN → вывести IP-диапазоны его сети, чтобы весь блок шёл мимо VPN
  if (c.result === "direct" && c.stub) await markVpnBlock(key);
  return { ...c, key, verdict, moved };
}

let pumping = null;
function pumpQueue() {
  if (pumping) return pumping;
  pumping = (async () => {
    for (let n = 0; n < 12; n++) {
      const [state, agent] = [await loadState(), await getAgent()];
      if (!state.settings.enabled || !state.settings.autoCheck) break;
      if (!agent.reachable || vpnState(agent) !== "on") break; // без агента и включённого VPN сравнивать пути нельзя
      const now = Date.now();
      const item = Object.values(state.queue).filter((q) => (q.nextAt || 0) <= now).sort((a, b) => a.addedAt - b.addedAt)[0];
      if (!item) break;
      await updateStore((s) => {
        if (s.queue[item.key]) s.queue[item.key] = { ...s.queue[item.key], tries: (s.queue[item.key].tries || 0) + 1, checking: true };
      });
      const r = await checkAndPlace(item.key, { reason: item.reason });
      if (r.result === "error") {
        await updateStore((s) => {
          if (s.queue[item.key]) s.queue[item.key] = { ...s.queue[item.key], checking: false, nextAt: Date.now() + 60 * 1000, error: r.error };
        });
      }
      await new Promise((res) => setTimeout(res, 1500));
    }
  })().finally(() => (pumping = null));
  return pumping;
}

// ---- обнаружение новых сайтов в браузере ----
const recentNotice = new Map(); // key -> ts, чтобы не ставить в очередь один и тот же сайт снова и снова

function hostKey(url, groupByBase) {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    const h = u.hostname.toLowerCase();
    if (!h.includes(".") || isIp(h) || h === "localhost") return null;
    return toKey(h, groupByBase);
  } catch (_) {
    return null;
  }
}

async function noticeSite(url, { failed = false } = {}) {
  const state = await loadState();
  if (!state.settings.enabled || !state.settings.autoCheck) return;
  const key = hostKey(url, state.settings.groupByBaseDomain);
  if (!key || isExcepted(key, state.ignore)) return;
  const last = recentNotice.get(key) || 0;
  if (Date.now() - last < 5 * 60 * 1000) return;
  recentNotice.set(key, Date.now());
  const listed = KINDS.find((k) => Object.keys(state.lists[k].entries).some((e) => covers(e, key)));
  if (listed && !failed) return; // сайт уже разложен, пока открывается — ничего не делаем
  if (state.queue[key]) return;
  const un = state.unreachable[key];
  if (un && (un.nextAt || 0) > Date.now()) return;
  if (Object.keys(state.queue).length >= MAX_QUEUE) return;
  // Сайт из списка перестал открываться (или новый сайт) — проверить, не пора ли перенести
  await updateStore((s) => {
    s.queue[key] = { key, addedAt: Date.now(), nextAt: 0, tries: 0, reason: listed ? "failed-listed" : "new" };
  });
  chrome.alarms.create("pump", { delayInMinutes: 0.03 });
}

// Открывается ли сайт вообще — оставлено для «+ текущий сайт» без агента (запасной путь).
async function markVpnBlock(host) {
  await updateStore(async (state) => {
    const c = state.challenges[host] || { host, count: 0, firstSeen: Date.now(), ranges: [], asns: [], status: "new" };
    c.count += 1;
    c.lastSeen = Date.now();
    c.signal = c.signal || "проверка: через VPN не пускает";
    if (c.status === "ignored") c.status = "new";
    state.challenges[host] = c;
  });
  chrome.alarms.create("derive", { delayInMinutes: 0.02 });
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
  const n = Object.keys(state.queue || {}).length;
  try {
    await chrome.action.setBadgeText({ text: n ? String(n) : "" });
    await chrome.action.setBadgeBackgroundColor({ color: "#2f6fed" });
  } catch (_) {}
}

chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name === "sync") {
    lastSyncAt = Date.now();
    await syncAgent(await loadState());
  } else if (a.name === "derive") {
    await runDerive();
  } else if (a.name === "vpnpoll") {
    await pollAgentStatus();
  } else if (a.name === "pump" || a.name === "pumpTick") {
    await pumpQueue();
  }
});
chrome.alarms.create("vpnpoll", { periodInMinutes: 1 });
chrome.alarms.create("pumpTick", { periodInMinutes: 1 }); // повторные попытки: VPN был выключен, агент не отвечал
pollAgentStatus();

// ---- слушатели: новые сайты и ошибки навигации (только основной фрейм — то, что пользователь открывал сам) ----
chrome.webNavigation.onCompleted.addListener((d) => {
  if (d.frameId === 0) noticeSite(d.url);
});
chrome.webNavigation.onErrorOccurred.addListener((d) => {
  if (d.frameId === 0 && BLOCKING_ERRORS.has(d.error)) noticeSite(d.url, { failed: true });
});

chrome.runtime.onInstalled.addListener(async () => {
  // Записать нормализованное (и при обновлении — мигрированное) состояние.
  await chrome.storage.local.set({ state: await loadState() });
});

// ---- сообщения от popup ----
const okKind = (msg) => (KINDS.includes(msg.list) ? msg.list : null);

// Убрать сайт из очередей/списков и положить в нужный список вручную.
function placeManual(s, key, kind, source = "manual") {
  for (const k of KINDS) if (k !== kind) delete s.lists[k].entries[key];
  const prev = s.lists[kind].entries[key];
  s.lists[kind].entries[key] = { ...(prev || {}), key, addedAt: (prev && prev.addedAt) || Date.now(), source: (prev && prev.source) || source, both: false };
  if (kind === "vpn") delete s.challenges[key];
  delete s.queue[key];
  delete s.unreachable[key];
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    if (msg.type === "getState") {
      const state = await loadState();
      sendResponse({
        ...state,
        agent: await getAgent(),
        sig: currentSig(state),
        lists_computed: { vpn: computeList(state, "vpn"), direct: computeList(state, "direct") }
      });
      return;
    }
    // Принудительно: отправить списки и дождаться, пока агент их применит.
    if (msg.type === "forceSync") {
      const state = await loadState();
      lastSyncAt = Date.now();
      sendResponse(await syncAgent(state));
      return;
    }
    if (msg.type === "downloadList") {
      const state = await loadState();
      const kind = KINDS.includes(msg.list) ? msg.list : "vpn";
      sendResponse({ ok: true, count: await downloadList(state, kind) });
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
    if (msg.type === "setSettings") {
      await updateStore((state) => {
        Object.assign(state.settings, msg.settings);
      });
      if (msg.settings && msg.settings.autoCheck) chrome.alarms.create("pump", { delayInMinutes: 0.02 });
      sendResponse({ ok: true });
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
      const next = normalizeState(raw); // понимает форматы v1, v2 и v3
      next.imported = true;
      await updateStore((s) => {
        for (const k of Object.keys(s)) delete s[k];
        Object.assign(s, next);
      });
      const n = KINDS.reduce((a, k) => a + Object.keys(next.lists[k].entries).length, 0);
      chrome.alarms.create("pump", { delayInMinutes: 0.05 });
      sendResponse({ ok: true, count: n, queued: Object.keys(next.queue).length });
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
    // «+ текущий сайт»: проверить в обоих путях и положить в нужный список.
    if (msg.type === "addCurrentSite") {
      const state = await loadState();
      const key = normalizeEntry(msg.host);
      if (!key || isIp(key)) return sendResponse({ ok: false, error: "нет подходящего сайта во вкладке" });
      const k = toKey(key, state.settings.groupByBaseDomain);
      sendResponse({ ok: true, ...(await checkAndPlace(k, { source: "manual" })) });
      return;
    }
    // Ручная запись в список (домен, IP или IP/CIDR) без проверки: пользователь знает, чего хочет.
    if (msg.type === "addEntry") {
      const list = okKind(msg);
      const key = normalizeEntry(msg.value);
      if (!list || !key) return sendResponse({ ok: false, error: "не похоже на домен или IP" });
      await updateStore((s) => placeManual(s, key, list));
      sendResponse({ ok: true, key });
      return;
    }
    if (msg.type === "moveEntry") {
      if (!KINDS.includes(msg.to)) return sendResponse({ ok: false });
      await updateStore((s) => placeManual(s, msg.key, msg.to));
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "removeEntry" || msg.type === "removeEntries") {
      const list = okKind(msg);
      const keys = msg.type === "removeEntry" ? [msg.key] : Array.isArray(msg.keys) ? msg.keys : [];
      if (!list) return sendResponse({ ok: false });
      await updateStore((s) => {
        for (const k of keys) {
          delete s.lists[list].entries[k];
          if (list === "direct") delete s.challenges[k];
        }
      });
      sendResponse({ ok: true });
      return;
    }
    // Перепроверить сайт (поставить в начало очереди).
    if (msg.type === "recheck") {
      await updateStore((s) => {
        s.queue[msg.key] = { key: msg.key, addedAt: 0, nextAt: 0, tries: 0, reason: "manual" };
        if (s.unreachable[msg.key]) s.unreachable[msg.key].nextAt = 0;
      });
      chrome.alarms.create("pump", { delayInMinutes: 0.02 });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "dismissUnreachable") {
      await updateStore((s) => {
        delete s.unreachable[msg.key];
        delete s.queue[msg.key];
        if (!isExcepted(msg.key, s.ignore)) s.ignore.push(msg.key); // больше не проверять этот сайт
      });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "addIgnore") {
      const d = normalizeEntry(msg.domain);
      if (!d) return sendResponse({ ok: false, error: "не похоже на домен или IP" });
      await updateStore((s) => {
        if (!s.ignore.includes(d)) s.ignore.push(d);
        for (const k of Object.keys(s.queue)) if (covers(d, k)) delete s.queue[k];
        for (const k of Object.keys(s.unreachable)) if (covers(d, k)) delete s.unreachable[k];
      });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "removeIgnore") {
      await updateStore((s) => {
        s.ignore = s.ignore.filter((x) => x !== msg.domain);
      });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "clearChecks") {
      await updateStore((s) => {
        s.queue = {};
        s.unreachable = {};
      });
      sendResponse({ ok: true });
      return;
    }
    // Контент-скрипт увидел страницу «отключите VPN / проверка браузера»: сайт блокирует VPN → «мимо VPN».
    if (msg.type === "challengeDetected") {
      const host = (msg.host || "").toLowerCase().replace(/^www\./, "");
      if (!host || !host.includes(".") || vpnState(await getAgent()) !== "on") return sendResponse({ ok: false });
      const state0 = await loadState();
      if (!state0.settings.enabled || !state0.settings.autoCheck || isExcepted(host, state0.ignore)) return sendResponse({ ok: false });
      const key = toKey(host, state0.settings.groupByBaseDomain);
      await updateStore((s) => {
        if (s.lists.direct.entries[key]) return;
        delete s.lists.vpn.entries[key];
        s.lists.direct.entries[key] = { key, addedAt: Date.now(), source: "stub", stub: true, verdict: { at: Date.now(), why: "страница-заглушка: " + (msg.signal || "") } };
        delete s.queue[key];
        delete s.unreachable[key];
      });
      await markVpnBlock(key);
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "rederiveChallenge") {
      await updateStore((s) => {
        const c = s.challenges[msg.host];
        if (c) {
          c.status = "new";
          c.ranges = [];
        }
      });
      chrome.alarms.create("derive", { delayInMinutes: 0.02 });
      sendResponse({ ok: true });
      return;
    }
  })();
  return true; // async
});
