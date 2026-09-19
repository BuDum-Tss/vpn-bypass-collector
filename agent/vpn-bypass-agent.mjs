#!/usr/bin/env node
// VPN Bypass Agent — держит маршруты, чтобы каждый сайт шёл нужным путём.
// Два списка: «direct» — сайты, которые должны открываться МИМО VPN, «vpn» — которые должны открываться ЧЕРЕЗ VPN.
// Путь по умолчанию (для сайтов вне списков): "vpn" (рекомендуется) или "direct".
//   по умолчанию VPN    → маршруты (route add <ip> <LAN-gw>) нужны для списка direct и российских подсетей;
//   по умолчанию direct → маршруты нужны для списка vpn (плюс «половинки» туннельных маршрутов напрямую).
// Записи «умолчательной» стороны, попавшие внутрь широкого диапазона другой стороны, получают точечный маршрут.
// Работает только когда VPN включён; при выключении маршруты снимаются.
// Тот же механизм, что использует сам hidemy.name (VpnBypassProvider / "forced host route").

import { promises as dns } from "node:dns";
import {
  readFileSync, writeFileSync, existsSync, mkdirSync, watch, appendFileSync, statSync, unlinkSync,
} from "node:fs";
import { spawnSync, execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import http from "node:http";
import path from "node:path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const expand = (s) =>
  String(s).replace(/%([^%]+)%/g, (_, n) => process.env[n] ?? `%${n}%`);

const DEFAULTS = {
  listPath: "%APPDATA%\\vpn-bypass\\domains.txt",          // чёрный список (обход VPN)
  whitelistPath: "%APPDATA%\\vpn-bypass\\whitelist.txt",   // белый список (только через VPN)
  mode: "blacklist",       // до первого /apply: blacklist = по умолчанию VPN, whitelist = по умолчанию напрямую
  staticEntries: [],       // всегда мимо VPN (добавляются к списку direct)
  regionDirect: true,      // когда по умолчанию VPN: российские IP-сети (data/ru-ranges.txt) идут напрямую
  regionFile: "",          // свой файл со списком CIDR вместо data/ru-ranges.txt
  enableIPv6: false,
  reResolveMinutes: 15,
  vpnPollSeconds: 20,
  staleHours: 24,
  routeMetric: 1,
  // regex по имени/описанию VPN-адаптера. Для нескольких VPN: "hidemy|Amnezia|WireGuard"
  vpnAdapterMatch: "hidemy",
  logPath: "C:\\ProgramData\\vpn-bypass-agent\\agent.log",
  apiPort: 35777,          // локальный HTTP для расширения (127.0.0.1)
  vpnControl: true,        // разрешить кнопку вкл/выкл VPN (Disable/Enable-NetAdapter)
  geoTtlSeconds: 30,
  dryRun: false,           // true — ничего не менять в таблице маршрутов, только писать в лог
};

const cfgPath = process.env.VPN_BYPASS_CONFIG || path.join(HERE, "config.json");
// Правка config.json в Блокноте / PowerShell 5.1 добавляет BOM — JSON.parse на нём падает.
const readJson = (p) => JSON.parse(readFileSync(p, "utf8").replace(/^﻿/, ""));
const cfg = { ...DEFAULTS, ...(existsSync(cfgPath) ? readJson(cfgPath) : {}) };
cfg.listPath = expand(cfg.listPath);
cfg.whitelistPath = expand(cfg.whitelistPath);
cfg.logPath = expand(cfg.logPath);
const statePath = path.join(path.dirname(cfg.logPath), "state.json");
const lockPath = path.join(path.dirname(cfg.logPath), "agent.lock");
// direct — мимо VPN (файл listPath, «чёрный» у расширения 2.0), vpn — через VPN (файл whitelistPath, «белый»).
const KINDS = ["direct", "vpn"];
const listFile = (kind) => (kind === "vpn" ? cfg.whitelistPath : cfg.listPath);
const defFromLegacy = (m) => (m === "whitelist" ? "direct" : "vpn");   // режим расширения 2.0 → путь по умолчанию
const legacyMode = (def) => (def === "direct" ? "whitelist" : "blacklist");
const kindFromLegacy = (m) => (m === "whitelist" ? "vpn" : "direct");  // «белый» список = через VPN
cfg.regionFile = cfg.regionFile ? expand(cfg.regionFile) : path.join(HERE, "data", "ru-ranges.txt");

// ---------- utils ----------
function log(...a) {
  const line = `[${new Date().toISOString()}] ${a.join(" ")}`;
  console.log(line);
  try {
    mkdirSync(path.dirname(cfg.logPath), { recursive: true });
    if (existsSync(cfg.logPath) && statSync(cfg.logPath).size > 1_000_000) {
      writeFileSync(cfg.logPath + ".1", readFileSync(cfg.logPath));
      writeFileSync(cfg.logPath, "");
    }
    appendFileSync(cfg.logPath, line + "\n");
  } catch {}
}
const arr = (x) => (Array.isArray(x) ? x : x == null ? [] : [x]);

// Асинхронный запуск: пока идёт powershell/route.exe, HTTP-сервер агента продолжает отвечать.
function run(cmd, args, timeout = 30000) {
  return new Promise((resolve) => {
    execFile(
      cmd, args,
      { encoding: "utf8", maxBuffer: 32 * 1024 * 1024, windowsHide: true, timeout },
      (err, stdout, stderr) =>
        resolve({
          status: err ? (typeof err.code === "number" ? err.code : 1) : 0,
          stdout: stdout || "",
          stderr: (stderr || "") + (err && !stderr ? err.message : ""),
        }),
    );
  });
}
async function ps(script) {
  const r = await run("powershell.exe", [
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script,
  ]);
  if (r.status !== 0) throw new Error("powershell: " + r.stderr.trim());
  return r.stdout.trim();
}
async function psJson(script) {
  const out = await ps(script + " | ConvertTo-Json -Depth 6 -Compress");
  return out ? JSON.parse(out) : null;
}
function isAdmin() {
  return spawnSync("net.exe", ["session"], { encoding: "utf8" }).status === 0;
}
function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === "EPERM"; // существует, но нет прав — значит живой
  }
}
function acquireSingleInstance() {
  try {
    if (existsSync(lockPath)) {
      const old = parseInt(readFileSync(lockPath, "utf8").trim(), 10);
      if (old && old !== process.pid && pidAlive(old)) {
        log(`another instance is running (pid ${old}) — exiting`);
        process.exit(0);
      }
    }
    mkdirSync(path.dirname(lockPath), { recursive: true });
    writeFileSync(lockPath, String(process.pid));
  } catch (e) {
    log("lock error: " + e.message);
  }
}
function releaseSingleInstance() {
  try {
    if (existsSync(lockPath) && readFileSync(lockPath, "utf8").trim() === String(process.pid)) {
      unlinkSync(lockPath);
    }
  } catch {}
}

// ---------- IPv4 / маршруты ----------
function cidrMask(prefix) {
  const n = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}
const ipToInt = (ip) => ip.split(".").reduce((a, o) => ((a << 8) | +o) >>> 0, 0);
const intToIp = (n) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
function targetParts(target) {
  const [net, pfx] = target.split("/");
  return { net, mask: pfx ? cidrMask(+pfx) : "255.255.255.255" };
}
// Две более узкие «половинки» префикса: они длиннее и потому перебивают исходный маршрут туннеля.
function halves(prefix) {
  const [ip, len] = prefix.split("/");
  const L = +len;
  if (!(L >= 0 && L < 24)) return [];
  const base = ipToInt(ip);
  const step = 2 ** (32 - L - 1);
  return [`${intToIp(base)}/${L + 1}`, `${intToIp((base + step) >>> 0)}/${L + 1}`];
}
async function routeAdd(target, gw, ifIndex) {
  const { net, mask } = targetParts(target);
  const args = ["add", net, "mask", mask, gw, "metric", String(cfg.routeMetric)];
  if (ifIndex != null) args.push("if", String(ifIndex));
  if (cfg.dryRun) {
    log(`[dry-run] route ${args.join(" ")}`);
    return true;
  }
  const r = await run("route.exe", args, 10000);
  return r.status === 0 && !/failed|ошиб/i.test(r.stdout);
}
async function routeDel(target, gw, ifIndex) {
  const { net, mask } = targetParts(target);
  const args = ["delete", net, "mask", mask];
  if (gw) args.push(gw);
  if (gw && ifIndex != null) args.push("if", String(ifIndex));
  if (cfg.dryRun) {
    log(`[dry-run] route ${args.join(" ")}`);
    return true;
  }
  const r = await run("route.exe", args, 10000);
  return r.status === 0 || /not found|не найден/i.test(r.stdout + r.stderr);
}

// ---------- VPN detection ----------
// Универсально для любого протокола (WireGuard/AmneziaWG, OpenVPN, Xray-обёртка):
// «туннельные» маршруты — широкие (≤/16) маршруты на интерфейсе VPN-адаптера
// либо старый признак: 0/1, 128/1, 0/2.. с next-hop 10.x.
// withOwn — заодно прочитать все маршруты с нашей метрикой (для сверки со state). Это самое тяжёлое место при
// тысячах маршрутов, поэтому плановые проверки делают его редко, а не каждые 20 с.
async function detectVpn(withOwn = true) {
  let d;
  try {
    d = await psJson(`
$m='${cfg.vpnAdapterMatch}'
$pref=@('0.0.0.0/1','128.0.0.0/1','0.0.0.0/2','0.0.0.0/3','0.0.0.0/5')
$ad=Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and ($_.Name -match $m -or $_.InterfaceDescription -match $m) }
$ifs=@($ad | ForEach-Object { $_.ifIndex })
$tunAll=@(); if ($ifs.Count) { $tunAll=@(Get-NetRoute -InterfaceIndex $ifs -AddressFamily IPv4 -ErrorAction SilentlyContinue) }
$tun=@($tunAll | Where-Object { [int]$_.DestinationPrefix.Split('/')[1] -le 16 -and [int]$_.DestinationPrefix.Split('.')[0] -lt 224 } | ForEach-Object { @{ p=$_.DestinationPrefix; nh=$_.NextHop; ifx=$_.ifIndex } })
$leg=@(); foreach ($p in $pref) { $leg += @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $p -ErrorAction SilentlyContinue | ForEach-Object { @{ p=$_.DestinationPrefix; nh=$_.NextHop; ifx=$_.ifIndex } }) }
$def=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | ForEach-Object { @{ nh=$_.NextHop; ifx=$_.ifIndex } })
$own=$null
${withOwn ? "$own=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.RouteMetric -eq " + cfg.routeMetric + " } | ForEach-Object { $_.DestinationPrefix })" : ""}
$phys=@(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.ifIndex })
[pscustomobject]@{ ifs=$ifs; tun=$tun; leg=$leg; def=$def; own=$own; phys=$phys }`);
  } catch (e) {
    log("detectVpn error: " + e.message);
    return { up: false, error: e.message };
  }
  if (!d) return { up: false };
  const hidemyIf = new Set(arr(d.ifs));
  const legacy = arr(d.leg).filter((r) => /^10\./.test(r.nh || "") || hidemyIf.has(r.ifx));
  const tunnel = new Map();
  for (const r of [...arr(d.tun), ...legacy]) if (!tunnel.has(r.p)) tunnel.set(r.p, r);
  // Собственные маршруты агента (в белом списке — широкие CIDR через интерфейс VPN, например 142.250.0.0/15)
  // не считаются «маршрутами туннеля»: иначе агент строит для них «половинки» напрямую и перебивает сам себя.
  for (const p of Object.keys(state.routes || {})) tunnel.delete(p);
  const up = tunnel.size > 0;
  const vpnIfs = new Set([...hidemyIf, ...legacy.map((r) => r.ifx)]);
  // «Физический» шлюз = default-маршрут на АППАРАТНОМ адаптере (Wi-Fi/Ethernet). Раньше исключали шлюзы 10.x
  // как признак VPN — но у домашних сетей и мобильных точек доступа шлюз как раз 10.x, и агент выбирал
  // виртуальный адаптер (Radmin/Tailscale), отправляя весь «прямой» трафик в никуда.
  const phys = new Set(arr(d.phys));
  const gwRow = arr(d.def).find((r) => {
    if (!r.nh || r.nh === "0.0.0.0" || vpnIfs.has(r.ifx)) return false;
    return phys.size ? phys.has(r.ifx) : !/^10\./.test(r.nh); // нет данных об адаптерах — прежняя эвристика
  });
  // Next-hop/интерфейс самого туннеля — куда слать трафик «через VPN» (on-link 0.0.0.0 у WireGuard, 10.x у OpenVPN).
  const first = [...tunnel.values()].sort((a, b) => +a.p.split("/")[1] - +b.p.split("/")[1])[0];
  return {
    up,
    gw: gwRow?.nh || null,
    gwIf: gwRow?.ifx ?? null,
    vpnGw: first ? first.nh : null,
    vpnIf: first ? first.ifx : null,
    tunnel: [...tunnel.values()].map((r) => r.p),
    // маршруты с нашей метрикой, реально присутствующие в таблице — для сверки со state
    own: d.own == null ? undefined : arr(d.own), // undefined — в этот раз не читали
    splitCount: tunnel.size,
  };
}

// ---------- кэши статуса (чтобы /status отвечал мгновенно) ----------
function singleFlight(fn) {
  let p = null;
  return () => (p ||= fn().finally(() => (p = null)));
}
let vpnCache = { v: null, ts: 0 };
let lastOwnAt = 0; // когда последний раз читали реальные маршруты для сверки
let vpnFlight = null;
function refreshVpn(withOwn = false) {
  vpnFlight ||= detectVpn(withOwn)
    .then((v) => {
      vpnCache = { v, ts: Date.now() };
      if (withOwn && v.own) lastOwnAt = Date.now();
      return v;
    })
    .finally(() => (vpnFlight = null));
  return vpnFlight;
}
let adaptersCache = { v: [], ts: 0 };
const refreshAdapters = singleFlight(async () => {
  adaptersCache = { v: await vpnAdapters(), ts: Date.now() };
  return adaptersCache.v;
});

let geoCache = { ts: 0, v: null };
const refreshGeo = singleFlight(async () => {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 6000);
  try {
    const r = await fetch("https://ipwho.is/", { signal: ac.signal });
    const j = await r.json();
    const v = j && j.success !== false
      ? {
          ip: j.ip,
          country: j.country,
          countryCode: j.country_code,
          city: j.city,
          isp: (j.connection && (j.connection.isp || j.connection.org)) || j.org || null,
          flag: (j.flag && j.flag.emoji) || null,
        }
      : null;
    if (v) geoCache = { ts: Date.now(), v };
  } catch {
    /* оставляем прошлое значение, если сеть моргнула */
  } finally {
    clearTimeout(t);
  }
  return geoCache.v;
});
// Отдаёт кэш сразу; устаревший — обновляет в фоне.
function getGeoCached() {
  if (Date.now() - geoCache.ts > cfg.geoTtlSeconds * 1000) refreshGeo();
  return geoCache.v;
}

// ---------- вкл/выкл VPN (Disable/Enable-NetAdapter на адаптерах VPN) ----------
async function vpnAdapters() {
  try {
    return arr(
      await psJson(
        `Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '${cfg.vpnAdapterMatch}' -or $_.InterfaceDescription -match '${cfg.vpnAdapterMatch}' } | ForEach-Object { @{ name=$_.Name; status=$_.Status } }`,
      ),
    );
  } catch {
    return [];
  }
}
async function setVpn(action) {
  if (!cfg.vpnControl) return { ok: false, error: "vpnControl disabled in config" };
  const ads = await vpnAdapters();
  if (!ads.length) return { ok: false, error: "no VPN adapters found" };
  const verb = action === "connect" ? "Enable-NetAdapter" : "Disable-NetAdapter";
  const names = ads.map((a) => `'${a.name.replace(/'/g, "''")}'`).join(",");
  try {
    await ps(`@(${names}) | ForEach-Object { ${verb} -Name $_ -Confirm:$false -ErrorAction SilentlyContinue }`);
    if (action === "connect") {
      // подтолкнуть службу-менеджер соединения
      await ps(`Start-Service 'hidemy.name VPN Watcher' -ErrorAction SilentlyContinue`);
    }
    log(`VPN ${action}: ${verb} on ${ads.map((a) => a.name).join(", ")}`);
    geoCache = { ts: 0, v: geoCache.v };
    setTimeout(() => reconcile(`vpn ${action}`), 2500);
    return { ok: true, adapters: ads.map((a) => a.name) };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ---------- списки: файлы, нормализация ----------
function isIpOrCidr(s) {
  return /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(s);
}
function normEntry(line) {
  line = String(line).replace(/#.*$/, "").trim().toLowerCase();
  if (!line) return null;
  if (isIpOrCidr(line)) return line; // голый IP или IP/CIDR — до срезания пути
  const proto = line.match(/^[a-z][a-z0-9+.-]*:\/\/([^/]+)/);
  if (proto) line = proto[1];
  line = line.replace(/^www\./, "").replace(/[/:?].*$/, "");
  if (isIpOrCidr(line)) return line;
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/.test(line)) return line;
  return null;
}
function writeList(kind, entries) {
  const clean = [...new Set(arr(entries).map(normEntry).filter(Boolean))];
  const what = kind === "vpn" ? "список «через VPN»" : "список «мимо VPN»";
  const body =
    `# vpn-bypass — ${what}, от расширения, ${new Date().toISOString()}\n` +
    "# один домен / IP / IP-CIDR в строке; '#' — комментарий\n" +
    clean.join("\n") + "\n";
  const file = listFile(kind);
  mkdirSync(path.dirname(file), { recursive: true });
  // Защита от потери: прежний НЕпустой список сохраняем в .bak (пустая перезапись .bak не затирает).
  try {
    if (existsSync(file)) {
      const old = readFileSync(file, "utf8");
      const oldCount = old.split(/\r?\n/).map(normEntry).filter(Boolean).length;
      if (oldCount > 0 && old.replace(/^#.*$/gm, "").trim() !== clean.join("\n")) writeFileSync(file + ".bak", old);
    }
  } catch (e) {
    log("list backup error: " + e.message);
  }
  writeFileSync(file, body);
  return clean.length;
}
function readList(kind, fileOnly = false) {
  const set = new Set();
  if (kind === "direct" && !fileOnly) {
    for (const e of cfg.staticEntries || []) {
      const n = normEntry(e);
      if (n) set.add(n);
    }
  }
  try {
    for (const line of readFileSync(listFile(kind), "utf8").split(/\r?\n/)) {
      const n = normEntry(line);
      if (n) set.add(n);
    }
  } catch {
    /* нет файла = пустой пользовательский список */
  }
  return [...set];
}

// Российские IP-сети (RIPE; обновляются tools/update-ru-ranges.mjs): по умолчанию VPN они идут напрямую.
let regionCache = { mtime: 0, list: [] };
function readRegion() {
  if (!cfg.regionDirect) return [];
  try {
    const st = statSync(cfg.regionFile);
    if (st.mtimeMs === regionCache.mtime) return regionCache.list;
    const list = readFileSync(cfg.regionFile, "utf8")
      .split(/\r?\n/).map((l) => l.replace(/#.*$/, "").trim()).filter((l) => isIpOrCidr(l));
    regionCache = { mtime: st.mtimeMs, list };
    return list;
  } catch {
    return [];
  }
}

// Интервалы адресов: «target целиком внутри одного из широких диапазонов» — двоичным поиском.
function cidrRange(t) {
  const [n, p] = t.split("/");
  const a = ipToInt(n);
  return [a, a + 2 ** (32 - (p == null ? 32 : +p)) - 1];
}
function mergeIntervals(targets) {
  const merged = [];
  for (const [a, b] of targets.map(cidrRange).sort((x, y) => x[0] - y[0])) {
    const last = merged[merged.length - 1];
    if (last && a <= last[1] + 1) last[1] = Math.max(last[1], b);
    else merged.push([a, b]);
  }
  return merged;
}
function coveredBy(t, merged) {
  const [a, b] = cidrRange(t);
  let lo = 0, hi = merged.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [s0, e0] = merged[mid];
    if (a < s0) hi = mid - 1;
    else if (a > e0) lo = mid + 1;
    else return b <= e0;
  }
  return false;
}
// Параллельный прогон: route.exe на тысячи маршрутов по одному — минуты, по 8 сразу — секунды.
async function mapLimit(items, n, fn) {
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (i < items.length) {
        const k = i++;
        await fn(items[k], k);
      }
    }),
  );
}
function routableTarget(target) {
  const ip = target.split("/")[0];
  if (ip.includes(":")) return cfg.enableIPv6;
  const [a, b] = ip.split(".").map(Number);
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT / Tailscale
  return true;
}
async function resolveAll(entries) {
  const targets = new Map(); // ip|cidr -> Set(source)
  const put = (t, src) => {
    if (!routableTarget(t)) return;
    (targets.get(t) || targets.set(t, new Set()).get(t)).add(src);
  };
  for (const e of entries) {
    if (isIpOrCidr(e)) {
      put(e, e); // голый IP или целая подсеть — как есть
      continue;
    }
    const fns = ["resolve4", ...(cfg.enableIPv6 ? ["resolve6"] : [])];
    // «www.» из записей вырезается, а у многих сайтов www и apex — разные адреса: резолвим оба.
    const names = e.split(".").length <= 2 ? [e, "www." + e] : [e];
    for (const name of names) {
      for (const fn of fns) {
        try {
          for (const ip of await dns[fn](name)) put(ip, e);
        } catch {
          /* NXDOMAIN / no AAAA — ok */
        }
      }
    }
  }
  return targets;
}

// Разовый резолв имён для показа IP в расширении (кэш 5 мин; тот же DNS, что и для маршрутов).
const resolveCache = new Map(); // name -> { ts, ips }
async function resolveNames(names) {
  const uniq = [...new Set(arr(names).map((n) => String(n).toLowerCase().trim()))]
    .filter((n) => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(n))
    .slice(0, 200);
  const out = {};
  const one = async (n) => {
    const hit = resolveCache.get(n);
    if (hit && Date.now() - hit.ts < 5 * 60 * 1000) return (out[n] = hit.ips);
    let ips = [];
    try {
      ips = await Promise.race([
        dns.resolve4(n),
        new Promise((_, rej) => setTimeout(() => rej(new Error("dns timeout")), 4000)),
      ]);
    } catch {
      /* NXDOMAIN / таймаут — пусто */
    }
    resolveCache.set(n, { ts: Date.now(), ips });
    out[n] = ips;
  };
  for (let i = 0; i < uniq.length; i += 8) await Promise.all(uniq.slice(i, i + 8).map(one));
  return out;
}

// ---------- state ----------
// routes: ip -> { domains, lastSeen, gw, ifx }   маршруты для записей списка
// base:   prefix -> { gw, ifx }                  whitelist: «половинки» туннельных маршрутов → напрямую
let state = { routes: {}, base: {}, def: null, routesDef: null, sig: null, apply: null };
try {
  if (existsSync(statePath)) state = { ...state, ...JSON.parse(readFileSync(statePath, "utf8")) };
} catch {}
// Миграция с версии, где был режим: blacklist/whitelist → путь по умолчанию vpn/direct.
if (state.def !== "vpn" && state.def !== "direct") state.def = defFromLegacy(state.mode || cfg.mode);
if (!state.routesDef && state.routesMode) state.routesDef = defFromLegacy(state.routesMode);
delete state.mode;
delete state.routesMode;
state.routes ||= {};
state.base ||= {};
const saveState = () => {
  try {
    mkdirSync(path.dirname(statePath), { recursive: true });
    writeFileSync(statePath, JSON.stringify(state, null, 2));
  } catch (e) {
    log("saveState error: " + e.message);
  }
};
async function removeAllRoutes(reason) {
  const ips = Object.keys(state.routes);
  const base = Object.keys(state.base);
  if (!ips.length && !base.length) return;
  log(`removing ${ips.length} route(s) + ${base.length} base route(s) — ${reason}`);
  await mapLimit(ips, 8, (ip) => routeDel(ip, state.routes[ip].gw, state.routes[ip].ifx));
  await mapLimit(base, 8, (p) => routeDel(p, state.base[p].gw, state.base[p].ifx));
  state.routes = {};
  state.base = {};
  saveState();
}

// ---------- reconcile ----------
let applyBusy = false;
let lastFull = { at: 0, ok: false, def: null, gw: null, gwIf: null, vpnIf: null };
let chain = Promise.resolve();
let queued = null; // проход, который ещё не начался
// Проходы идут строго по очереди; запросы, пришедшие во время работы, схлопываются в один следующий.
// Возвращает итог того прохода, который их обслужил.
function reconcile(reason) {
  if (queued) return queued;
  const p = chain.then(() => {
    queued = null;
    return doReconcile(reason);
  });
  queued = p;
  chain = p.catch(() => {});
  return p;
}

async function doReconcile(reason) {
  const t0 = Date.now();
  const def = state.def;
  const other = def === "vpn" ? "direct" : "vpn";
  const sum = {
    at: t0, reason, default: def, mode: legacyMode(def), ok: true, vpnUp: null,
    entries: 0, entriesDirect: 0, entriesVpn: 0, regionTargets: 0, targets: 0, overrides: 0,
    added: 0, removed: 0, failed: 0, routes: 0, baseRoutes: 0, note: null, error: null, ms: 0,
  };
  // Плановая проверка (poll) обычно ничего не меняет — «применяется…» показываем только на полном проходе.
  applyBusy = reason !== "poll";
  try {
    // Сверку с реальной таблицей делаем на любом непланово запущенном проходе и раз в 2 минуты на плановых.
    const vpn = await refreshVpn(reason !== "poll" || Date.now() - lastOwnAt > 120000);
    sum.vpnUp = !!vpn.up;
    if (!vpn.up) {
      await removeAllRoutes(`VPN down (${reason})`);
      sum.note = "VPN выключен — маршруты сняты";
      return sum;
    }
    if (!vpn.gw) {
      sum.ok = false;
      sum.error = "VPN включён, но физический шлюз не найден";
      log(sum.error + " — skipping");
      return sum;
    }
    if (def === "direct" && vpn.vpnIf == null) {
      sum.ok = false;
      sum.error = "не найден интерфейс туннеля VPN";
      log(sum.error + " — skipping");
      return sum;
    }
    // Самопроверка: записи state, которых нет в реальной таблице (переподключили Wi-Fi/VPN, кто-то удалил),
    // забываем — ниже они будут добавлены заново. В dryRun таблица не меняется, поэтому там не сверяем.
    let drift = 0;
    if (!cfg.dryRun && vpn.own) {
      const present = new Set(vpn.own);
      const norm = (k) => (k.includes("/") ? k : k + "/32");
      for (const k of Object.keys(state.routes)) if (!present.has(norm(k))) { delete state.routes[k]; drift++; }
      for (const k of Object.keys(state.base)) if (!present.has(norm(k))) { delete state.base[k]; drift++; }
      if (drift) log(`drift: ${drift} route(s) from state are missing in the routing table — re-adding`);
    }
    // Быстрый путь: VPN/шлюз/путь по умолчанию те же и полный проход был недавно — не резолвим сотни имён каждые 20 с.
    // Изменения списка приходят отдельно (наблюдатель файлов, /apply) и всегда идут полным проходом.
    if (
      reason === "poll" && drift === 0 && lastFull.ok && lastFull.def === def && lastFull.gw === vpn.gw &&
      lastFull.gwIf === vpn.gwIf && lastFull.vpnIf === vpn.vpnIf &&
      Date.now() - lastFull.at < cfg.reResolveMinutes * 60 * 1000
    ) {
      sum.skipped = true;
      return sum;
    }
    applyBusy = true;
    // Сменили путь по умолчанию — сначала снять маршруты прежнего.
    if (state.routesDef && state.routesDef !== def) {
      await removeAllRoutes(`default path switch ${state.routesDef} → ${def}`);
    }
    state.routesDef = def;

    const lists = { direct: readList("direct"), vpn: readList("vpn") };
    const entrySet = { direct: new Set(lists.direct), vpn: new Set(lists.vpn) };
    sum.entriesDirect = lists.direct.length;
    sum.entriesVpn = lists.vpn.length;
    sum.entries = sum.entriesDirect + sum.entriesVpn;
    const resolved = { direct: await resolveAll(lists.direct), vpn: await resolveAll(lists.vpn) };
    const region = def === "vpn" ? readRegion().filter(routableTarget) : []; // российские сети — напрямую
    sum.regionTargets = region.length;
    const now = Date.now();

    // Что и каким путём должно быть в таблице. Явные маршруты — у «неумолчательной» стороны.
    // Записи умолчательной стороны получают маршрут, только если попали внутрь широкого диапазона другой стороны
    // (иначе, например, YouTube из списка «через VPN» утонул бы в диапазоне «мимо VPN»).
    const want = new Map(); // target -> { path, from, domains }
    for (const [t, srcs] of resolved[other]) want.set(t, { path: other, from: other, domains: [...srcs] });
    for (const c of region) if (!want.has(c)) want.set(c, { path: "direct", from: "ru", domains: ["ru"] });
    const wide = [...want.keys()].filter((t) => t.includes("/") && !t.endsWith("/32"));
    const merged = wide.length ? mergeIntervals(wide) : [];
    if (merged.length) {
      for (const [t, srcs] of resolved[def]) {
        if (want.has(t) || !coveredBy(t, merged)) continue;
        want.set(t, { path: def, from: def, domains: [...srcs] });
        sum.overrides++;
      }
    }
    sum.targets = want.size;

    // Пути: напрямую — физический шлюз; через VPN — интерфейс туннеля (on-link 0.0.0.0 у WireGuard, next-hop у OpenVPN).
    const PATH = {
      direct: { gw: vpn.gw, ifx: vpn.gwIf },
      vpn: { gw: vpn.vpnGw || "0.0.0.0", ifx: vpn.vpnIf },
    };

    // По умолчанию напрямую: всё, что VPN забирает в туннель, перебиваем узкими половинками напрямую.
    const wantBase = new Map();
    if (def === "direct") {
      for (const p of vpn.tunnel) for (const h of halves(p)) wantBase.set(h, { gw: vpn.gw, ifx: vpn.gwIf });
    }
    await mapLimit([...wantBase], 8, async ([p, w]) => {
      const cur = state.base[p];
      if (cur && cur.gw === w.gw && cur.ifx === w.ifx) return;
      if (cur) await routeDel(p, cur.gw, cur.ifx);
      if (await routeAdd(p, w.gw, w.ifx)) {
        state.base[p] = { gw: w.gw, ifx: w.ifx };
        sum.added++;
      } else {
        sum.failed++;
        log(`base route add failed: ${p}`);
      }
    });
    for (const p of Object.keys(state.base)) {
      if (!wantBase.has(p)) {
        await routeDel(p, state.base[p].gw, state.base[p].ifx);
        delete state.base[p];
        sum.removed++;
      }
    }

    const toAdd = [];
    const toFix = [];
    for (const [t, w] of want) {
      const p = PATH[w.path];
      if (p.ifx == null) { sum.failed++; continue; } // нет интерфейса нужного пути
      const cur = state.routes[t];
      if (!cur) {
        toAdd.push([t, w, p]);
        continue;
      }
      cur.lastSeen = now;
      cur.domains = w.domains;
      cur.from = w.from;
      if (cur.gw !== p.gw || cur.ifx !== p.ifx || cur.path !== w.path) toFix.push([t, w, p]);
    }
    await mapLimit(toFix, 8, async ([t, w, p]) => {
      const cur = state.routes[t];
      await routeDel(t, cur.gw, cur.ifx);
      if (await routeAdd(t, p.gw, p.ifx)) Object.assign(cur, { gw: p.gw, ifx: p.ifx, path: w.path });
      else { delete state.routes[t]; sum.failed++; }
    });
    await mapLimit(toAdd, 8, async ([t, w, p]) => {
      if (await routeAdd(t, p.gw, p.ifx)) {
        state.routes[t] = { domains: w.domains, lastSeen: now, gw: p.gw, ifx: p.ifx, path: w.path, from: w.from };
        sum.added++;
      } else {
        sum.failed++;
        log(`route add failed: ${t}`);
      }
    });

    // Записи, которых больше нет в want, снимаем сразу. Исключение — домен, который всё ещё в своём списке,
    // а его IP просто перестал резолвиться: держим staleHours (CDN меняют адреса).
    const staleMs = cfg.staleHours * 3600 * 1000;
    const toDel = [];
    for (const t of Object.keys(state.routes)) {
      if (want.has(t)) continue;
      const r = state.routes[t];
      const domainKept = arr(r.domains).some((d) => !isIpOrCidr(d) && d !== "ru" && entrySet[r.from]?.has(d));
      if (!(domainKept && now - r.lastSeen <= staleMs)) toDel.push(t);
    }
    await mapLimit(toDel, 8, async (t) => {
      const r = state.routes[t];
      await routeDel(t, r.gw, r.ifx);
      delete state.routes[t];
      sum.removed++;
    });
    sum.routes = Object.keys(state.routes).length;
    sum.baseRoutes = Object.keys(state.base).length;
    if (sum.failed) {
      sum.ok = false;
      sum.error = `не удалось добавить маршрутов: ${sum.failed}`;
    }
    lastFull = { at: Date.now(), ok: sum.ok, def, gw: vpn.gw, gwIf: vpn.gwIf, vpnIf: vpn.vpnIf };
    return sum;
  } catch (e) {
    sum.ok = false;
    sum.error = e.message;
    log("reconcile error: " + (e.stack || e.message));
    return sum;
  } finally {
    applyBusy = false;
    sum.ms = Date.now() - t0;
    sum.routes = Object.keys(state.routes).length;
    sum.baseRoutes = Object.keys(state.base).length;
    if (!sum.skipped) {
      state.apply = sum;
      saveState();
    }
    if (!sum.skipped && (sum.added || sum.removed || sum.failed || reason !== "poll")) {
      log(
        `reconcile (${reason}, default=${def}): +${sum.added} -${sum.removed}` +
          `${sum.failed ? ` FAILED ${sum.failed}` : ""}, routes=${sum.routes}` +
          `${sum.baseRoutes ? ` base=${sum.baseRoutes}` : ""}` +
          `${sum.regionTargets ? ` ru=${sum.regionTargets}` : ""}${sum.overrides ? ` overrides=${sum.overrides}` : ""}, ${sum.ms}ms` +
          `${sum.note ? ` — ${sum.note}` : ""}${sum.error ? ` — ${sum.error}` : ""}`,
      );
    }
  }
}

// ---------- локальный HTTP для расширения ----------
async function statusPayload() {
  if (!vpnCache.v) await refreshVpn();
  else if (Date.now() - vpnCache.ts > 10000) refreshVpn();
  if (Date.now() - adaptersCache.ts > 30000) refreshAdapters();
  const v = vpnCache.v || { up: false };
  return {
    vpnUp: !!v.up,
    gw: v.gw,
    adapters: adaptersCache.v,
    geo: getGeoCached(),
    routes: Object.keys(state.routes).length,
    baseRoutes: Object.keys(state.base).length,
    default: state.def,
    mode: legacyMode(state.def), // для расширения 2.0
    region: { enabled: !!cfg.regionDirect, file: existsSync(cfg.regionFile), ranges: readRegion().length },
    sig: state.sig,
    apply: { ...(state.apply || {}), busy: applyBusy },
    vpnCheckedAt: vpnCache.ts,
    listPath: listFile("direct"),
    vpnListPath: listFile("vpn"),
    vpnControl: !!cfg.vpnControl,
    dryRun: !!cfg.dryRun,
    ts: Date.now(),
  };
}

function startApiServer() {
  const server = http.createServer((req, res) => {
    const cors = {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-headers": "content-type",
    };
    if (req.method === "OPTIONS") {
      res.writeHead(204, cors);
      return res.end();
    }
    const send = (code, obj) =>
      res.writeHead(code, { ...cors, "content-type": "application/json" }) &&
      res.end(JSON.stringify(obj));
    const url = new URL(req.url, "http://x");

    const readBody = () =>
      new Promise((resolve) => {
        let b = "";
        req.on("data", (c) => (b += c));
        req.on("end", () => {
          try {
            resolve(b ? JSON.parse(b) : {});
          } catch {
            resolve({});
          }
        });
      });

    (async () => {
      if (url.pathname === "/status" && req.method === "GET") {
        return send(200, await statusPayload());
      }
      if (url.pathname === "/resolve" && req.method === "POST") {
        const body = await readBody();
        return send(200, { ok: true, ips: await resolveNames(body.names) });
      }
      if (url.pathname === "/list" && req.method === "GET") {
        // kind=direct|vpn (или прежний mode=blacklist|whitelist); fileOnly=1 — без staticEntries: для импорта в расширение
        const q = url.searchParams;
        const kind = KINDS.includes(q.get("kind")) ? q.get("kind") : q.get("mode") ? kindFromLegacy(q.get("mode")) : "direct";
        return send(200, { kind, entries: readList(kind, q.get("fileOnly") === "1") });
      }
      // Обратная совместимость: старый формат {entries} = список «мимо VPN».
      if (url.pathname === "/list" && req.method === "POST") {
        const body = await readBody();
        const n = writeList("direct", body.entries || []);
        reconcile("api /list");
        return send(200, { ok: true, count: n });
      }
      // Основной канал: оба списка + путь по умолчанию; ждём применения и отдаём итог.
      // Принимает и прежний формат расширения 2.0: {mode: blacklist|whitelist, blacklist:[…], whitelist:[…]}.
      if (url.pathname === "/apply" && req.method === "POST") {
        const body = await readBody();
        const def = body.default != null ? body.default : body.mode != null ? defFromLegacy(body.mode) : null;
        if (def != null && def !== "vpn" && def !== "direct")
          return send(400, { ok: false, error: "default must be vpn|direct" });
        const incoming = { direct: body.direct ?? body.blacklist, vpn: body.vpn ?? body.whitelist };
        const counts = {};
        for (const k of KINDS) if (Array.isArray(incoming[k])) counts[k] = writeList(k, incoming[k]);
        if (def) state.def = def;
        if (body.sig != null) state.sig = String(body.sig);
        saveState();
        const summary = await reconcile("api /apply");
        return send(200, { ok: summary.ok, counts, summary });
      }
      // Принудительное применение без смены списков.
      if (url.pathname === "/refresh" && req.method === "POST") {
        const summary = await reconcile("api /refresh");
        return send(200, { ok: summary.ok, summary });
      }
      if (url.pathname === "/vpn" && req.method === "POST") {
        const body = await readBody();
        if (!["connect", "disconnect"].includes(body.action))
          return send(400, { ok: false, error: "action must be connect|disconnect" });
        return send(200, await setVpn(body.action));
      }
      return send(404, { error: "not found" });
    })().catch((e) => send(500, { error: e.message }));
  });
  server.on("error", (e) => log("api server error: " + e.message));
  server.listen(cfg.apiPort, "127.0.0.1", () =>
    log(`api on http://127.0.0.1:${cfg.apiPort}`),
  );
}

// ---------- CLI one-shots ----------
const flag = process.argv[2];
if (flag === "--status") {
  await refreshGeo();
  console.log("config:", JSON.stringify(cfg, null, 2));
  console.log("default path:", state.def);
  console.log("vpn:", JSON.stringify(await detectVpn(), null, 2));
  console.log("adapters:", JSON.stringify(await vpnAdapters(), null, 2));
  console.log("geo:", JSON.stringify(geoCache.v, null, 2));
  console.log("direct list:", readList("direct"));
  console.log("vpn list:", readList("vpn"));
  console.log("region ranges:", readRegion().length);
  console.log("last apply:", JSON.stringify(state.apply, null, 2));
  console.log("active routes:", JSON.stringify(state.routes, null, 2));
  console.log("base routes:", JSON.stringify(state.base, null, 2));
  process.exitCode = 0;
} else if (flag === "--cleanup") {
  await removeAllRoutes("manual --cleanup");
  console.log("done");
  process.exitCode = 0;
} else if (flag === "--once") {
  console.log(JSON.stringify(await reconcile("--once"), null, 2));
  process.exitCode = 0;
} else {
  runDaemon();
}

function runDaemon() {

// ---------- daemon ----------
acquireSingleInstance();
if (!isAdmin()) {
  log("WARNING: not elevated — 'route add' will fail. Use the scheduled task or run as admin.");
}
log(`agent start (pid ${process.pid}) — default=${state.def}, direct=${cfg.listPath} | vpn=${cfg.whitelistPath}${cfg.dryRun ? " [DRY-RUN]" : ""}`);

for (const f of new Set([listFile("direct"), listFile("vpn")])) mkdirSync(path.dirname(f), { recursive: true });
const listNames = new Set([path.basename(cfg.listPath), path.basename(cfg.whitelistPath)]);
let watchTimer = null;
try {
  for (const dir of new Set([path.dirname(cfg.listPath), path.dirname(cfg.whitelistPath)])) {
    watch(dir, (_ev, fn) => {
      if (fn && !listNames.has(fn)) return;
      clearTimeout(watchTimer);
      watchTimer = setTimeout(() => reconcile("list changed"), 800);
    });
  }
  log("watching list directory");
} catch (e) {
  log("watch failed, relying on polling: " + e.message);
}

// перечитывать config.json на лету (staticEntries, интервалы и т.д.)
let cfgTimer = null;
try {
  watch(path.dirname(cfgPath), (_ev, fn) => {
    if (fn && fn !== path.basename(cfgPath)) return;
    clearTimeout(cfgTimer);
    cfgTimer = setTimeout(() => {
      try {
        const next = readJson(cfgPath);
        for (const k of ["staticEntries", "enableIPv6", "reResolveMinutes",
          "vpnPollSeconds", "staleHours", "routeMetric", "vpnAdapterMatch",
          "vpnControl", "geoTtlSeconds"]) {
          if (k in next) cfg[k] = next[k];
        }
        log("config reloaded");
        reconcile("config changed");
      } catch (e) {
        log("config reload error: " + e.message);
      }
    }, 500);
  });
} catch {}

startApiServer();
// Чистый старт: маршруты эфемерны (после перезагрузки их нет), а state.json мог о них помнить.
// Очистка идёт ПЕРВЫМ звеном очереди reconcile: плановые проходы ждут её конца, а не работают параллельно
// (иначе очистка стирала маршруты, только что добавленные проходом, а state считал их существующими).
chain = removeAllRoutes("startup cleanup").catch((e) => log("startup cleanup error: " + e.message));
reconcile("startup");
setInterval(() => reconcile("poll"), cfg.vpnPollSeconds * 1000);
setInterval(() => reconcile("re-resolve"), cfg.reResolveMinutes * 60 * 1000);

for (const sig of ["SIGINT", "SIGTERM", "SIGBREAK"]) {
  process.on(sig, () => {
    removeAllRoutes(`shutdown (${sig})`).finally(() => {
      releaseSingleInstance();
      process.exit(0);
    });
  });
}
process.on("exit", releaseSingleInstance);

} // runDaemon
