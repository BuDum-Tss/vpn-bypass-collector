#!/usr/bin/env node
// Обновляет agent/data/ru-ranges.txt — российские IPv4-сети (RIPE Stat, country-resource-list).
// Когда путь по умолчанию — VPN, агент пускает эти сети напрямую: российские сервисы (.ru, .рф, .su и любые
// сайты на российских адресах) работают без VPN, а всё остальное идёт через него.
//
//   node agent/tools/update-ru-ranges.mjs [--max-prefix=24]
//
// Ничего не меняет в системе — только пишет файл со списком.
import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "..", "data", "ru-ranges.txt");
const maxPrefix = +(process.argv.find((a) => a.startsWith("--max-prefix="))?.split("=")[1] ?? 24);

const toInt = (ip) => ip.split(".").reduce((a, o) => ((a << 8) | +o) >>> 0, 0);
const toIp = (n) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");

const url = "https://stat.ripe.net/data/country-resource-list/data.json?resource=RU&v4_format=prefix";
const res = await fetch(url, { signal: AbortSignal.timeout(90000) });
if (!res.ok) throw new Error("RIPE Stat: HTTP " + res.status);
const j = await res.json();
const v4 = j.data?.resources?.ipv4 || [];
if (!v4.length) throw new Error("RIPE Stat вернул пустой список IPv4 для RU");

const toRange = (s) => {
  if (s.includes("/")) {
    const [n, p] = s.split("/");
    const a = toInt(n);
    return [a, a + 2 ** (32 - +p) - 1];
  }
  const [a, b] = s.split("-");
  return [toInt(a.trim()), toInt(b.trim())];
};

// слить смежные и пересекающиеся диапазоны
const merged = [];
for (const [a, b] of v4.map(toRange).sort((x, y) => x[0] - y[0])) {
  const last = merged[merged.length - 1];
  if (last && a <= last[1] + 1) last[1] = Math.max(last[1], b);
  else merged.push([a, b]);
}

// диапазон -> минимальный набор выровненных CIDR
const cidrs = [];
for (let [a, b] of merged) {
  while (a <= b) {
    let size = a === 0 ? 2 ** 32 : a & -a; // самый крупный выровненный блок, начинающийся в a
    while (size > b - a + 1) size /= 2;
    cidrs.push([a, 32 - Math.log2(size)]);
    a += size;
  }
}

const total = merged.reduce((s, [a, b]) => s + (b - a + 1), 0);
const kept = cidrs.filter(([, p]) => p <= maxPrefix);
const keptAddr = kept.reduce((s, [, p]) => s + 2 ** (32 - p), 0);
const lines = kept.map(([a, p]) => `${toIp(a)}/${p}`);

mkdirSync(path.dirname(OUT), { recursive: true });
writeFileSync(
  OUT,
  `# Российские IPv4-сети (RIPE Stat, country-resource-list RU), обновлено ${new Date().toISOString().slice(0, 10)}.\n` +
    `# Сгенерировано agent/tools/update-ru-ranges.mjs; блоки мельче /${maxPrefix} отброшены. Правьте скриптом, не руками.\n` +
    lines.join("\n") + "\n",
);
console.log(`RU: ${cidrs.length} CIDR (${(total / 1e6).toFixed(1)} млн адресов); записано ${kept.length} (/${maxPrefix} и крупнее) = ${(keptAddr / total * 100).toFixed(1)}% адресов`);
console.log("файл:", OUT);
