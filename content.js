// Детектор страниц-заглушек VPN/антибота, которые отдаются с HTTP 200
// (обычный webRequest.onErrorOccurred их не видит — соединение-то успешное).

(() => {
  if (window.top !== window.self) return; // только главный фрейм

  const TITLE_RE =
    /just a moment|attention required|antibot challenge|проверка браузера|один момент|доступ (ограничен|запрещ)/i;

  const BODY_RE = new RegExp(
    [
      "vpn мешает работе",
      "отключите (его|vpn|впн)",
      "выключите vpn",
      "disable( your)? vpn",
      "turn off( your)? vpn",
      "using a vpn or proxy",
      "vpn или прокси",
      "please,? enable javascript",
      "включите javascript",
      "убедиться,? что вы не робот",
      "make sure (that )?you are not a robot",
      "checking (your|if) .{0,20}browser",
      "недоступ(ен|на|но) .{0,30}(в вашем|для вашего) регион",
      "not available in your (region|country|location)",
      "access denied[\\s\\S]{0,60}(country|region|your ip|ваш ip)",
      "antibot challenge",
    ].join("|"),
    "i",
  );

  function bodyText() {
    return ((document.body && document.body.innerText) || "").slice(0, 4000);
  }

  function check(reason) {
    const title = document.title || "";
    const body = bodyText();
    let signal = null;

    if (TITLE_RE.test(title)) signal = "title";
    else if (BODY_RE.test(body)) signal = "text";
    else if (
      body.length < 1500 &&
      /\bvpn\b|\bпрокси\b|\brobot\b|\bробот\b/i.test(body) &&
      /disable|отключ|выключ|enable javascript|включите/i.test(body)
    ) {
      signal = "short-page";
    }

    if (!signal) return false;
    try {
      chrome.runtime.sendMessage({
        type: "challengeDetected",
        host: location.hostname,
        url: location.href.slice(0, 300),
        title: title.slice(0, 120),
        signal,
        reason,
      });
    } catch (_) {}
    return true;
  }

  if (!check("idle")) setTimeout(() => check("delayed"), 3500);
})();
