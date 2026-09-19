// ==UserScript==
// @name         CSQTT-Keenetic VK Auto Auth
// @namespace    https://github.com/Xenofan-git/CSQTT-Keenetic
// @version      1.0.0
// @description  Automatically returns VK implicit OAuth token from blank.html to CSQTT-Keenetic.
// @match        https://oauth.vk.ru/blank.html*
// @match        https://oauth.vk.com/blank.html*
// @run-at       document-start
// ==/UserScript==

(() => {
  const p = new URLSearchParams(location.hash.replace(/^#/, ""));
  const token = p.get("access_token") || "";
  const userId = p.get("user_id") || "";
  const expiresIn = p.get("expires_in") || "0";
  const state = p.get("state") || "";
  if (!token || !state) return;

  let encoded = state.replace(/-/g, "+").replace(/_/g, "/");
  while (encoded.length % 4) encoded += "=";

  let raw;
  try {
    raw = decodeURIComponent(escape(atob(encoded)));
  } catch (_) {
    return;
  }

  const separator = raw.indexOf("|");
  if (separator <= 0) return;

  const panel = raw.slice(0, separator);
  if (!/^https?:\/\//i.test(panel)) return;

  const form = document.createElement("form");
  form.method = "POST";
  form.action = panel + "/api/vk/token";
  form.style.display = "none";

  for (const [name, value] of [
    ["token", token],
    ["user_id", userId],
    ["expires_in", expiresIn],
    ["state", state],
  ]) {
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    input.value = value;
    form.appendChild(input);
  }

  (document.documentElement || document.body).appendChild(form);
  form.submit();
})();
