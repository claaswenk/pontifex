// Pontifex UI. Loaded from 'self' only: the Content-Security-Policy allows no
// inline scripts and no eval. Every page works without this file; it only adds
// live behaviour on top.
(function () {
  "use strict";

  // Forms marked data-enhance are sent in the background and the page content is
  // replaced by the answer, so nothing reloads and nothing typed is lost. The
  // server answers exactly as it does without this file (a redirect to the page),
  // and only <main> and the header are taken from the answer.
  var MAX_SIDE = 256;

  // A chosen picture is scaled down in the browser (this also drops its metadata).
  // If that is not possible the original goes along and the server checks it.
  function shrink(file) {
    if (!file || !window.createImageBitmap || !window.HTMLCanvasElement) {
      return Promise.resolve(file);
    }
    return window.createImageBitmap(file).then(function (bitmap) {
      var scale = Math.min(1, MAX_SIDE / Math.max(bitmap.width, bitmap.height));
      var canvas = document.createElement("canvas");
      canvas.width = Math.max(1, Math.round(bitmap.width * scale));
      canvas.height = Math.max(1, Math.round(bitmap.height * scale));
      canvas.getContext("2d").drawImage(bitmap, 0, 0, canvas.width, canvas.height);
      var type = file.type === "image/png" ? "image/png" : "image/jpeg";
      return new Promise(function (resolve) {
        canvas.toBlob(function (blob) {
          resolve(blob && blob.size < file.size ? new File([blob], "picture", { type: type }) : file);
        }, type, 0.85);
      });
    }).catch(function () { return file; });
  }

  function body(form) {
    var data = new FormData(form);
    var pending = [];
    form.querySelectorAll('input[type="file"]').forEach(function (input) {
      if (input.files && input.files.length) {
        pending.push(shrink(input.files[0]).then(function (file) {
          data.set(input.name, file, file.name || "picture");
        }));
      }
    });
    return Promise.all(pending).then(function () { return data; });
  }

  function swap(html) {
    var doc = new DOMParser().parseFromString(html, "text/html");
    ["header.topbar", "main.page"].forEach(function (selector) {
      var fresh = doc.querySelector(selector);
      var old = document.querySelector(selector);
      if (fresh && old) { old.replaceWith(document.importNode(fresh, true)); }
    });
    var title = doc.querySelector("title");
    if (title) { document.title = title.textContent; }
    fadeNotices();
  }

  // Messages stay for 5 seconds, then fade out and are removed.
  var NOTICE_MS = 5000;
  var FADE_MS = 600;
  function fadeNotices() {
    document.querySelectorAll("[data-flash]:not([data-timed])").forEach(function (notice) {
      notice.setAttribute("data-timed", "");
      window.setTimeout(function () {
        notice.classList.add("is-fading");
        window.setTimeout(function () { notice.remove(); }, FADE_MS);
      }, NOTICE_MS);
    });
  }
  fadeNotices();

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!form.hasAttribute || !form.hasAttribute("data-enhance") || !window.fetch || !window.FormData) {
      return;
    }
    event.preventDefault();
    var pressed = event.submitter || form.querySelector('button[type="submit"]');
    form.querySelectorAll("button").forEach(function (b) { b.disabled = true; });
    if (pressed) { pressed.classList.add("is-loading"); }
    body(form).then(function (data) {
      return window.fetch(form.action, {
        method: "POST", body: data, credentials: "same-origin", redirect: "follow",
      });
    }).then(function (response) {
      var type = response.headers.get("Content-Type") || "";
      if (response.redirected && new URL(response.url).pathname === "/login") {
        window.location.assign(response.url);  // the session ended
        return null;
      }
      if (type.indexOf("text/html") !== 0) { throw new Error("unexpected answer"); }
      return response.text().then(swap);
    }).catch(function () {
      // Never send the form a second time: the server may have acted already.
      window.location.reload();
    });
  });

  // A chosen picture is shown in the round field right away. It is drawn on a
  // canvas (square crop), because the CSP allows no blob: or data: images.
  document.addEventListener("change", function (event) {
    var input = event.target;
    if (!input.matches || !input.matches("[data-picture-input]")) { return; }
    var pick = input.parentNode.querySelector(".pic-pick");
    var canvas = pick && pick.querySelector("canvas");
    if (!canvas) { return; }
    var reset = function () {
      pick.classList.remove("has-preview");
      canvas.hidden = true;
    };
    if (!input.files || !input.files.length || !window.createImageBitmap) { reset(); return; }
    window.createImageBitmap(input.files[0]).then(function (bitmap) {
      var side = Math.min(bitmap.width, bitmap.height);
      canvas.getContext("2d").drawImage(
        bitmap, (bitmap.width - side) / 2, (bitmap.height - side) / 2, side, side,
        0, 0, canvas.width, canvas.height
      );
      canvas.hidden = false;
      pick.classList.add("has-preview");
    }).catch(reset);
  });

  // The device list refreshes by itself. It reads /devices/live, which does not
  // extend the session, and fails quietly: the next tick simply tries again.
  var REFRESH_MS = 10000;
  function applyLive(data) {
    (data.devices || []).forEach(function (device) {
      var row = document.querySelector('tr[data-device-id="' + device.id + '"]');
      if (!row) { return; }
      var state = device.status === "online" ? "online" : "offline";
      row.setAttribute("data-state", state);
      var badge = row.querySelector(".status");
      if (badge) {
        badge.classList.toggle("status--online", state === "online");
        badge.classList.toggle("status--offline", state === "offline");
      }
      var text = row.querySelector(".status__text");
      if (text) { text.textContent = state === "online" ? "Online" : "Offline"; }
      var latency = row.querySelector("[data-latency]");
      if (latency) {
        latency.textContent = typeof device.latency_ms === "number"
          ? Math.round(device.latency_ms * 10) / 10 + " ms" : "-";
      }
    });
    var summary = data.summary || {};
    ["total", "online", "offline"].forEach(function (key) {
      var tile = document.querySelector('[data-count="' + key + '"]');
      if (tile && typeof summary[key] === "number") { tile.textContent = summary[key]; }
    });
  }

  function refresh() {
    var live = document.querySelector("[data-live]");
    if (!live || document.hidden || !window.fetch) { return; }
    window.fetch(live.getAttribute("data-live"), {
      credentials: "same-origin", headers: { Accept: "application/json" },
    }).then(function (response) {
      if (response.redirected && new URL(response.url).pathname === "/login") {
        window.location.assign(response.url);  // the session ended
        return null;
      }
      var type = response.headers.get("Content-Type") || "";
      if (!response.ok || type.indexOf("application/json") !== 0) { return null; }
      return response.json();
    }).then(function (data) {
      if (data) { applyLive(data); }
    }).catch(function () { /* try again at the next tick */ });
  }
  window.setInterval(refresh, REFRESH_MS);

  // The footer shows the server's clock. The server renders the time once; here
  // it keeps ticking, based on the server's epoch so a wrong clock in the
  // browser does not matter.
  var clock = document.getElementById("server-time");
  if (clock) {
    var epoch = parseInt(clock.getAttribute("data-epoch"), 10);
    if (!isNaN(epoch)) {
      var offset = epoch * 1000 - Date.now();
      var pad = function (n) { return (n < 10 ? "0" : "") + n; };
      var tick = function () {
        var d = new Date(Date.now() + offset);
        clock.textContent =
          d.getUTCFullYear() + "-" + pad(d.getUTCMonth() + 1) + "-" + pad(d.getUTCDate()) + " " +
          pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + ":" + pad(d.getUTCSeconds()) + " UTC";
      };
      tick();
      window.setInterval(tick, 1000);
    }
  }
})();
