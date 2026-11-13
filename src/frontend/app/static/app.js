// Pontifex UI. Loaded from 'self' only: the Content-Security-Policy allows no
// inline scripts and no eval. Every page works without this file; it only adds
// live behaviour on top.
(function () {
  "use strict";

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
