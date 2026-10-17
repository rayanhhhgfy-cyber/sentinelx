/* Nexora analytics.js — internal stats beacon.
   INTENTIONAL: hardcoded API key + unauthenticated internal endpoint. */
(function () {
  "use strict";

  var NX_API_KEY = "nx_live_9f8e7d6c5b4a31287";

  function beacon() {
    fetch("/api/internal/stats", {
      method: "GET",
      headers: { "X-Api-Key": NX_API_KEY }
    })
      .then(function (r) { return r.json(); })
      .then(function (stats) {
        try {
          sessionStorage.setItem("nx_stats_snapshot", JSON.stringify(stats));
        } catch (e) { /* ignore */ }
      })
      .catch(function () { /* stats endpoint optional */ });
  }

  // fire once per page view
  if (document.readyState === "complete") {
    beacon();
  } else {
    window.addEventListener("load", beacon);
  }
})();
