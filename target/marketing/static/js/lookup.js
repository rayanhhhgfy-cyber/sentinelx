/* Nexora lookup.js — whitepaper lookup widget.
   Calls /api/v1/lookup with a FULL request shape: custom headers + JSON
   body. A smart scanner reconstructs method+headers+body purely from this
   file (no robots.txt / docs mention it anywhere). */
(function () {
  "use strict";

  var form = document.getElementById("nx-lookup");
  if (!form) return;

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var code = document.getElementById("lookup-code").value;

    fetch("/api/v1/lookup", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Request-ID": "web-001",
        "X-Client-Version": "2.4.1"
      },
      body: JSON.stringify({ code: code, verbose: true })
    })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var box = document.getElementById("nx-lookup-result");
        if (d.error) {
          box.textContent = "Error: " + d.error;
        } else if (d.result) {
          box.textContent = "Found: " + d.result;
        } else {
          box.textContent = "No whitepaper matches that code.";
        }
      })
      .catch(function () {
        document.getElementById("nx-lookup-result").textContent =
          "Lookup unavailable.";
      });
  });
})();
