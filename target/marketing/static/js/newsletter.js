/* Nexora newsletter.js — signup form + promo banner from URL fragment */
(function () {
  "use strict";

  // INTENTIONAL DOM XSS: promo code from the URL fragment is written
  // straight into innerHTML with no sanitization.
  // e.g. https://site/#<img src=x onerror=alert(1)>
  var promo = window.location.hash.slice(1);
  if (promo) {
    var box = document.getElementById("nx-promo");
    if (box) {
      box.innerHTML = "Promo applied: " + decodeURIComponent(promo);
    }
  }

  var form = document.getElementById("nx-newsletter");
  if (!form) return;
  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var email = form.querySelector('input[name="email"]').value;
    fetch("/api/newsletter", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email })
    })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        document.getElementById("nx-news-msg").textContent = d.message;
      });
  });
})();
