/* Nexora main.js — navigation + client spotlight widget */
(function () {
  "use strict";

  // Client spotlight: pull a featured client from the API
  var spot = document.getElementById("spotlight-body");
  if (spot) {
    fetch("/api/clients/1")
      .then(function (r) { return r.json(); })
      .then(function (c) {
        spot.textContent = c.name + " — $" + c.contract_value + " engagement";
      })
      .catch(function () { spot.textContent = "Spotlight unavailable."; });
  }

  // Active nav highlighting
  var path = window.location.pathname;
  var links = document.querySelectorAll("nav a");
  for (var i = 0; i < links.length; i++) {
    if (links[i].getAttribute("href") === path) {
      links[i].classList.add("active");
    }
  }

  // Remember last visit for the welcome-back banner
  try {
    localStorage.setItem("nx_last_visit", new Date().toISOString());
  } catch (e) { /* storage unavailable */ }
})();
