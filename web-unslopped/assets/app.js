document.addEventListener("DOMContentLoaded", function () {
  // data-filter inputs filter sibling .row-list .row elements by text.
  document.querySelectorAll("input[data-filter]").forEach(function (input) {
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      var scope = input.closest(".section") || document;
      var rows = scope.querySelectorAll(".row-list .row");
      rows.forEach(function (row) {
        row.style.display =
          row.textContent.toLowerCase().indexOf(q) === -1 ? "none" : "";
      });
    });
  });

  // data-copy buttons copy the previous sibling's text, label "Copied" for 1.5s.
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var text = btn.previousElementSibling
        ? btn.previousElementSibling.innerText
        : "";
      var label = btn.textContent;
      function done() {
        btn.textContent = "Copied";
        setTimeout(function () {
          btn.textContent = label;
        }, 1500);
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, done);
      } else {
        done();
      }
    });
  });

  // Login form goes to the overview.
  var login = document.getElementById("login-form");
  if (login) {
    login.addEventListener("submit", function (e) {
      e.preventDefault();
      window.location.href = "overview.html";
    });
  }

  // New-scan form goes to the live scan.
  var scan = document.getElementById("new-scan-form");
  if (scan) {
    scan.addEventListener("submit", function (e) {
      e.preventDefault();
      window.location.href = "scan.html";
    });
  }

  // Settings form stays; the submit button reads "Saved" for 2s.
  var settings = document.getElementById("settings-form");
  if (settings) {
    settings.addEventListener("submit", function (e) {
      e.preventDefault();
      var btn = settings.querySelector('button[type="submit"]');
      if (!btn) return;
      var label = btn.textContent;
      btn.textContent = "Saved";
      setTimeout(function () {
        btn.textContent = label;
      }, 2000);
    });
  }
});
