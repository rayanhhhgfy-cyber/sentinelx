/* Nexora contact-form.js — AJAX contact submission (no CSRF token — intentional) */
(function () {
  "use strict";
  var form = document.getElementById("nx-contact");
  if (!form) return;
  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var payload = {
      name: form.querySelector('input[name="name"]').value,
      email: form.querySelector('input[name="email"]').value,
      message: form.querySelector('textarea[name="message"]').value
    };
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/contact", true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onreadystatechange = function () {
      if (xhr.readyState === 4 && xhr.status === 200) {
        var d = JSON.parse(xhr.responseText);
        document.getElementById("nx-contact-msg").textContent = d.message;
      }
    };
    xhr.send(JSON.stringify(payload));
  });
})();
