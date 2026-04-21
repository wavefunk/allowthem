// mode-toggle.js — persisted dark/light toggle for allowthem.
//
// Contract:
//   - On load: read localStorage["allowthem:mode"], apply to <html data-mode>.
//     If unset, leave the attribute alone (server default = dark; no attr).
//   - On click of any [data-mode-toggle]: flip, persist, update button label.
//   - When <html data-mode-locked> is present (tenant forced a mode),
//     the toggle is hidden via CSS and this script is a no-op on click.
//
// Kept tiny on purpose. No dependencies. Runs in module-less <script> tag.

(function () {
  "use strict";

  var KEY = "allowthem:mode";
  var html = document.documentElement;

  function currentMode() {
    return html.getAttribute("data-mode") || "dark";
  }

  function labelFor(mode) {
    // Show the mode you'd switch *to* on click.
    return mode === "dark" ? "light" : "dark";
  }

  function paintButtons() {
    var next = labelFor(currentMode());
    var buttons = document.querySelectorAll("[data-mode-toggle]");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].setAttribute("data-next-mode", next);
    }
  }

  // Apply stored preference unless tenant has locked the mode.
  if (!html.hasAttribute("data-mode-locked")) {
    try {
      var stored = window.localStorage.getItem(KEY);
      if (stored === "dark" || stored === "light") {
        html.setAttribute("data-mode", stored);
      }
    } catch (_e) {
      // Private mode / disabled storage — ignore.
    }
  }

  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest && ev.target.closest("[data-mode-toggle]");
    if (!btn) return;
    if (html.hasAttribute("data-mode-locked")) return;
    var next = labelFor(currentMode());
    html.setAttribute("data-mode", next);
    try {
      window.localStorage.setItem(KEY, next);
    } catch (_e) {}
    paintButtons();
  });

  paintButtons();
})();
