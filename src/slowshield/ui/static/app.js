// SlowShield UI helpers (served from 'self'; no inline handlers so the CSP can forbid inline script).
(() => {
  "use strict";
  const KEY = "slowshield-theme";
  const root = document.documentElement;
  try {
    const saved = localStorage.getItem(KEY);
    if (saved === "dark" || saved === "light") root.dataset.theme = saved;
  } catch (_) { /* storage may be blocked */ }

  // Tabs (Setup page). The server preselects the shell from the visitor's OS; their last choice wins.
  const SHELL_KEY = "slowshield-shell";
  document.querySelectorAll("[data-tabs]").forEach((tabs) => {
    const buttons = [...tabs.querySelectorAll('[role="tab"]')];
    const shell = tabs.dataset.tabs === "shell";
    const select = (btn, user = true) => {
      for (const b of buttons) {
        const on = b === btn;
        b.setAttribute("aria-selected", String(on));
        b.tabIndex = on ? 0 : -1;
        document.getElementById(b.getAttribute("aria-controls")).hidden = !on;
      }
      if (!user) return;
      btn.focus();
      if (shell) {
        try { localStorage.setItem(SHELL_KEY, btn.dataset.shell); } catch (_) { /* storage blocked: fine */ }
      }
    };
    tabs.addEventListener("click", (event) => {
      const btn = event.target.closest('[role="tab"]');
      if (btn) select(btn);
    });
    tabs.addEventListener("keydown", (event) => {
      const i = buttons.indexOf(document.activeElement);
      if (i < 0) return;
      if (event.key === "ArrowRight") select(buttons[(i + 1) % buttons.length]);
      if (event.key === "ArrowLeft") select(buttons[(i - 1 + buttons.length) % buttons.length]);
    });
    if (shell) {
      let saved = null;
      try { saved = localStorage.getItem(SHELL_KEY); } catch (_) { /* ignore */ }
      const btn = buttons.find((b) => b.dataset.shell === saved);
      if (btn) select(btn, false);
    }
  });

  document.addEventListener("click", (event) => {
    const toggle = event.target.closest("[data-theme-toggle]");
    if (toggle) {
      const dark = root.dataset.theme
        ? root.dataset.theme === "dark"
        : window.matchMedia("(prefers-color-scheme: dark)").matches;
      root.dataset.theme = dark ? "light" : "dark";
      try { localStorage.setItem(KEY, root.dataset.theme); } catch (_) { /* ignore */ }
      return;
    }
    const copy = event.target.closest("[data-copy]");
    if (copy) {
      const code = copy.parentElement.querySelector("code");
      if (!code || !navigator.clipboard) return;
      navigator.clipboard.writeText(code.textContent).then(() => {
        copy.textContent = "Copied";
        copy.classList.add("done");
        setTimeout(() => { copy.textContent = "Copy"; copy.classList.remove("done"); }, 1500);
      });
    }
  });
})();
