// SlowShield UI helpers (served from 'self'; no inline handlers so the CSP can forbid inline script).
(() => {
  "use strict";
  const KEY = "slowshield-theme";
  const root = document.documentElement;
  try {
    const saved = localStorage.getItem(KEY);
    if (saved === "dark" || saved === "light") root.dataset.theme = saved;
  } catch (_) { /* storage may be blocked */ }

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
