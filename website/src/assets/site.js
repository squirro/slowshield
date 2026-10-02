// slowshield.net — progressive enhancement only; the page is complete without JavaScript.
const root = document.documentElement;
root.classList.remove("no-js");
root.classList.add("js");

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const scrollDriven = CSS.supports("animation-timeline: view()");

// Fallback reveal for browsers without CSS scroll-driven animations.
if (!scrollDriven && !reduceMotion && "IntersectionObserver" in window) {
  root.classList.add("no-sda");
  const io = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (e.isIntersecting) {
          e.target.classList.add("in");
          io.unobserve(e.target);
        }
      }
    },
    { rootMargin: "0px 0px -12% 0px" },
  );
  document.querySelectorAll(".reveal").forEach((el) => io.observe(el));
}

// Scrollytelling: the step closest to the middle of the viewport drives the pinned diagram.
const figure = document.querySelector(".story-figure");
const steps = [...document.querySelectorAll(".step")];
if (figure && steps.length && "IntersectionObserver" in window) {
  const io = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        const n = e.target.dataset.step;
        figure.dataset.step = n;
        steps.forEach((s) => s.classList.toggle("active", s === e.target));
      }
    },
    { rootMargin: "-45% 0px -45% 0px", threshold: 0 },
  );
  steps.forEach((s) => io.observe(s));
}

// Tabs (Get started).
document.querySelectorAll("[data-tabs]").forEach((tabs) => {
  const buttons = [...tabs.querySelectorAll('[role="tab"]')];
  const select = (btn) => {
    for (const b of buttons) {
      const on = b === btn;
      b.setAttribute("aria-selected", String(on));
      b.tabIndex = on ? 0 : -1;
      document.getElementById(b.getAttribute("aria-controls")).hidden = !on;
    }
    btn.focus();
  };
  tabs.addEventListener("click", (e) => {
    const btn = e.target.closest('[role="tab"]');
    if (btn) select(btn);
  });
  tabs.addEventListener("keydown", (e) => {
    const i = buttons.indexOf(document.activeElement);
    if (i < 0) return;
    if (e.key === "ArrowRight") select(buttons[(i + 1) % buttons.length]);
    if (e.key === "ArrowLeft") select(buttons[(i - 1 + buttons.length) % buttons.length]);
  });
});

// Copy buttons.
document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-copy]");
  if (!btn || !navigator.clipboard) return;
  const code = btn.parentElement.querySelector("code");
  navigator.clipboard.writeText(code.textContent).then(() => {
    btn.textContent = "Copied";
    btn.classList.add("done");
    setTimeout(() => {
      btn.textContent = "Copy";
      btn.classList.remove("done");
    }, 1600);
  });
});

// Pause ambient animations while off-screen (battery-friendly).
if ("IntersectionObserver" in window) {
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) e.target.classList.toggle("paused", !e.isIntersecting);
  });
  document.querySelectorAll(".hero-art, .edge-map, .sun").forEach((el) => io.observe(el));
}
