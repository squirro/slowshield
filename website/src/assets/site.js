// slowshield.org — progressive enhancement only; the page is complete without JavaScript.
const root = document.documentElement;
root.classList.remove("no-js");
root.classList.add("js");

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// Headline: a random variant first, then the others in a random order (each shown once before any repeats),
// fading every six seconds. Without JavaScript the first one shows. With reduced motion it is a plain fade,
// without the slide (see site.css).
const headlines = [...document.querySelectorAll("[data-hl]")];
if (headlines.length > 1) {
  const rand = (n) => crypto.getRandomValues(new Uint32Array(1))[0] % n;
  const shuffled = (items) => {
    const a = [...items];
    for (let i = a.length - 1; i > 0; i--) { const j = rand(i + 1); [a[i], a[j]] = [a[j], a[i]]; }
    return a;
  };
  let current = rand(headlines.length);
  let queue = [];
  const next = () => {
    if (!queue.length) queue = shuffled(headlines.keys()).filter((i) => i !== current);
    current = queue.shift();
    return current;
  };
  const show = (n) => headlines.forEach((el, i) => {
    el.classList.toggle("on", i === n);
    el.setAttribute("aria-hidden", String(i !== n));
  });
  headlines.forEach((el) => { el.hidden = false; });
  headlines[0].parentElement.classList.add("rotating");
  show(current);
  let timer = 0;
  const start = () => { timer = window.setInterval(() => show(next()), 6000); };
  document.addEventListener("visibilitychange", () => { window.clearInterval(timer); if (!document.hidden) start(); });
  start();
}

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

// Scrollytelling: the step at the reading line drives the pinned diagram. data-step picks that step's layers and --p
// (0 to 1: how far the reading line is through the step) plays it, so the diagram follows the scroll in both
// directions. With reduced motion, --p stays 1 and every step shows how it ends.
const figure = document.querySelector(".story-figure");
const steps = [...document.querySelectorAll(".step")];
if (figure && steps.length) {
  // On narrow screens the diagram is pinned at the top, so the text is read further down.
  const narrow = window.matchMedia("(max-width: 900px)");
  let frame = 0;
  const update = () => {
    frame = 0;
    const line = window.innerHeight * (narrow.matches ? 0.72 : 0.5);
    let step = "0";
    let progress = 0;
    let active = null;
    for (const s of steps) {
      const r = s.getBoundingClientRect();
      if (r.top > line) break;
      step = s.dataset.step;
      active = s;
      progress = Math.min(1, (line - r.top) / r.height);
    }
    figure.dataset.step = step;
    figure.style.setProperty("--p", reduceMotion ? "1" : progress.toFixed(3));
    steps.forEach((s) => s.classList.toggle("active", s === active));
    if (narrow.matches) return;
    // Wide screens: each step's text by its distance from the reading line, in viewport heights. Within 0.2 it is
    // fully shown; below, it fades in and rises over the 0.3 before that; above, it dims to a quarter.
    const clamp = (v) => Math.min(1, Math.max(0, v));
    for (const s of steps) {
      const r = s.getBoundingClientRect();
      const d = (r.top + r.height / 2 - line) / window.innerHeight;
      const below = d > 0 ? clamp((0.5 - d) / 0.3) : 1;
      const above = d < 0 ? 0.25 + 0.75 * clamp((0.45 + d) / 0.25) : 1;
      s.style.setProperty("--in", (below * above).toFixed(3));
      s.style.setProperty("--rise", reduceMotion ? "0" : (1 - below).toFixed(3));
    }
  };
  const queue = () => { if (!frame) frame = requestAnimationFrame(update); };
  window.addEventListener("scroll", queue, { passive: true });
  window.addEventListener("resize", queue);
  update();
}

// Tabs (Get started).
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
      try { localStorage.setItem("ss-shell", btn.dataset.shell); } catch { /* storage blocked: fine */ }
    }
  };
  tabs.addEventListener("click", (e) => {
    const btn = e.target.closest('[role="tab"]');
    if (btn) select(btn);
  });
  // Shell snippets: the visitor's last choice, else a guess from the OS (zsh on macOS, bash elsewhere).
  if (shell) {
    let want = null;
    try { want = localStorage.getItem("ss-shell"); } catch { /* ignore */ }
    if (!want) {
      const os = (navigator.userAgentData?.platform || navigator.platform || "").toLowerCase();
      want = os.includes("mac") ? "zsh" : "bash";
    }
    const btn = buttons.find((b) => b.dataset.shell === want);
    if (btn) select(btn, false);
  }
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

// Caching diagram: an office and a cloud region near the visitor, taken only from the time zone setting
// (no geolocation API, so never a permission prompt). Fallback: San Francisco and us-east-1.
const officeLabel = document.querySelector('[data-loc="office"]');
const prodLabel = document.querySelector('[data-loc="prod"]');
if (officeLabel && prodLabel) {
  const PLACES = {
    "Europe/Zurich": ["Zurich", "eu-central-2"], "Europe/Berlin": ["Berlin", "eu-central-1"],
    "Europe/Vienna": ["Vienna", "eu-central-1"], "Europe/Paris": ["Paris", "eu-west-3"],
    "Europe/London": ["London", "eu-west-2"], "Europe/Dublin": ["Dublin", "eu-west-1"],
    "Europe/Amsterdam": ["Amsterdam", "eu-west-1"], "Europe/Madrid": ["Madrid", "eu-south-2"],
    "Europe/Rome": ["Milan", "eu-south-1"], "Europe/Stockholm": ["Stockholm", "eu-north-1"],
    "America/New_York": ["New York", "us-east-1"], "America/Toronto": ["Toronto", "ca-central-1"],
    "America/Chicago": ["Chicago", "us-east-2"], "America/Denver": ["Denver", "us-west-2"],
    "America/Los_Angeles": ["San Francisco", "us-west-1"], "America/Vancouver": ["Vancouver", "ca-west-1"],
    "America/Sao_Paulo": ["São Paulo", "sa-east-1"], "Asia/Tokyo": ["Tokyo", "ap-northeast-1"],
    "Asia/Seoul": ["Seoul", "ap-northeast-2"], "Asia/Singapore": ["Singapore", "ap-southeast-1"],
    "Asia/Hong_Kong": ["Hong Kong", "ap-east-1"], "Asia/Kolkata": ["Mumbai", "ap-south-1"],
    "Asia/Calcutta": ["Mumbai", "ap-south-1"], "Asia/Dubai": ["Dubai", "me-central-1"],
    "Asia/Jerusalem": ["Tel Aviv", "il-central-1"], "Asia/Jakarta": ["Jakarta", "ap-southeast-3"],
    "Australia/Sydney": ["Sydney", "ap-southeast-2"], "Australia/Melbourne": ["Melbourne", "ap-southeast-4"],
    "Africa/Johannesburg": ["Johannesburg", "af-south-1"],
  };
  const REGION_BY_CONTINENT = { Europe: "eu-central-1", America: "us-east-1", Asia: "ap-southeast-1",
    Australia: "ap-southeast-2", Africa: "af-south-1" };
  let tz = "";
  try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch { /* keep the fallback */ }
  let place = PLACES[tz];
  if (!place) {
    const [continent, ...rest] = tz.split("/");
    if (REGION_BY_CONTINENT[continent] && rest.length) {
      place = [rest[rest.length - 1].replaceAll("_", " "), REGION_BY_CONTINENT[continent]];
    }
  }
  if (place) {
    officeLabel.textContent = `Office · ${place[0]}`;
    prodLabel.textContent = `Production · ${place[1]}`;
  }
}
