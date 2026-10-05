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

// Scrollytelling: each chapter of How it works has its own pinned diagram, driven by the step at the reading line.
// data-step picks that step's layers and --p (0 to 1: how far the reading line is through the step) plays it, so the
// diagram follows the scroll in both directions. Before a chapter's first step its diagram rests (data-rest, --p 0);
// after its last it keeps that step's end. With reduced motion, --p stays 1 and every step shows how it ends.
const chapters = [...document.querySelectorAll(".story")].map((story) => ({
  figure: story.querySelector(".story-figure"),
  steps: [...story.querySelectorAll(".step")],
})).filter((c) => c.figure && c.steps.length);
if (chapters.length) {
  // On narrow screens the diagram is pinned at the top, so the text is read between it and the bottom.
  const narrow = window.matchMedia("(max-width: 900px)");
  const clamp = (v) => Math.min(1, Math.max(0, v));
  let frame = 0;
  const update = () => {
    frame = 0;
    const vh = window.innerHeight;
    for (const { figure, steps } of chapters) {
      const pinnedTop = parseFloat(getComputedStyle(figure).top) || 0;  // also where the pinned title ends
      const pinnedBottom = pinnedTop + figure.offsetHeight;
      const line = narrow.matches ? (pinnedBottom + vh) / 2 : vh / 2;
      let step = figure.dataset.rest;
      let progress = 0;
      for (const s of steps) {
        const r = s.getBoundingClientRect();
        const inside = r.top <= line && r.bottom > line;
        s.classList.toggle("active", inside);
        if (r.top > line) continue;
        step = s.dataset.step;
        progress = Math.min(1, (line - r.top) / r.height);
      }
      figure.dataset.step = step;
      figure.style.setProperty("--p", reduceMotion ? "1" : progress.toFixed(3));
      if (narrow.matches) continue;
      // Wide screens: below the reading line, a step's text fades in and rises as it comes within 0.5 to 0.2
      // viewport heights of it; above, it fades out over the 0.15 before its top reaches the pinned title.
      for (const s of steps) {
        const r = s.getBoundingClientRect();
        const d = (r.top + r.height / 2 - line) / vh;
        const below = d > 0 ? clamp((0.5 - d) / 0.3) : 1;
        const above = clamp((s.firstElementChild.getBoundingClientRect().top - pinnedTop) / (0.15 * vh));
        s.style.setProperty("--in", (below * above).toFixed(3));
        s.style.setProperty("--rise", reduceMotion ? "0" : (1 - below).toFixed(3));
      }
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
