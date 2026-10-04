// k6 load scenarios for SlowShield. Driven entirely by environment variables so the Python runner
// (perf/runner.py) can sweep scenarios and A/B images without editing this file.
//
//   TARGET     base URL of the instance under test, e.g. http://127.0.0.1:18080
//   SCENARIO   one of the keys in SCENARIOS below
//   MODE       "latency" (constant arrival rate, open model) or "throughput" (constant VUs, closed model)
//   RATE       requests/s for latency mode           (default 200)
//   VUS        virtual users for throughput mode     (default 32)
//   DURATION   e.g. "20s"                            (default 20s)
import http from "k6/http";
import { check } from "k6";

const TARGET = __ENV.TARGET || "http://127.0.0.1:18080";
const MODE = __ENV.MODE || "latency";
const RATE = parseInt(__ENV.RATE || "200", 10);
const VUS = parseInt(__ENV.VUS || "32", 10);
const DURATION = __ENV.DURATION || "20s";

const JSON_ACCEPT = { headers: { Accept: "application/vnd.pypi.simple.v1+json" } };
const HTML_ACCEPT = { headers: { Accept: "text/html" } };
const CORGI = { headers: { Accept: "application/vnd.npm.install-v1+json" } };
const FULL = { headers: { Accept: "application/json" } };
// k6 counts every status >= 400 as a failed request. For the blocked request 451 is the success and
// anything else (a 200 serves the malware) the failure; setup() requests keep the default.
const BLOCKED = { ...JSON_ACCEPT, responseCallback: http.expectedStatuses(451) };

// Index URLs are relative ("../../packages/..") to the project page; resolve them against /pypi/.
function resolve(url) {
  return url.startsWith("http") ? url : `${TARGET}/pypi/${url.replace(/^(\.\.\/)+/, "")}`;
}

// Artifact paths are discovered at setup() from the proxy's own index so the script stays generic.
function discover() {
  const out = {};
  const idx = http.get(`${TARGET}/pypi/simple/alpha/`, JSON_ACCEPT);
  if (idx.status === 200) {
    const files = idx.json("files") || [];
    const wheel = files.find((f) => f.filename.endsWith(".whl")) || files[0];
    if (wheel) out.small = resolve(wheel.url);
  }
  const big = http.get(`${TARGET}/pypi/simple/big-wheel/`, JSON_ACCEPT);
  if (big.status === 200) {
    const files = big.json("files") || [];
    if (files.length) out.big = resolve(files[0].url);
  }
  return out;
}

const SCENARIOS = {
  pypi_simple_json: () => http.get(`${TARGET}/pypi/simple/many-versions/`, JSON_ACCEPT),
  pypi_simple_html: () => http.get(`${TARGET}/pypi/simple/many-versions/`, HTML_ACCEPT),
  npm_packument_full: () => http.get(`${TARGET}/npm/left-pad-ng`, FULL),
  npm_packument_corgi: () => http.get(`${TARGET}/npm/left-pad-ng`, CORGI),
  npm_huge_full: () => http.get(`${TARGET}/npm/huge-packument`, FULL),
  npm_huge_corgi: () => http.get(`${TARGET}/npm/huge-packument`, CORGI),
  artifact_cached: (d) => http.get(d.small),
  artifact_big: (d) => http.get(d.big, { responseType: "none", timeout: "120s" }),
  blocked: () => http.get(`${TARGET}/pypi/simple/malware-pkg/`, BLOCKED),
  dashboard: () => http.get(`${TARGET}/`),
  mixed: (d) => {
    const r = Math.random();
    if (r < 0.45) return http.get(`${TARGET}/pypi/simple/alpha/`, JSON_ACCEPT);
    if (r < 0.75) return http.get(`${TARGET}/npm/@acme%2fwidget`, CORGI);
    if (r < 0.95) return http.get(d.small);
    return http.get(`${TARGET}/npm/tagged`, FULL);
  },
};

const scenarioName = __ENV.SCENARIO || "pypi_simple_json";
const run = SCENARIOS[scenarioName];
if (!run) throw new Error(`unknown SCENARIO ${scenarioName}`);

export const options = {
  discardResponseBodies: scenarioName === "artifact_big",
  summaryTrendStats: ["avg", "min", "med", "p(90)", "p(95)", "p(99)", "max"],
  scenarios: {
    main:
      MODE === "throughput"
        ? { executor: "constant-vus", vus: VUS, duration: DURATION }
        : {
            executor: "constant-arrival-rate",
            rate: RATE,
            timeUnit: "1s",
            duration: DURATION,
            preAllocatedVUs: Math.max(50, Math.ceil(RATE / 10)),
            maxVUs: Math.max(200, RATE),
          },
  },
};

export function setup() {
  return discover();
}

export default function (data) {
  const res = run(data);
  const expected = scenarioName === "blocked" ? 451 : 200;
  check(res, { status: (r) => r.status === expected });
}
