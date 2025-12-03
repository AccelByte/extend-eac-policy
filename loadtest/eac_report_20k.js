import http from "k6/http";
import { check, fail } from "k6";

const mockMode = (__ENV.MOCK_MODE || "true").toLowerCase() === "true";
const baseURL = (__ENV.BASE_URL || "http://127.0.0.1:18000").replace(/\/$/, "");
const basePath = (__ENV.BASE_PATH || "").replace(/\/$/, "");

const iterations = Number(__ENV.ITERATIONS || 20000);
const vus = Number(__ENV.VUS || 200);

const publicToken = __ENV.PUBLIC_TOKEN || (mockMode ? "mock-public" : "");

if (!mockMode && !publicToken) {
  fail("PUBLIC_TOKEN must be set when MOCK_MODE=false");
}

export const options = {
  scenarios: {
    fixedIterations: {
      executor: "shared-iterations",
      vus,
      iterations,
      maxDuration: __ENV.MAX_DURATION || "10m",
    },
  },
  thresholds: {
    http_req_duration: ["p(95)<500", "p(99)<1000"],
    http_req_failed: ["rate<0.01"],
  },
};

const reasons = [
  "CLIENT_ACTION_REASON_CLIENT_VIOLATION",
  "CLIENT_ACTION_REASON_CLIENT_VIOLATION_WIN",
  "CLIENT_ACTION_REASON_CLIENT_DISABLED",
  "CLIENT_ACTION_REASON_CLIENT_BANNED",
  "CLIENT_ACTION_REASON_CLIENT_SENSOR",
];

function randomReason() {
  return reasons[Math.floor(Math.random() * reasons.length)];
}

function randomUser() {
  const rand = Math.random().toString(16).slice(2, 10);
  return `00000000-0000-4000-8000-${rand.padEnd(12, "0")}`;
}

function headers(token) {
  return {
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
  };
}

export default function () {
  const url = `${baseURL}${basePath}/v1/public/anti-cheat/eac/report`;
  const body = JSON.stringify({
    userId: randomUser(),
    clientActionReason: randomReason(),
    clientActionDetailsReasonString: "loadtest-20k",
  });

  const res = http.post(url, body, headers(publicToken || "mock"));
  check(res, {
    "status is 2xx": (r) => r.status >= 200 && r.status < 300,
  });
}
