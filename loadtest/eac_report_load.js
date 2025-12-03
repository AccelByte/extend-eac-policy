import http from "k6/http";
import { check, fail } from "k6";

const mockMode = (__ENV.MOCK_MODE || "true").toLowerCase() === "true";
const baseURL = (__ENV.BASE_URL || "http://localhost:18000").replace(/\/$/, "");
const basePath = (__ENV.BASE_PATH || "").replace(/\/$/, "");

const duration = __ENV.DURATION || "2m";
const ratePublic = Number(__ENV.RATE_PUBLIC || 200);
const rateAdmin = Number(__ENV.RATE_ADMIN || 50);
const vus = Number(__ENV.VUS || 200);
const maxVUs = Number(__ENV.MAX_VUS || 400);

const publicToken = __ENV.PUBLIC_TOKEN || (mockMode ? "mock-public" : "");
const adminToken = __ENV.ADMIN_TOKEN || (mockMode ? "mock-admin" : "");
const integrityToken = __ENV.INTEGRITY_TOKEN || publicToken || (mockMode ? "mock-integrity" : "");

const publicEnabled = Boolean(publicToken);
const adminEnabled = Boolean(adminToken);
const integrityEnabled = Boolean(integrityToken);

if (!mockMode && !publicEnabled && !adminEnabled && !integrityEnabled) {
  fail("No tokens provided. Set PUBLIC_TOKEN and/or ADMIN_TOKEN (INTEGRITY_TOKEN optional).");
}

const scenarios = {};
if (publicEnabled) {
  scenarios.publicReports = {
    executor: "constant-arrival-rate",
    exec: "hitPublicReport",
    rate: ratePublic,
    timeUnit: "1s",
    duration,
    preAllocatedVUs: vus,
    maxVUs,
  };
}
if (integrityEnabled) {
  scenarios.integrityReports = {
    executor: "constant-arrival-rate",
    exec: "hitIntegrityReport",
    rate: Math.max(1, Math.floor(ratePublic / 2)),
    timeUnit: "1s",
    duration,
    preAllocatedVUs: Math.min(vus, 10),
    maxVUs,
  };
}
if (adminEnabled) {
  scenarios.adminReports = {
    executor: "constant-arrival-rate",
    exec: "hitAdminReport",
    rate: rateAdmin,
    timeUnit: "1s",
    duration,
    preAllocatedVUs: Math.min(vus, 10),
    maxVUs,
  };
}

export const options = {
  scenarios,
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

function requestBody(userId, detailSuffix) {
  return JSON.stringify({
    userId: userId || randomUser(),
    clientActionReason: randomReason(),
    clientActionDetailsReasonString: `loadtest-${detailSuffix}`,
  });
}

function headers(token) {
  return {
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
  };
}

function hitEndpoint(path, token, detail) {
  const url = `${baseURL}${basePath}${path}`;
  const body = requestBody(undefined, detail);
  const res = http.post(url, body, headers(token));
  check(res, {
    "status is 2xx": (r) => r.status >= 200 && r.status < 300,
    "has duration": (r) => r.timings.duration > 0,
  });
  return res;
}

export function hitPublicReport() {
  hitEndpoint("/v1/public/anti-cheat/eac/report", publicToken, "public");
}

export function hitIntegrityReport() {
  hitEndpoint("/v1/public/anti-cheat/eac/integrity/report", integrityToken, "integrity");
}

export function hitAdminReport() {
  hitEndpoint("/v1/admin/anti-cheat/eac/report", adminToken, "admin");
}

export function teardown() {
  // Helps k6 print a clear separation after runs when multiple scenarios are enabled.
}
