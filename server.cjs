"use strict";

const http = require("node:http");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");
const { URL } = require("node:url");

const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 8787);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "dev-admin-token";
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const DATA_DIR = path.join(ROOT, "data");
const STATE_FILE = path.join(DATA_DIR, "state.json");
const MAX_BODY_BYTES = 64 * 1024;
const ALLOWED_EVENTS = new Set(["run", "ai_request", "insert"]);
let state;
let writeQueue = Promise.resolve();

function nowIso() {
  return new Date().toISOString();
}

function createInitialState() {
  return { schemaVersion: 1, licenses: [], usage: [] };
}

function id(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function normalizeKey(value) {
  return String(value || "").trim().toUpperCase().replace(/\s+/g, "");
}

function normalizeAccount(value) {
  return String(value || "").trim().replace(/\s+/g, " ").toLowerCase();
}

function hash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function normalizeDevice(value) {
  return String(value || "").trim();
}

function publicLicense(license) {
  const expired = new Date(license.expiresAt).getTime() <= Date.now();
  return {
    id: license.id,
    licenseKeySuffix: license.keySuffix,
    userName: license.userName || "",
    status: expired && license.status === "active" ? "expired" : license.status,
    createdAt: license.createdAt,
    expiresAt: license.expiresAt,
    lastUsedAt: license.lastUsedAt || null,
    totalPrograms: license.totalPrograms || 0,
    solvedPrograms: license.solvedPrograms || 0,
    activationCount: license.deviceIdHash ? 1 : 0,
    lockReason: license.lockReason || ""
  };
}

function licenseState(license) {
  if (!license) return "invalid";
  if (license.status === "locked") return "locked";
  if (license.status === "revoked") return "revoked";
  if (new Date(license.expiresAt).getTime() <= Date.now()) return "expired";
  return "active";
}

function findLicenseByKey(key) {
  const keyHash = hash(normalizeKey(key));
  return state.licenses.find(license => license.keyHash === keyHash) || null;
}

function findLicenseById(value) {
  return state.licenses.find(license => license.id === value) || null;
}

async function loadState() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  try {
    state = JSON.parse(await fsp.readFile(STATE_FILE, "utf8"));
    if (!state || !Array.isArray(state.licenses) || !Array.isArray(state.usage)) {
      throw new Error("state.json has an invalid shape");
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    state = createInitialState();
    await persistState();
  }
}

function persistState() {
  const snapshot = JSON.stringify(state, null, 2);
  writeQueue = writeQueue.then(async () => {
    const temp = `${STATE_FILE}.${process.pid}.tmp`;
    await fsp.writeFile(temp, snapshot, "utf8");
    await fsp.rename(temp, STATE_FILE);
  });
  return writeQueue;
}

function sendJson(response, status, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
  });
  response.end(body);
}

function sendText(response, status, body, contentType) {
  response.writeHead(status, {
    "Content-Type": contentType,
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*"
  });
  response.end(body);
}

function adminAuthorized(request) {
  const header = String(request.headers.authorization || "");
  return header === `Bearer ${ADMIN_TOKEN}`;
}

function requireAdmin(request, response) {
  if (adminAuthorized(request)) return true;
  sendJson(response, 401, { ok: false, error: "Admin authentication required." });
  return false;
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let body = "";
    request.setEncoding("utf8");
    request.on("data", chunk => {
      size += Buffer.byteLength(chunk);
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error("Request body is too large."), { statusCode: 413 }));
        request.destroy();
        return;
      }
      body += chunk;
    });
    request.on("end", () => {
      if (!body.trim()) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(Object.assign(new Error("Request body must be valid JSON."), { statusCode: 400 }));
      }
    });
    request.on("error", reject);
  });
}

function createLicenseKey() {
  let key;
  do {
    const raw = crypto.randomBytes(8).toString("hex").toUpperCase();
    key = `SRH-${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`;
  } while (findLicenseByKey(key));
  return key;
}

function dateOrNull(value) {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : null;
}

function findLicenseForClient(body) {
  const license = findLicenseByKey(body.licenseKey);
  if (!license) return { license: null, error: "Invalid license key." };
  const deviceId = normalizeDevice(body.deviceId);
  if (!deviceId) return { license, error: "A device id is required." };
  if (license.deviceIdHash && license.deviceIdHash !== hash(deviceId)) {
    return { license, error: "This license is already activated on another device." };
  }
  const accountId = String(body.userName || "").trim();
  if (license.userName && accountId && normalizeAccount(license.userName) !== normalizeAccount(accountId)) {
    return { license, error: "This license is already bound to another SkillRack account." };
  }
  return { license, deviceId, accountId };
}

async function activateLicense(body) {
  const result = findLicenseForClient(body);
  if (result.error) return { status: 401, body: { ok: false, error: result.error } };
  const license = result.license;
  const current = licenseState(license);
  if (current !== "active") return { status: current === "locked" ? 423 : 410, body: { ok: false, error: `License is ${current}.`, reason: current } };
  if (!license.deviceIdHash) license.deviceIdHash = hash(result.deviceId);
  license.userName = String(body.userName || license.userName || "").trim().slice(0, 120);
  license.lastUsedAt = nowIso();
  await persistState();
  return { status: 200, body: { ok: true, license: publicLicense(license), serverTime: nowIso() } };
}

async function validateLicense(body) {
  const result = findLicenseForClient(body);
  if (result.error) return { status: 200, body: { ok: true, allowed: false, reason: "INVALID_LICENSE", error: result.error } };
  const license = result.license;
  const reason = licenseState(license);
  if (reason === "active") {
    license.lastUsedAt = nowIso();
    if (result.accountId && !license.userName) license.userName = result.accountId.slice(0, 120);
    await persistState();
  }
  return {
    status: 200,
    body: { ok: true, allowed: reason === "active", reason, serverTime: nowIso(), license: publicLicense(license) }
  };
}

async function recordUsage(body) {
  const result = findLicenseForClient(body);
  if (result.error) return { status: 401, body: { ok: false, error: result.error } };
  const license = result.license;
  if (licenseState(license) !== "active") return { status: 403, body: { ok: false, error: "License is not active." } };
  const runId = String(body.runId || "").trim();
  const event = String(body.event || "").trim();
  if (!runId || !ALLOWED_EVENTS.has(event)) return { status: 400, body: { ok: false, error: "runId and a supported event are required." } };
  const duplicate = state.usage.find(item => item.licenseId === license.id && item.runId === runId);
  if (duplicate) return { status: 200, body: { ok: true, duplicate: true, usage: publicLicense(license) } };
  const resultName = String(body.result || "unknown");
  const usage = {
    id: id("usage"),
    licenseId: license.id,
    runId,
    event,
    result: resultName,
    language: String(body.language || "unknown").slice(0, 80),
    occurredAt: nowIso()
  };
  state.usage.push(usage);
  if (event === "run") {
    license.totalPrograms = (license.totalPrograms || 0) + 1;
    if (resultName === "success") license.solvedPrograms = (license.solvedPrograms || 0) + 1;
  }
  license.lastUsedAt = usage.occurredAt;
  await persistState();
  return { status: 200, body: { ok: true, duplicate: false, usage: publicLicense(license) } };
}

function adminStats() {
  const licenses = state.licenses.map(publicLicense);
  const byEvent = {};
  const byDay = {};
  for (const item of state.usage) {
    byEvent[item.event] = (byEvent[item.event] || 0) + 1;
    const day = item.occurredAt.slice(0, 10);
    byDay[day] ||= { date: day, events: 0, programsDone: 0, programsSolved: 0 };
    byDay[day].events += 1;
    if (item.event === "run") {
      byDay[day].programsDone += 1;
      if (item.result === "success") byDay[day].programsSolved += 1;
    }
  }
  return {
    totals: {
      licenses: licenses.length,
      activeLicenses: licenses.filter(item => item.status === "active").length,
      lockedLicenses: licenses.filter(item => item.status === "locked").length,
      expiredLicenses: licenses.filter(item => item.status === "expired").length,
      programsDone: licenses.reduce((sum, item) => sum + item.totalPrograms, 0),
      programsSolved: licenses.reduce((sum, item) => sum + item.solvedPrograms, 0),
      usageEvents: state.usage.length
    },
    byEvent,
    byDay: Object.values(byDay).sort((a, b) => a.date.localeCompare(b.date))
  };
}

async function handleAdmin(request, response, url) {
  if (!requireAdmin(request, response)) return;
  if (request.method === "GET" && url.pathname === "/api/admin/licenses") {
    const search = String(url.searchParams.get("search") || "").toLowerCase();
    const licenses = state.licenses
      .map(publicLicense)
      .filter(license => !search || `${license.id} ${license.licenseKeySuffix} ${license.userName}`.toLowerCase().includes(search));
    sendJson(response, 200, { ok: true, licenses });
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/admin/stats") {
    sendJson(response, 200, { ok: true, ...adminStats() });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/admin/licenses") {
    const body = await readJson(request);
    const expiresAt = dateOrNull(body.expiresAt);
    if (!expiresAt || new Date(expiresAt).getTime() <= Date.now()) {
      sendJson(response, 400, { ok: false, error: "expiresAt must be a future date." });
      return;
    }
    const key = createLicenseKey();
    const license = {
      id: id("lic"),
      keyHash: hash(key),
      keySuffix: key.slice(-4),
      userName: "",
      status: "active",
      createdAt: nowIso(),
      expiresAt,
      lastUsedAt: null,
      deviceIdHash: "",
      totalPrograms: 0,
      solvedPrograms: 0,
      lockReason: ""
    };
    state.licenses.push(license);
    await persistState();
    sendJson(response, 201, { ok: true, license: { ...publicLicense(license), licenseKey: key } });
    return;
  }
  const actionMatch = url.pathname.match(/^\/api\/admin\/licenses\/([^/]+)\/(lock|unlock)$/);
  if (request.method === "POST" && actionMatch) {
    const license = findLicenseById(actionMatch[1]);
    if (!license) {
      sendJson(response, 404, { ok: false, error: "License not found." });
      return;
    }
    const action = actionMatch[2];
    if (action === "lock") {
      const body = await readJson(request);
      license.status = "locked";
      license.lockReason = String(body.reason || "Locked by administrator.").slice(0, 200);
      license.lockedAt = nowIso();
    } else {
      license.status = new Date(license.expiresAt).getTime() <= Date.now() ? "active" : "active";
      license.lockReason = "";
      license.lockedAt = null;
    }
    await persistState();
    sendJson(response, 200, { ok: true, license: publicLicense(license) });
    return;
  }
  sendJson(response, 404, { ok: false, error: "Admin route not found." });
}

async function handleRequest(request, response) {
  if (request.method === "OPTIONS") {
    response.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
    });
    response.end();
    return;
  }
  const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
  if (url.pathname === "/health" && request.method === "GET") {
    sendJson(response, 200, { ok: true, service: "skillrack-helper-license-server", serverTime: nowIso() });
    return;
  }
  if (url.pathname.startsWith("/api/admin/")) {
    await handleAdmin(request, response, url);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/license/activate") {
    const result = await activateLicense(await readJson(request));
    sendJson(response, result.status, result.body);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/license/validate") {
    const result = await validateLicense(await readJson(request));
    sendJson(response, result.status, result.body);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/license/usage") {
    const result = await recordUsage(await readJson(request));
    sendJson(response, result.status, result.body);
    return;
  }
  if ((url.pathname === "/" || url.pathname === "/admin" || url.pathname === "/admin/")) {
    const html = await fsp.readFile(path.join(PUBLIC_DIR, "index.html"), "utf8");
    sendText(response, 200, html, "text/html; charset=utf-8");
    return;
  }
  if (url.pathname === "/admin.js") {
    const js = await fsp.readFile(path.join(PUBLIC_DIR, "admin.js"), "utf8");
    sendText(response, 200, js, "text/javascript; charset=utf-8");
    return;
  }
  if (url.pathname === "/admin.css") {
    const css = await fsp.readFile(path.join(PUBLIC_DIR, "admin.css"), "utf8");
    sendText(response, 200, css, "text/css; charset=utf-8");
    return;
  }
  sendJson(response, 404, { ok: false, error: "Route not found." });
}

async function start() {
  await loadState();
  const server = http.createServer((request, response) => {
    handleRequest(request, response).catch(error => {
      console.error(error);
      if (!response.headersSent) sendJson(response, error.statusCode || 500, { ok: false, error: error.message || "Server error." });
      else response.destroy();
    });
  });
  server.listen(PORT, HOST, () => {
    console.log(`SkillRack license server: http://${HOST}:${PORT}`);
    if (ADMIN_TOKEN === "dev-admin-token") console.warn("Using default admin token. Set ADMIN_TOKEN before production use.");
  });
}

start().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
