"use strict";

import crypto from "node:crypto";
import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
if (!supabaseUrl || !supabaseKey) throw new Error("SUPABASE_URL and SUPABASE_SECRET_KEY must be configured.");

const supabase = createClient(supabaseUrl, supabaseKey, {
  auth: { autoRefreshToken: false, persistSession: false }
});
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const ALLOWED_EVENTS = new Set(["run", "ai_request", "insert"]);

function hash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function normalizeKey(value) {
  return String(value || "").trim().toUpperCase().replace(/\s+/g, "");
}

function nowIso() {
  return new Date().toISOString();
}

function id() {
  return crypto.randomBytes(8).toString("hex");
}

function publicLicense(license) {
  const expired = new Date(license.expires_at).getTime() <= Date.now();
  return {
    id: license.id,
    licenseKeySuffix: license.key_suffix,
    userName: license.user_name || "",
    status: expired && license.status === "active" ? "expired" : license.status,
    createdAt: license.created_at,
    expiresAt: license.expires_at,
    lastUsedAt: license.last_used_at || null,
    totalPrograms: license.total_programs || 0,
    solvedPrograms: license.solved_programs || 0,
    activationCount: license.device_id_hash ? 1 : 0,
    lockReason: license.lock_reason || ""
  };
}

function licenseState(license) {
  if (!license) return "invalid";
  if (license.status === "locked") return "locked";
  if (license.status === "revoked") return "revoked";
  if (new Date(license.expires_at).getTime() <= Date.now()) return "expired";
  return "active";
}

function json(res, status, payload) {
  res.status(status)
    .setHeader("Cache-Control", "no-store")
    .setHeader("Access-Control-Allow-Origin", "*")
    .setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization")
    .setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    .json(payload);
}

function adminAuthorized(req) {
  if (!ADMIN_TOKEN) return false;
  return String(req.headers.authorization || "") === `Bearer ${ADMIN_TOKEN}`;
}

function requireAdmin(req, res) {
  if (adminAuthorized(req)) return true;
  json(res, 401, { ok: false, error: "Admin authentication required." });
  return false;
}

async function body(req) {
  if (req.body && typeof req.body === "object") return req.body;
  return {};
}

async function getLicenseByKey(value) {
  const keyHash = hash(normalizeKey(value));
  const { data, error } = await supabase.from("licenses").select("*").eq("key_hash", keyHash).maybeSingle();
  if (error) throw error;
  return data;
}

async function getLicenseById(value) {
  const { data, error } = await supabase.from("licenses").select("*").eq("id", value).maybeSingle();
  if (error) throw error;
  return data;
}

async function clientLicense(bodyValue) {
  const license = await getLicenseByKey(bodyValue.licenseKey);
  if (!license) return { error: "Invalid license key." };
  const deviceId = String(bodyValue.deviceId || "").trim();
  if (!deviceId) return { license, error: "A device id is required." };
  if (license.device_id_hash && license.device_id_hash !== hash(deviceId)) {
    return { license, error: "This license is already activated on another device." };
  }
  return { license, deviceId };
}

function createLicenseKey() {
  const raw = crypto.randomBytes(8).toString("hex").toUpperCase();
  return `SRH-${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`;
}

function validFutureDate(value) {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) && date.getTime() > Date.now() ? date.toISOString() : null;
}

async function activate(bodyValue) {
  const result = await clientLicense(bodyValue);
  if (result.error) return { status: 401, payload: { ok: false, error: result.error } };
  const current = licenseState(result.license);
  if (current !== "active") return { status: current === "locked" ? 423 : 410, payload: { ok: false, error: `License is ${current}.`, reason: current } };
  const patch = {
    device_id_hash: result.license.device_id_hash || hash(result.deviceId),
    user_name: String(bodyValue.userName || result.license.user_name || "").trim().slice(0, 120),
    last_used_at: nowIso()
  };
  const { data, error } = await supabase.from("licenses").update(patch).eq("id", result.license.id).select("*").single();
  if (error) throw error;
  return { status: 200, payload: { ok: true, license: publicLicense(data), serverTime: nowIso() } };
}

async function validate(bodyValue) {
  const result = await clientLicense(bodyValue);
  if (result.error) return { status: 200, payload: { ok: true, allowed: false, reason: "INVALID_LICENSE", error: result.error } };
  const reason = licenseState(result.license);
  if (reason === "active") {
    const patch = { last_used_at: nowIso() };
    if (bodyValue.userName) patch.user_name = String(bodyValue.userName).trim().slice(0, 120);
    await supabase.from("licenses").update(patch).eq("id", result.license.id);
  }
  return { status: 200, payload: { ok: true, allowed: reason === "active", reason, serverTime: nowIso(), license: publicLicense(result.license) } };
}

async function usage(bodyValue) {
  const result = await clientLicense(bodyValue);
  if (result.error) return { status: 401, payload: { ok: false, error: result.error } };
  if (licenseState(result.license) !== "active") return { status: 403, payload: { ok: false, error: "License is not active." } };
  const runId = String(bodyValue.runId || "").trim();
  const event = String(bodyValue.event || "").trim();
  if (!runId || !ALLOWED_EVENTS.has(event)) return { status: 400, payload: { ok: false, error: "runId and a supported event are required." } };
  const { data, error } = await supabase.rpc("record_license_usage", {
    p_license_id: result.license.id,
    p_run_id: runId,
    p_event: event,
    p_result: String(bodyValue.result || "unknown"),
    p_language: String(bodyValue.language || "unknown").slice(0, 80)
  });
  if (error) {
    const status = error.message === "LICENSE_NOT_ACTIVE" ? 403 : 400;
    return { status, payload: { ok: false, error: error.message } };
  }
  return { status: 200, payload: { ok: true, ...data, usage: publicLicense({ ...result.license, total_programs: data.total_programs, solved_programs: data.solved_programs, last_used_at: data.last_used_at }) } };
}

async function listLicenses() {
  const { data, error } = await supabase.from("licenses").select("*").order("created_at", { ascending: false });
  if (error) throw error;
  return data.map(publicLicense);
}

async function stats() {
  const [{ data: licenses, error: licenseError }, { data: events, error: eventError }] = await Promise.all([
    supabase.from("licenses").select("*").order("created_at", { ascending: false }),
    supabase.from("usage_events").select("event,result,occurred_at")
  ]);
  if (licenseError) throw licenseError;
  if (eventError) throw eventError;
  const publicLicenses = licenses.map(publicLicense);
  const byEvent = {};
  const byDay = {};
  for (const item of events) {
    byEvent[item.event] = (byEvent[item.event] || 0) + 1;
    const day = item.occurred_at.slice(0, 10);
    byDay[day] ||= { date: day, events: 0, programsDone: 0, programsSolved: 0 };
    byDay[day].events += 1;
    if (item.event === "run") {
      byDay[day].programsDone += 1;
      if (item.result === "success") byDay[day].programsSolved += 1;
    }
  }
  return {
    totals: {
      licenses: publicLicenses.length,
      activeLicenses: publicLicenses.filter(item => item.status === "active").length,
      lockedLicenses: publicLicenses.filter(item => item.status === "locked").length,
      expiredLicenses: publicLicenses.filter(item => item.status === "expired").length,
      programsDone: publicLicenses.reduce((sum, item) => sum + item.totalPrograms, 0),
      programsSolved: publicLicenses.reduce((sum, item) => sum + item.solvedPrograms, 0),
      usageEvents: events.length
    },
    byEvent,
    byDay: Object.values(byDay).sort((a, b) => a.date.localeCompare(b.date))
  };
}

export {
  supabase, json, body, requireAdmin, getLicenseById, publicLicense,
  createLicenseKey, hash, normalizeKey, validFutureDate, activate, validate,
  usage, listLicenses, stats, nowIso, id
};
