"use strict";

import * as lib from "./server.js";

export default async function handleRoute(route, req, res) {
  try {
    if (req.method === "OPTIONS") {
      res.status(204).setHeader("Access-Control-Allow-Origin", "*")
        .setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization")
        .setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS").end();
      return;
    }
    if (route === "health" && req.method === "GET") {
      lib.json(res, 200, { ok: true, service: "skillrack-helper-license-api", serverTime: lib.nowIso() });
      return;
    }
    if (route === "license/activate" && req.method === "POST") {
      const result = await lib.activate(await lib.body(req));
      lib.json(res, result.status, result.payload);
      return;
    }
    if (route === "license/validate" && req.method === "POST") {
      const result = await lib.validate(await lib.body(req), req);
      lib.json(res, result.status, result.payload);
      return;
    }
    if (route === "license/usage" && req.method === "POST") {
      const result = await lib.usage(await lib.body(req), req);
      lib.json(res, result.status, result.payload);
      return;
    }
    if (route === "auth/refresh" && req.method === "POST") {
      const result = await lib.refresh(await lib.body(req));
      lib.json(res, result.status, result.payload);
      return;
    }
    if (route === "auth/revoke" && req.method === "POST") {
      const result = await lib.revoke(await lib.body(req));
      lib.json(res, result.status, result.payload);
      return;
    }
    if (!route.startsWith("admin/")) {
      lib.json(res, 404, { ok: false, error: "Route not found." });
      return;
    }
    if (!lib.requireAdmin(req, res)) return;
    if (route === "admin/licenses" && req.method === "GET") {
      lib.json(res, 200, { ok: true, licenses: await lib.listLicenses() });
      return;
    }
    if (route === "admin/stats" && req.method === "GET") {
      lib.json(res, 200, { ok: true, ...(await lib.stats()) });
      return;
    }
    if (route === "admin/licenses" && req.method === "POST") {
      const input = await lib.body(req);
      const expiresAt = lib.validFutureDate(input.expiresAt);
      if (!expiresAt) {
        lib.json(res, 400, { ok: false, error: "expiresAt must be a future date." });
        return;
      }
      let key = lib.createLicenseKey();
      let inserted;
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const { data, error } = await lib.supabase.from("licenses").insert({
          key_hash: lib.hash(lib.normalizeKey(key)), key_suffix: key.slice(-4), expires_at: expiresAt
        }).select("*").single();
        if (!error) { inserted = data; break; }
        key = lib.createLicenseKey();
      }
      if (!inserted) throw new Error("Could not create a unique license.");
      lib.json(res, 201, { ok: true, license: { ...lib.publicLicense(inserted), licenseKey: key } });
      return;
    }
    const actionMatch = route.match(/^admin\/licenses\/([^/]+)\/(lock|unlock)$/);
    if (req.method === "POST" && actionMatch) {
      const license = await lib.getLicenseById(actionMatch[1]);
      if (!license) { lib.json(res, 404, { ok: false, error: "License not found." }); return; }
      const input = await lib.body(req);
      const patch = actionMatch[2] === "lock"
        ? { status: "locked", lock_reason: String(input.reason || "Locked by administrator.").slice(0, 200), locked_at: lib.nowIso() }
        : { status: "active", lock_reason: "", locked_at: null };
      const { data, error } = await lib.supabase.from("licenses").update(patch).eq("id", license.id).select("*").single();
      if (error) throw error;
      lib.json(res, 200, { ok: true, license: lib.publicLicense(data) });
      return;
    }
    lib.json(res, 404, { ok: false, error: "Route not found." });
  } catch (error) {
    console.error(error);
    const status = Number(error?.status) || 500;
    lib.json(res, status, {
      ok: false,
      reason: error?.reason || "SERVER_ERROR",
      error: status >= 500 ? "Server error." : (error.message || "Request failed.")
    });
  }
};
