import crypto from "node:crypto";

export class SessionError extends Error {
  constructor(status, reason, message) {
    super(message);
    this.status = status;
    this.reason = reason;
  }
}

function sessionSecret() {
  const value = String(process.env.SESSION_SIGNING_SECRET || "");
  if (value.length < 32) {
    throw new SessionError(500, "BACKEND_NOT_CONFIGURED", "Session signing secret is not configured.");
  }
  return value;
}

export function hashSecret(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function sign(value) {
  return crypto.createHmac("sha256", sessionSecret()).update(value).digest("base64url");
}

export function createAccessToken(sessionId, licenseId, expiresAt) {
  const payload = Buffer.from(JSON.stringify({
    sid: String(sessionId),
    lid: String(licenseId),
    exp: Math.floor(new Date(expiresAt).getTime() / 1000)
  })).toString("base64url");
  return `${payload}.${sign(payload)}`;
}

export function parseAccessToken(value) {
  const parts = String(value || "").split(".");
  if (parts.length !== 2) throw new SessionError(401, "UNAUTHORIZED", "The access token is invalid.");
  const expected = sign(parts[0]);
  const actual = parts[1];
  if (expected.length !== actual.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual))) {
    throw new SessionError(401, "UNAUTHORIZED", "The access token is invalid.");
  }
  let payload;
  try {
    payload = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  } catch (_) {
    throw new SessionError(401, "UNAUTHORIZED", "The access token is invalid.");
  }
  if (!payload.sid || !payload.lid || !Number.isFinite(payload.exp) || payload.exp <= Math.floor(Date.now() / 1000)) {
    throw new SessionError(401, "SESSION_EXPIRED", "The access session has expired.");
  }
  return payload;
}

function bearer(req) {
  const value = String(req?.headers?.authorization || "");
  if (!value.startsWith("Bearer ")) throw new SessionError(401, "UNAUTHORIZED", "A bearer session is required.");
  const token = value.slice(7).trim();
  if (!token) throw new SessionError(401, "UNAUTHORIZED", "A bearer session is required.");
  return token;
}

function refreshTtlDays() {
  return Math.max(1, Number(process.env.REFRESH_TOKEN_TTL_DAYS || 30));
}

function accessTtlSeconds() {
  return Math.max(60, Number(process.env.ACCESS_TOKEN_TTL_SECONDS || 900));
}

function sessionTimes() {
  const refreshExpiresAt = new Date(Date.now() + refreshTtlDays() * 86400000).toISOString();
  const accessExpiresAt = new Date(Date.now() + accessTtlSeconds() * 1000).toISOString();
  return { refreshExpiresAt, accessExpiresAt };
}

function newRefreshToken() {
  return crypto.randomBytes(48).toString("base64url");
}

function activeLicenseError(license) {
  if (!license) return new SessionError(403, "LICENSE_INVALID", "The license is not available.");
  if (license.status === "locked" || license.status === "revoked") {
    return new SessionError(403, "LICENSE_LOCKED", "This license is not active.");
  }
  if (!license.expires_at || new Date(license.expires_at).getTime() <= Date.now()) {
    return new SessionError(403, "LICENSE_EXPIRED", "The license has expired.");
  }
  return null;
}

async function findLicense(client, licenseId) {
  const { data, error } = await client.from("licenses").select("*").eq("id", String(licenseId)).maybeSingle();
  if (error) throw error;
  return data;
}

export async function issueSession(client, license, deviceId) {
  const refreshToken = newRefreshToken();
  const { refreshExpiresAt, accessExpiresAt } = sessionTimes();
  const sessionId = crypto.randomUUID();
  const { data, error } = await client.from("sessions").insert({
    id: sessionId,
    license_id: String(license.id),
    device_id_hash: hashSecret(deviceId),
    refresh_token_hash: hashSecret(refreshToken),
    expires_at: refreshExpiresAt,
    revoked_at: null
  }).select("*").single();
  if (error) throw error;
  if (!data?.id) throw new SessionError(500, "DATABASE_ERROR", "The session could not be created.");
  return {
    accessToken: createAccessToken(data.id, license.id, accessExpiresAt),
    refreshToken,
    accessTokenExpiresAt: accessExpiresAt,
    refreshTokenExpiresAt: refreshExpiresAt
  };
}

export async function rotateSession(client, refreshToken, deviceId) {
  const oldHash = hashSecret(refreshToken);
  const { data: session, error: sessionError } = await client.from("sessions")
    .select("*").eq("refresh_token_hash", oldHash).maybeSingle();
  if (sessionError) throw sessionError;
  if (!session || session.revoked_at || new Date(session.expires_at).getTime() <= Date.now()) {
    throw new SessionError(401, "SESSION_EXPIRED", "The refresh session has expired.");
  }
  const license = await findLicense(client, session.license_id);
  const licenseError = activeLicenseError(license);
  if (licenseError) throw licenseError;
  if (session.device_id_hash !== hashSecret(deviceId) || license.device_id_hash !== session.device_id_hash) {
    throw new SessionError(403, "LICENSE_LOCKED", "This device session is no longer active.");
  }

  const nextRefreshToken = newRefreshToken();
  const { refreshExpiresAt, accessExpiresAt } = sessionTimes();
  const { data: updated, error: updateError } = await client.from("sessions")
    .update({
      refresh_token_hash: hashSecret(nextRefreshToken),
      expires_at: refreshExpiresAt,
      last_used_at: new Date().toISOString()
    })
    .eq("id", session.id)
    .eq("refresh_token_hash", oldHash)
    .is("revoked_at", null)
    .select("*").maybeSingle();
  if (updateError) throw updateError;
  if (!updated) throw new SessionError(401, "SESSION_EXPIRED", "The refresh session has already been rotated.");
  return {
    accessToken: createAccessToken(session.id, license.id, accessExpiresAt),
    refreshToken: nextRefreshToken,
    accessTokenExpiresAt: accessExpiresAt,
    refreshTokenExpiresAt: refreshExpiresAt
  };
}

export async function revokeSession(client, refreshToken) {
  if (!refreshToken) return;
  const { data: session, error: selectError } = await client.from("sessions")
    .select("id").eq("refresh_token_hash", hashSecret(refreshToken)).maybeSingle();
  if (selectError) throw selectError;
  if (!session) return;
  const { error } = await client.from("sessions")
    .update({ revoked_at: new Date().toISOString() }).eq("id", session.id).is("revoked_at", null)
    .select("id").maybeSingle();
  if (error) throw error;
}

export async function authenticatedContext(client, req) {
  const token = parseAccessToken(bearer(req));
  const { data: session, error: sessionError } = await client.from("sessions")
    .select("*").eq("id", token.sid).maybeSingle();
  if (sessionError) throw sessionError;
  if (!session || session.revoked_at || String(session.license_id) !== String(token.lid) ||
      new Date(session.expires_at).getTime() <= Date.now()) {
    throw new SessionError(401, "SESSION_EXPIRED", "The access session has expired.");
  }
  const license = await findLicense(client, session.license_id);
  const licenseError = activeLicenseError(license);
  if (licenseError) throw licenseError;
  if (!license.device_id_hash || license.device_id_hash !== session.device_id_hash) {
    throw new SessionError(403, "LICENSE_LOCKED", "This device session is no longer active.");
  }
  return { session, license };
}
