import assert from "node:assert/strict";
import test from "node:test";
import {
  authenticatedContext,
  hashSecret,
  issueSession,
  parseAccessToken,
  revokeSession,
  rotateSession
} from "../lib/session.js";

process.env.SESSION_SIGNING_SECRET = "test-session-secret-012345678901234567890123456789";

class Query {
  constructor(client, table) {
    this.client = client;
    this.table = table;
    this.filters = [];
    this.operation = "select";
    this.values = null;
  }

  select() { return this; }
  insert(values) { this.operation = "insert"; this.values = values; return this; }
  update(values) { this.operation = "update"; this.values = values; return this; }
  eq(field, value) { this.filters.push([field, "eq", value]); return this; }
  is(field, value) { this.filters.push([field, "is", value]); return this; }
  single() { return this.execute(true); }
  maybeSingle() { return this.execute(false); }

  async execute(single) {
    const rows = this.client[this.table];
    if (this.operation === "insert") {
      const row = { ...this.values };
      rows.push(row);
      return { data: row, error: null };
    }
    const matches = rows.filter(row => this.filters.every(([field, operator, value]) => {
      if (operator === "is") return row[field] === value;
      return String(row[field]) === String(value);
    }));
    if (this.operation === "update") {
      for (const row of matches) Object.assign(row, this.values);
    }
    if (single) return { data: matches[0] || null, error: matches.length === 1 ? null : new Error("expected one row") };
    return { data: matches[0] || null, error: null };
  }
}

class FakeClient {
  sessions = [];
  licenses = [];
  from(table) { return new Query(this, table); }
}

function createClient() {
  const client = new FakeClient();
  client.licenses.push({
    id: "9007199254740993",
    status: "active",
    expires_at: new Date(Date.now() + 86400000).toISOString(),
    device_id_hash: hashSecret("device-a"),
    user_name: ""
  });
  return client;
}

test("session activation, rotation, account lookup, and revocation use hashed refresh tokens", async () => {
  const client = createClient();
  const license = client.licenses[0];
  const first = await issueSession(client, license, "device-a");

  assert.equal(client.sessions.length, 1);
  assert.notEqual(client.sessions[0].refresh_token_hash, first.refreshToken);
  assert.equal(parseAccessToken(first.accessToken).lid, license.id);

  const context = await authenticatedContext(client, {
    headers: { authorization: `Bearer ${first.accessToken}` }
  });
  assert.equal(String(context.license.id), license.id);

  const second = await rotateSession(client, first.refreshToken, "device-a");
  assert.notEqual(second.refreshToken, first.refreshToken);
  await assert.rejects(
    () => rotateSession(client, first.refreshToken, "device-a"),
    error => error.reason === "SESSION_EXPIRED"
  );

  await revokeSession(client, second.refreshToken);
  await assert.rejects(
    () => authenticatedContext(client, { headers: { authorization: `Bearer ${second.accessToken}` } }),
    error => error.reason === "SESSION_EXPIRED"
  );
});

test("refresh rejects a different device", async () => {
  const client = createClient();
  const first = await issueSession(client, client.licenses[0], "device-a");
  await assert.rejects(
    () => rotateSession(client, first.refreshToken, "device-b"),
    error => error.reason === "LICENSE_LOCKED"
  );
});
