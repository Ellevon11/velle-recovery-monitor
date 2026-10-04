import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { monitor, signingKeys, validateConfig, getJSON } from "./monitor.mjs";

const config = JSON.parse(await readFile(new URL("./config.json", import.meta.url), "utf8"));
const now = Date.parse("2026-10-04T20:00:00Z");
const jwks = { keys: [{ kid: "synthetic", kty: "RSA", use: "sig", alg: "RS256", n: "synthetic-modulus", e: "AQAB" }] };
const settings = { ...config, signingKeys: signingKeys(jwks) };
const cert = { validFrom: "Oct 4 18:00:00 2026 GMT", validTo: "Oct 11 10:00:00 2026 GMT", fingerprint: Array(32).fill("AA").join(":") };
function responses(overrides = {}) {
  return {
    "/healthz": { status: 200, body: { status: "ok", mode: "independent-recovery" }, certificate: cert },
    "/monitorz": { status: 200, body: {
      version: 1, mode: "independent-recovery-monitor", issuer: settings.issuer,
      signingKeys: settings.signingKeys, checkedAt: new Date(now).toISOString(),
      discovery: "available", authenticatedRecovery: "unverified", productionAuthOutageIndependence: "release-blocked",
    } },
    "/api/independent-recovery": { status: 401, body: { error: "Synthetic unauthorized" } },
    "/api/__clerk/.well-known/jwks.json": { status: 200, body: jwks },
    ...overrides,
  };
}
async function run(overrides, options = {}) {
  const values = responses(overrides);
  const calls = [];
  const result = await monitor(settings, { now, request: async url => {
    calls.push(url);
    const value = values[new URL(url).pathname];
    if (value instanceof Error) throw value;
    return value;
  }, ...options });
  return { result, calls };
}
const check = (result, id) => result.checks.find(c => c.id === id);

test("availability success is explicitly NOT authenticated recovery readiness", async () => {
  const { result } = await run();
  assert.equal(result.availability, "ok");
  assert.equal(result.authenticatedRecovery, "unverified");
  assert.equal(result.productionAuthOutageIndependence, "release-blocked");
});
test("primary signing host and gateway can fail together without suppressing independent alerts", async () => {
  const { result, calls } = await run({
    "/healthz": new Error("private-cookie-must-not-escape"),
    "/monitorz": new Error("AWS-credential-must-not-escape"),
    "/api/independent-recovery": new Error("gateway-down"),
    "/api/__clerk/.well-known/jwks.json": new Error("primary-down"),
  });
  assert.equal(calls.length, 4);
  assert.equal(result.availability, "incident");
  assert.equal(check(result, "gateway-health").status, "failed");
  assert.equal(check(result, "discovery-storage").status, "failed");
  assert.equal(check(result, "production-signing-key-freshness").status, "failed");
  assert.doesNotMatch(JSON.stringify(result), /private-cookie|AWS-credential/);
});
test("a public health success alone cannot hide discovery failure", async () => {
  const { result } = await run({ "/monitorz": { status: 503, body: {} } });
  assert.equal(result.availability, "incident");
  assert.equal(check(result, "gateway-health").status, "ok");
  assert.equal(check(result, "discovery-storage").status, "failed");
});
test("primary unavailable still checks reachable gateway and marks freshness unknown", async () => {
  const { result } = await run({ "/api/__clerk/.well-known/jwks.json": new Error("down") });
  assert.equal(check(result, "discovery-storage").status, "ok");
  assert.equal(check(result, "deployed-production-pins").status, "ok");
  assert.equal(check(result, "production-signing-key-freshness").status, "failed");
});
test("unknown or same-kid replacement production keys alert without modifying approved pins", async () => {
  for (const changed of [{ ...jwks.keys[0], kid: "new" }, { ...jwks.keys[0], n: "replacement" }]) {
    const before = JSON.stringify(settings);
    const { result } = await run({ "/api/__clerk/.well-known/jwks.json": { status: 200, body: { keys: [changed] } } });
    assert.equal(check(result, "production-signing-key-freshness").status, "failed");
    assert.equal(JSON.stringify(settings), before);
  }
});
test("gateway stale pins and preview tenant substitution fail", async () => {
  for (const override of [{ signingKeys: signingKeys({ keys: [{ ...jwks.keys[0], n: "other" }] }) },
    { issuer: "https://preview.clerk.accounts.dev" }, { checkedAt: "2026-10-01T00:00:00Z" }]) {
    const metadata = responses()["/monitorz"];
    const { result } = await run({ "/monitorz": { ...metadata, body: { ...metadata.body, ...override } } });
    assert.equal(result.availability, "incident");
  }
});
test("expiry, impending renewal and non-extending replacement all alert", async () => {
  const { result: soon } = await run({ "/healthz": { ...responses()["/healthz"], certificate: { ...cert, validTo: "Oct 5 10:00:00 2026 GMT" } } });
  assert.equal(check(soon, "certificate-renewal").status, "failed");
  const { result: expired } = await run({ "/healthz": { ...responses()["/healthz"], certificate: { ...cert, validTo: "Oct 3 10:00:00 2026 GMT" } } });
  assert.equal(check(expired, "public-ip-tls").status, "failed");
  const { result: replaced } = await run({}, { previous: { certificate: { fingerprint: "old", expiresAt: "2026-10-12T00:00:00Z" } } });
  assert.equal(check(replaced, "certificate-regression").status, "failed");
  const { result: renewed } = await run({}, { previous: { certificate: { fingerprint: "old", expiresAt: "2026-10-09T00:00:00Z" } } });
  assert.equal(renewed.availability, "ok");
});
test("a redirect or unauthenticated discovery success is never followed or accepted", async () => {
  const { result } = await run({ "/api/independent-recovery": { status: 200, body: { points: [] } },
    "/api/__clerk/.well-known/jwks.json": { status: 302, body: jwks } });
  assert.equal(check(result, "discovery-auth-boundary").status, "failed");
  assert.equal(check(result, "production-signing-key-freshness").status, "failed");
});
test("arbitrary origins, issuers, keyless config and credentials in URLs are rejected", async () => {
  for (const altered of [{ gatewayOrigin: "https://other.example" }, { issuer: "https://other.example" }, { signingKeys: [] }]) {
    assert.throws(() => validateConfig({ ...settings, ...altered }));
  }
  await assert.rejects(getJSON("https://user:credential@example.com/"));
  await assert.rejects(getJSON("http://18.226.155.37/healthz"));
});
test("public key parsing rejects duplicate or non-production algorithms", () => {
  assert.throws(() => signingKeys({ keys: [jwks.keys[0], jwks.keys[0]] }));
  assert.throws(() => signingKeys({ keys: [{ ...jwks.keys[0], alg: "none" }] }));
});