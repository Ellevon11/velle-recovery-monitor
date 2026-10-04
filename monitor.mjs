import https from "node:https";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

export function signingKeys(jwks) {
  if (!Array.isArray(jwks?.keys) || !jwks.keys.length || jwks.keys.length > 10) throw new Error("Invalid public keys");
  const seen = new Set();
  return jwks.keys.map(key => {
    if (key.kty !== "RSA" || key.use !== "sig" || (key.alg && key.alg !== "RS256")
      || typeof key.kid !== "string" || typeof key.e !== "string" || typeof key.n !== "string"
      || seen.has(key.kid)) throw new Error("Invalid public keys");
    seen.add(key.kid);
    return { kid: key.kid, thumbprint: createHash("sha256")
      .update(JSON.stringify({ e: key.e, kty: "RSA", n: key.n })).digest("base64url") };
  }).sort((a, b) => a.kid.localeCompare(b.kid));
}

function sameKeys(a, b) {
  const normalize = keys => keys.map(k => ({ kid: k.kid, thumbprint: k.thumbprint })).sort((x, y) => x.kid.localeCompare(y.kid));
  return Array.isArray(a) && Array.isArray(b) && JSON.stringify(normalize(a)) === JSON.stringify(normalize(b));
}

export function validateConfig(config) {
  // Deliberately not overridable through workflow inputs or environment.
  if (config.gatewayOrigin !== "https://18.226.155.37"
    || config.issuer !== "https://code-migrate.replit.app/api/__clerk"
    || config.jwksUrl !== `${config.issuer}/.well-known/jwks.json`
    || !Array.isArray(config.signingKeys) || !config.signingKeys.length
    || config.signingKeys.length > 10 || config.certificateWarningHours !== 36
    || !config.signingKeys.every(k => typeof k.kid === "string" && /^[A-Za-z0-9_-]{43}$/.test(k.thumbprint))
    || new Set(config.signingKeys.map(k => k.kid)).size !== config.signingKeys.length) {
    throw new Error("Approved public monitor configuration is required.");
  }
}

/** Numeric-IP requests omit SNI, matching native clients and testing Caddy's
 * default_sni. Node validates the public CA chain AND IP SAN. No redirects,
 * cookie jar, auth headers, proxy fallback, or certificate bypass. */
export function getJSON(url, { deadlineMs = 12_000 } = {}) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    if (target.protocol !== "https:" || target.username || target.password || target.search || target.hash) {
      reject(new Error("Unsafe monitor URL")); return;
    }
    let timer;
    const req = https.get(target, {
      rejectUnauthorized: true, minVersion: "TLSv1.2", agent: false,
      headers: { Accept: "application/json", "User-Agent": "Velle-Independent-Recovery-Monitor/1" },
    }, res => {
      const peer = res.socket.getPeerCertificate();
      const certificate = {
        fingerprint: peer.fingerprint256,
        validFrom: peer.valid_from,
        validTo: peer.valid_to,
      };
      let bytes = 0;
      const chunks = [];
      res.on("data", chunk => {
        bytes += chunk.length;
        if (bytes > 64 * 1024) { req.destroy(new Error("Response too large")); return; }
        chunks.push(chunk);
      });
      res.on("error", reject);
      res.on("end", () => {
        clearTimeout(timer);
        try {
          resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString("utf8")), certificate });
        } catch { reject(new Error("Invalid monitor response")); }
      });
    });
    // Absolute deadline, including DNS/connect/TLS and slow response bodies.
    timer = setTimeout(() => req.destroy(new Error("Monitor deadline")), deadlineMs);
    req.on("error", () => { clearTimeout(timer); reject(new Error("Verified HTTPS request failed")); });
  });
}

export async function monitor(config, { request = getJSON, now = Date.now(), previous = {} } = {}) {
  validateConfig(config);
  const checks = [];
  const add = (id, status, message) => checks.push({ id, status, message });
  // Do not let failure of the primary JWKS host suppress gateway checks.
  const results = await Promise.allSettled([
    request(`${config.gatewayOrigin}/healthz`),
    request(`${config.gatewayOrigin}/monitorz`),
    request(`${config.gatewayOrigin}/api/independent-recovery`),
    request(config.jwksUrl),
  ]);
  const [health, diagnostics, discovery, source] = results;
  let certificate;
  if (health.status === "fulfilled") {
    const value = health.value;
    add("gateway-health", value.status === 200 && value.body?.status === "ok"
      && value.body?.mode === "independent-recovery" ? "ok" : "failed", "Gateway public health response");
    const cert = value.certificate;
    const expires = Date.parse(cert?.validTo);
    const starts = Date.parse(cert?.validFrom);
    const hours = (expires - now) / 3_600_000;
    const valid = Number.isFinite(expires) && Number.isFinite(starts) && starts <= now && expires > now
      && typeof cert?.fingerprint === "string" && /^[A-Fa-f0-9:]{95}$/.test(cert.fingerprint);
    add("public-ip-tls", valid ? "ok" : "failed", "Public CA chain and IP identity verification; valid certificate dates");
    if (valid) {
      certificate = { fingerprint: cert.fingerprint, expiresAt: new Date(expires).toISOString() };
      add("certificate-renewal", hours > config.certificateWarningHours ? "ok" : "failed",
        hours > config.certificateWarningHours ? "Certificate has more than 36 hours remaining" : "Certificate renewal overdue: 36 hours or less remaining");
      if (previous.certificate && previous.certificate.fingerprint !== certificate.fingerprint
        && expires <= Date.parse(previous.certificate.expiresAt)) {
        add("certificate-regression", "failed", "Replacement certificate did not extend expiry; operator review required");
      }
    }
  } else {
    add("gateway-health", "failed", "Gateway did not return a verified HTTPS health response");
    add("public-ip-tls", "failed", "Trusted public-IP HTTPS could not be verified (network or TLS failure)");
  }
  if (diagnostics.status === "fulfilled") {
    const { status, body } = diagnostics.value;
    const recent = Math.abs(now - Date.parse(body?.checkedAt)) <= 5 * 60_000;
    const expected = body?.version === 1 && body?.mode === "independent-recovery-monitor"
      && body?.issuer === config.issuer
      && body?.authenticatedRecovery === "unverified"
      && body?.productionAuthOutageIndependence === "release-blocked";
    add("deployed-production-pins", expected && sameKeys(body.signingKeys, config.signingKeys) ? "ok" : "failed",
      "Deployed gateway must retain the approved production issuer and exact pinned key identities");
    add("discovery-storage", expected && status === 200 && recent && body.discovery === "available" ? "ok" : "failed",
      "Read-only discovery listing in a reserved non-customer namespace (not an authenticated recovery drill)");
  } else {
    add("deployed-production-pins", "failed", "Gateway trust diagnostics are unavailable");
    add("discovery-storage", "failed", "Gateway discovery diagnostics are unavailable");
  }
  add("discovery-auth-boundary",
    discovery.status === "fulfilled" && discovery.value.status === 401 ? "ok" : "failed",
    "Unauthenticated discovery must fail closed; 401 does not prove authenticated readiness");
  if (source.status === "fulfilled") {
    try {
      const live = signingKeys(source.value.body);
      add("production-signing-key-freshness",
        source.value.status === 200 && sameKeys(live, config.signingKeys) ? "ok" : "failed",
        "Production signing-key changes require explicit operator verification and pin refresh; never auto-trust replacements");
    } catch { add("production-signing-key-freshness", "failed", "Production signing metadata is invalid"); }
  } else {
    add("production-signing-key-freshness", "failed",
      "Production signing source is unreachable; freshness is unknown. Gateway checks still ran independently");
  }
  add("authenticated-recovery-readiness", "unverified", "No customer session or journal is used; authenticated recovery has not been certified");
  add("production-auth-outage-independence", "release-blocked", "Fresh production sign-in and refresh still depend on the primary host");
  return {
    version: 1, checkedAt: new Date(now).toISOString(), checks,
    availability: checks.some(c => c.status === "failed") ? "incident" : "ok",
    authenticatedRecovery: "unverified", productionAuthOutageIndependence: "release-blocked",
    ...(certificate ? { certificate } : {}),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let report;
  try {
    const config = JSON.parse(await readFile(new URL("./config.json", import.meta.url), "utf8"));
    let previous = {};
    try { previous = JSON.parse(await readFile(new URL("./state.json", import.meta.url), "utf8")); } catch {}
    report = await monitor(config, { previous });
  } catch {
    // Never print raw HTTP response bodies, tokens, AWS errors, or environment.
    report = { version: 1, checkedAt: new Date().toISOString(), availability: "incident",
      authenticatedRecovery: "unverified", productionAuthOutageIndependence: "release-blocked",
      checks: [{ id: "monitor-execution", status: "failed", message: "Monitor configuration or execution failed; operator action required" }] };
  }
  await writeFile("report.json", JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify(report, null, 2));
  process.exitCode = report.availability === "ok" ? 0 : 1;
}