import assert from "node:assert/strict";
import { test } from "node:test";
import { notify } from "./notify.mjs";

const now = Date.parse("2026-10-04T20:00:00Z");
const report = { availability: "incident", checkedAt: new Date(now).toISOString(),
  checks: [{ id: "gateway-health", status: "failed", message: "Gateway unreachable" }] };
function fixture({ previous, issue, failState = false, privateRepo = false } = {}) {
  const calls = [];
  const request = async (url, init = {}) => {
    const path = new URL(url).pathname;
    const body = init.body && JSON.parse(init.body);
    calls.push({ path, method: init.method ?? "GET", body });
    if (path.endsWith("/contents/state.json")) {
      if (init.method === "PUT") return new Response("{}", { status: failState ? 403 : 200 });
      return new Response(JSON.stringify(previous ? { sha: "public-state-sha", content: Buffer.from(JSON.stringify(previous)).toString("base64") } : {}), { status: previous ? 200 : 404 });
    }
    if (path.endsWith("/comments")) return new Response("{}");
    if (path.endsWith("/issues/42")) return new Response(JSON.stringify(issue));
    if (path.endsWith("/issues")) {
      if (init.method === "POST") return new Response(JSON.stringify({ number: 42 }), { status: 201 });
      return new Response(JSON.stringify(issue ? [issue] : []));
    }
    return new Response(JSON.stringify({ private: privateRepo, default_branch: "main" }));
  };
  return { calls, request };
}
function run(f, overrides = {}) {
  return notify({ report, config: { alertAssignee: "Owner" }, repo: "Owner/velle-recovery-monitor", token: "synthetic-test-token",
    runId: "123", now, request: f.request, ...overrides });
}
const alert = { number: 42, title: "Velle recovery gateway monitoring alert", body: "<!-- velle-recovery-monitor -->", state: "open" };
test("first outage opens independently assigned issue and records public state", async () => {
  const f = fixture();
  const result = await run(f);
  assert.equal(result.delivered, true);
  assert.deepEqual(f.calls.find(c => c.method === "POST").body.assignees, ["Owner"]);
  assert.ok(f.calls.some(c => c.method === "PUT"));
  assert.doesNotMatch(JSON.stringify(f.calls), /synthetic-test-token/);
});
test("unchanged outage does not spam comments or commits", async () => {
  const f = fixture({ previous: { issueNumber: 42, signature: "gateway-health", lastCheckedAt: report.checkedAt }, issue: alert });
  await run(f);
  assert.equal(f.calls.filter(c => ["POST", "PATCH", "PUT"].includes(c.method)).length, 0);
});
test("changed failures notify and recovery closes incident without claiming recovery readiness", async () => {
  const previous = { issueNumber: 42, signature: "old", lastCheckedAt: report.checkedAt };
  const changed = fixture({ previous, issue: alert });
  await run(changed);
  assert.ok(changed.calls.some(c => c.path.endsWith("/comments") && c.method === "POST"));
  const recovered = fixture({ previous, issue: alert });
  await run(recovered, { report: { ...report, availability: "ok", checks: [] } });
  assert.ok(recovered.calls.some(c => c.method === "PATCH" && c.body.state === "closed"));
  assert.match(recovered.calls.find(c => c.path.endsWith("/comments")).body.body, /still unverified/);
});
test("retry after failed state write recovers existing bot-created issue", async () => {
  const f = fixture({ issue: alert });
  await run(f);
  assert.equal(f.calls.filter(c => c.path.endsWith("/issues") && c.method === "POST").length, 0);
});
test("daily commit keeps public scheduled workflow active", async () => {
  const f = fixture({ previous: { issueNumber: 42, signature: "gateway-health", lastCheckedAt: "2026-10-02T20:00:00Z" }, issue: alert });
  await run(f);
  assert.ok(f.calls.some(c => c.method === "PUT"));
});
test("state persistence failure and private repo fail explicitly", async () => {
  await assert.rejects(run(fixture({ failState: true })), /GitHub alert operation failed/);
  const f = fixture({ privateRepo: true });
  await assert.rejects(run(f), /approved public/);
  assert.equal(f.calls.length, 1);
});
test("first hosted run verifies a clearly labelled synthetic assigned alert and closes it", async () => {
  const f = fixture();
  const original = f.request;
  f.request = async (url, init) => {
    const response = await original(url, init);
    if (new URL(url).pathname.endsWith("/issues/42") && init.method === "GET") {
      return new Response(JSON.stringify({ assignees: [{ login: "Owner" }] }));
    }
    return response;
  };
  const result = await run(f, { report: { ...report, availability: "ok", checks: [] }, startupDrill: true });
  assert.equal(result.alertDeliveryVerifiedAt, new Date(now).toISOString());
  const posted = f.calls.find(c => c.method === "POST" && c.path.endsWith("/issues"));
  assert.match(posted.body.title, /^\[TEST\]/);
  assert.match(posted.body.body, /No gateway outage was induced/);
  assert.ok(f.calls.some(c => c.method === "PATCH" && c.body.state === "closed"));
});
test("persisted alert verification does not repeat the synthetic test", async () => {
  const f = fixture({ previous: { signature: "ok", lastCheckedAt: report.checkedAt, alertDeliveryVerifiedAt: report.checkedAt } });
  await run(f, { report: { ...report, availability: "ok", checks: [] }, startupDrill: true });
  assert.equal(f.calls.filter(c => c.method === "POST").length, 0);
});