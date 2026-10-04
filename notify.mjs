import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const title = "Velle recovery gateway monitoring alert";
const marker = "<!-- velle-recovery-monitor -->";

/** Only fixed diagnostic summaries become public issues; never remote bodies. */
export function incidentBody(report, runUrl) {
  return `${marker}
Independent monitoring detected a recovery gateway problem.

${report.checks.filter(c => c.status === "failed").map(c => `- ${c.id}: ${c.message}`).join("\n")}

Checked: ${report.checkedAt}
Run: ${runUrl}

Authenticated recovery is **unverified**. Production sign-in/refresh outage independence remains **release-blocked**.
Do not rotate keys automatically, disable TLS verification, or use customer journals to investigate.
`;
}

export async function notify({ report, config, repo, token, request = fetch, now = Date.now(), runId, startupDrill = false }) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo ?? "") || !token
    || !/^[A-Za-z0-9-]+$/.test(config.alertAssignee ?? "") || !/^\d+$/.test(String(runId))) {
    throw new Error("Alert delivery configuration is incomplete");
  }
  const base = `/repos/${repo}`;
  const api = async (path, method = "GET", body) => {
    const response = await request(`https://api.github.com${path}`, {
      method, signal: AbortSignal.timeout(15_000),
      headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json",
        "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28" },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (!response.ok) throw new Error(`GitHub alert operation failed (${response.status})`);
    return response.status === 204 ? null : response.json();
  };
  const repository = await api(base);
  // Never silently consume private-repository Actions minutes.
  if (repository.private || repository.default_branch !== "main") throw new Error("Monitor requires the approved public main-branch repository");
  let previous = {}, file;
  const fileResponse = await request(`https://api.github.com${base}/contents/state.json`, {
    signal: AbortSignal.timeout(15_000),
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" },
  });
  if (fileResponse.ok) {
    file = await fileResponse.json();
    previous = JSON.parse(Buffer.from(file.content, "base64").toString("utf8"));
  } else if (fileResponse.status !== 404) throw new Error("Monitor state could not be read");
  let issueNumber = previous.issueNumber;
  const failedIds = report.checks.filter(c => c.status === "failed").map(c => c.id).sort().join(",");
  const incident = report.availability !== "ok";
  const signature = incident ? failedIds : "ok";
  const runUrl = `https://github.com/${repo}/actions/runs/${runId}`;
  let issue;
  if (Number.isSafeInteger(issueNumber) && issueNumber > 0) {
    issue = await api(`${base}/issues/${issueNumber}`);
    if (issue.title !== title || !issue.body?.includes(marker) || issue.pull_request) throw new Error("Alert issue identity mismatch");
  } else if (incident) {
    // Recover after a state-write failure without creating repeated alerts.
    const issues = await api(`${base}/issues?state=open&per_page=100`);
    issue = issues.find(i => i.title === title && i.body?.includes(marker) && !i.pull_request);
    issueNumber = issue?.number;
  }
  if (incident && (!issue || issue.state === "closed")) {
    issue = await api(`${base}/issues`, "POST", {
      title, body: incidentBody(report, runUrl), assignees: [config.alertAssignee],
    });
    issueNumber = issue.number;
  } else if (incident && (previous.signature !== signature || !previous.issueNumber)) {
    await api(`${base}/issues/${issueNumber}`, "PATCH", { body: incidentBody(report, runUrl) });
    await api(`${base}/issues/${issueNumber}/comments`, "POST", { body: incidentBody(report, runUrl) });
  } else if (!incident && issue?.state === "open") {
    await api(`${base}/issues/${issueNumber}/comments`, "POST", {
      body: `Availability checks recovered at ${report.checkedAt}. ${runUrl}\nAuthenticated recovery is still unverified; production-auth outage independence remains release-blocked.`,
    });
    await api(`${base}/issues/${issueNumber}`, "PATCH", { state: "closed", state_reason: "completed" });
  }
  const certificate = report.certificate ?? previous.certificate;
  let alertDeliveryVerifiedAt = previous.alertDeliveryVerifiedAt;
  if (startupDrill && !alertDeliveryVerifiedAt) {
    const drill = await api(`${base}/issues`, "POST", {
      title: "[TEST] Velle recovery monitor alert-delivery check",
      body: `Synthetic alert-delivery check only. **No gateway outage was induced or detected by this test.**\n\nThe independent GitHub runner is checking that it can assign an alert to the owner. No customer account, journal, AWS credential or Clerk token is used.\n\n${runUrl}`,
      assignees: [config.alertAssignee],
    });
    const delivered = await api(`${base}/issues/${drill.number}`);
    if (!delivered.assignees?.some(a => a.login === config.alertAssignee)) {
      throw new Error("Synthetic alert assignment could not be verified");
    }
    await api(`${base}/issues/${drill.number}/comments`, "POST", {
      body: "Synthetic alert was successfully created and assigned by the independent runner. Closing the test. This does not certify authenticated recovery or production-auth outage independence.",
    });
    await api(`${base}/issues/${drill.number}`, "PATCH", { state: "closed", state_reason: "completed" });
    alertDeliveryVerifiedAt = new Date(now).toISOString();
  }
  const state = {
    version: 1, lastCheckedAt: report.checkedAt, signature,
    ...(issueNumber ? { issueNumber } : {}),
    ...(certificate ? { certificate } : {}),
    ...(alertDeliveryVerifiedAt ? { alertDeliveryVerifiedAt } : {}),
  };
  // A daily public, data-free state commit also prevents GitHub's 60-day
  // repository-inactivity scheduled-workflow shutdown. No extra service.
  if (!file || previous.signature !== signature || previous.issueNumber !== issueNumber
    || previous.alertDeliveryVerifiedAt !== alertDeliveryVerifiedAt
    || JSON.stringify(previous.certificate) !== JSON.stringify(certificate)
    || now - Date.parse(previous.lastCheckedAt) >= 24 * 3_600_000) {
    await api(`${base}/contents/state.json`, "PUT", {
      message: "Record public recovery-monitor status",
      content: Buffer.from(JSON.stringify(state, null, 2) + "\n").toString("base64"),
      ...(file ? { sha: file.sha } : {}),
      branch: "main",
    });
  }
  return { delivered: true, incident, ...(issueNumber ? { issueNumber } : {}),
    ...(alertDeliveryVerifiedAt ? { alertDeliveryVerifiedAt } : {}) };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    let report;
    try { report = JSON.parse(await readFile("report.json", "utf8")); }
    catch {
      report = { checkedAt: new Date().toISOString(), availability: "incident", checks: [
        { id: "monitor-execution", status: "failed", message: "Monitor did not produce a report; inspect the workflow" },
      ] };
    }
    const config = JSON.parse(await readFile(new URL("./config.json", import.meta.url), "utf8"));
    console.log(JSON.stringify(await notify({ report, config, repo: process.env.GITHUB_REPOSITORY,
      token: process.env.GITHUB_TOKEN, runId: process.env.GITHUB_RUN_ID, startupDrill: true })));
  } catch {
    console.error("GitHub alert delivery failed. Check workflow permissions and GitHub Actions failure notifications.");
    process.exitCode = 1;
  }
}