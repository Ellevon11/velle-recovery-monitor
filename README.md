# Velle independent recovery gateway monitor

This public repository contains **only monitoring code and public trust
identifiers**. It contains no Velle app source, journal, token, AWS access
key, bucket name, KMS key identifier, or Clerk administrative credential.

## What runs

GitHub-hosted standard Ubuntu runners check the approved public-IP gateway
every 15 minutes (at minutes 7, 22, 37 and 52). GitHub schedules can be delayed;
this is best-effort monitoring, not a guaranteed 15-minute alert SLA.
Only a public repository is approved; standard public-repository Actions
execution does not consume private-repository included minutes. Do not switch
to paid/larger runners or add a paid service without fresh owner approval.

Checks are concurrent: a failed primary signing-key host cannot prevent gateway
TLS, health, discovery, or deployed-trust checks from running or being reported.
The monitor and alert destination are neither of the monitored hosts.

- Verified public CA chain and the exact IP certificate identity, without SNI,
  matching native numeric-IP connections and exercising Caddy's default SNI.
- Certificate dates, renewal overdue at 36 hours remaining, and replacement
  certificates that fail to extend expiry. The certificate is not permanently
  pinned: normal trusted ACME renewal is allowed.
- `/healthz` response shape and status.
- `/monitorz` read-only discovery listing in a reserved non-customer namespace,
  plus exact deployed issuer/key fingerprints. Diagnostic checks are cached for
  one minute, single-flight and deadline-bounded. A hung underlying operation
  cannot create an unbounded probe flood.
- Unauthenticated discovery must return 401 (fail closed).
- Production JWKS must still match explicitly approved pinned key identities,
  including RSA material, not just `kid`. Unknown or changed keys alert; they
  are **never** downloaded into gateway trust automatically.

## Alerts and monitor continuity

An incident opens an issue assigned to the owner. Changed failures update that
issue; unchanged incidents do not produce issue-comment spam. Recovery posts a
comment and closes it. Failed checks also fail the workflow. Enable GitHub
Actions failure email notifications and notifications for assigned issues in
your GitHub notification settings; email delivery depends on those settings.
The first hosted run also creates a clearly labelled **[TEST]** issue, verifies
that it was assigned to the owner, and closes it. This tests the runner's actual
alert permissions without inducing an outage or using customer data. The
verification timestamp is persisted so the test does not repeat each run.
Email receipt itself is not certified by the API; check notification settings.
The GitHub Actions run and assigned incident issue remain the independent
visible report even if the primary app is down.

`state.json` stores only certificate fingerprint/expiry, diagnostic failure
identifiers, issue number, alert-verification time and check time. A daily state commit prevents the normal
60-day repository-inactivity shutdown of public scheduled workflows. Alert or
state persistence failures fail the workflow rather than falsely reporting
delivery. No artifacts or external notification services are purchased.

Use **Actions → Independent recovery gateway monitor → Run workflow** for a
manual check. A disabled/deleted workflow or GitHub-wide outage cannot alert
through this same GitHub runner; use a separately approved second monitor if
that risk needs coverage.

## This is not recovery certification

**Authenticated recovery: unverified. Production-auth outage independence:
release-blocked.** Neither a healthy public endpoint, a reserved-namespace
listing, nor a 401 establishes a production-authenticated recovery drill,
KMS decrypt success, journal correctness, or physical-phone recovery.
Fresh production sign-in/token refresh still depend on the primary host.
Do not use customer journals or customer sessions to investigate alerts.

## Responding to an alert

1. Inspect fixed diagnostic summaries in the issue/run. Do not copy credentials
   or environment files into issues/logs.
2. TLS/network/renewal failure: inspect the existing owned Caddy/Lightsail
   service and ACME renewal. Keep certificate checks enabled; never install a
   self-signed certificate as a workaround.
3. Discovery failure: inspect the existing read-only gateway credential access
   to the original private AWS store. Do not replace the bucket or encryption
   key, grant write access, or probe real owners.
4. Unknown signing keys: independently verify the original production tenant,
   issuer and public signing configuration. An operator must approve and update
   both gateway trust and monitor `config.json`. Do not accept arbitrary keys,
   change issuer, substitute preview keys, or create a new tenant.
5. Signing source unreachable: freshness is unknown; gateway checks still run.
   This can accompany the existing primary-host authentication release blocker.

## Local verification

Requires Node 20+ and no installed dependencies:

```sh
node --test monitor.test.mjs notify.test.mjs
node monitor.mjs
```

The actual production-authenticated outage drill is separate work and remains
a release blocker until demonstrated with synthetic, production-signed data.