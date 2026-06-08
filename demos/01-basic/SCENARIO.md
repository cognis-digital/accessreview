# Demo 01 — Q2 SOC 2 User Access Review

A mid-size SaaS company runs its quarterly periodic access review (UAR) ahead
of a SOC 2 Type II audit. The security team exports an **entitlements snapshot**
(`entitlements.json`) from its IdP/IGA tooling — one row per (user, system,
role) grant — and an **HR roster** (`roster.csv`) from the HRIS.

ACCESSREVIEW joins the two and flags grants that auditors care about:

| Finding      | What it catches                                              |
|--------------|--------------------------------------------------------------|
| `TERMINATED` | A user marked terminated in HR who still has live access     |
| `ORPHAN`     | An account with no matching HR/identity record               |
| `STALE`      | Access unused past the policy window (tighter for admins)    |
| `PRIVILEGED` | Admin/privileged entitlements that need elevated scrutiny    |
| `SOD`        | Separation-of-duties conflicts (toxic role pairs)            |
| `NO_MANAGER` | No manager to act as reviewer/approver                       |

Each grant gets a **risk score** and a **recommendation**: `revoke`, `review`,
or `certify`.

## Run it

```bash
# Full campaign as a table (exits non-zero if anything must be revoked)
python -m accessreview run demos/01-basic/entitlements.json \
    --roster demos/01-basic/roster.csv --as-of 2026-06-30

# Just the revocation work-list, as JSON for ticketing automation
python -m accessreview --format json revoke demos/01-basic/entitlements.json \
    --roster demos/01-basic/roster.csv --as-of 2026-06-30

# Summary stats only
python -m accessreview summary demos/01-basic/entitlements.json \
    --roster demos/01-basic/roster.csv --as-of 2026-06-30
```

## What to expect

- **u_carol** is terminated but still holds Salesforce + AWS access → `revoke`.
- **u_ghost** has an AWS admin grant with no HR record → `ORPHAN` → `revoke`.
- **u_alice** holds both `ap_clerk` and `ap_approver` → `SOD` conflict → `review`.
- **u_dave** is a privileged AWS admin unused for ~200 days → `STALE`+`PRIVILEGED`.
- **u_bob** uses everything recently and has no conflicts → `certify`.
