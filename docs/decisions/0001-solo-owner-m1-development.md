# ADR-001: Solo-owner M1 development releases

## Status

Accepted policy amendment, implementation proposed by Engines issue #57.

## Date

2026-11-12

## Context

The project has one developer. The owner explicitly requested: "Change the
requirement to simplify this project" after the separate legal reviewer,
parameter reviewer and builder-key handoff blocked Platform M1-PR30 (#48).
These were project release-process requirements, not permissions that this
software can grant from dependency copyright/patent holders.

## Decision

For Engines M1 development distribution, use one explicit repository-owner
main workflow dispatch, an approval checkbox and exact CPU archive/image
configuration/owner-wheel hashes. Remove the external review tar, dual-review
keys, policy pin and builder key from this workflow. Bind the owner decision to
source/run/artifacts in the keylessly signed release. Keep build provenance,
package isolation, immutable artifact pins and all installed boundary checks.

Approved manifests use engines-m1-v2 / OWNER_APPROVED_DEVELOPMENT_ONLY and
explicitly disclaim independent review and production readiness. Existing v1
candidate bytes remain unchanged and denied. The new source needs a fresh
candidate before later authorized publication. CLI evidence inputs are removed;
consumers must deliberately adopt this versioned development profile.

## Consequences

There is no separate specialist-signature or expiring reviewer-policy ceremony
for this development profile. The owner selects and can withdraw the exact
release set. No actual approval, key or publication is seeded by implementing
this change. Tests demonstrate authentication/binding rules, not legal rights
or cryptographic security. Third-party obligations and production/commercial
qualification remain separate. Historical M0 records and standalone strict
scoped-review/owner-wheel verification protocols are not changed.

## Alternatives

Retaining seven signatures and independently provisioned policy/builder keys was
rejected by the owner as excessive for the development workflow. Unconditional
publication was rejected because it would lose explicit owner intent and exact
artifact binding. Repository-owned signing keys are unnecessary: existing GitHub
OIDC authenticates the final publisher/source assertion.
