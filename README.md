# Meshest release verification

Verification material for the invitation-only Meshest pilot. This repository contains only a standalone bootstrap and public connector checksums. The application and connector archive remain restricted to approved pilot accounts.

The currently qualified profile is Linux ARM64, non-root Python 3.11+, curl and normal HTTPS certificate trust. Use the preparation command supplied by Meshest for an exact immutable commit in this repository, together with the connector archive downloaded after sign-in. The bootstrap verifies the archive and its preparation tool before the canonical extractor runs. It does not register agents, connect provider accounts, grant permissions or spend model allowance.

The trust boundary is this independently administered GitHub publisher over verified HTTPS and immutable commit contents. It is not a detached release signature, rollback-prevention guarantee or protection from a compromised publisher. Mutable branch URLs must not be substituted for the pinned commit. Failed preparation preserves downloaded files and existing or partial destinations; it does not automatically retry or repair saved state.

This material does not establish production readiness or support for native macOS/Windows installation. No private application source, connector binaries, credentials, owner identities or task data are published here.
