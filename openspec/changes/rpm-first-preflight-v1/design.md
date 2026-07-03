# Design: rpm-first-preflight-v1

RPM targets use this manager order: `dnf`, `microdnf`, `yum`, `zypper`, `rpm-ostree`, then portability fallbacks.

Debian targets keep `apt` first.

Preflight records the selected manager in `env_check.json.package_manager` and reuses the existing fallback, hard-block, phase-block, and confidence-ceiling matrix.

RPM extraction coverage is represented by `rpm2cpio` with `7z` and `bsdtar` fallbacks.
