#!/bin/bash
set -euo pipefail

OUT_DIR="${1:-/tmp/bbh-rpm-fixture}"
mkdir -p "$OUT_DIR"
if ! command -v rpmbuild >/dev/null 2>&1; then
  echo "SKIP: rpmbuild not installed" >&2
  exit 2
fi

TOP="$OUT_DIR/rpmbuild"
mkdir -p "$TOP/BUILD" "$TOP/RPMS" "$TOP/SOURCES" "$TOP/SPECS" "$TOP/SRPMS"
cat > "$TOP/SPECS/bbh-minimal.spec" <<'EOF'
Name: bbh-minimal
Version: 1.0
Release: 1%{?dist}
Summary: BlackBox Hunter minimal RPM fixture
License: MIT
BuildArch: noarch

%description
Minimal fixture package for BlackBox Hunter integration tests.

%prep

%build

%install
mkdir -p %{buildroot}/usr/bin
cat > %{buildroot}/usr/bin/bbh-minimal <<'EOS'
#!/bin/sh
printf '%s\n' bbh-minimal
EOS
chmod 0755 %{buildroot}/usr/bin/bbh-minimal

%files
/usr/bin/bbh-minimal
EOF

rpmbuild --define "_topdir $TOP" -bb "$TOP/SPECS/bbh-minimal.spec" >/dev/null
find "$TOP/RPMS" -name '*.rpm' -type f | head -n 1
