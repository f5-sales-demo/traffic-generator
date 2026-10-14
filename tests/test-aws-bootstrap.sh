#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
AWS_ROOT="${REPO_ROOT}/terraform/aws"
HOST_INTEGRATION=0
case "${1:-}" in
'') ;;
--host-integration) HOST_INTEGRATION=1 ;;
*)
  printf 'Usage: %s [--host-integration]\n' "$0" >&2
  exit 64
  ;;
esac
test "$#" -le 1
HOST_ROOT=
TMP=$(mktemp -d)
cleanup() {
  if test -n "$HOST_ROOT"; then sudo -n rm -rf -- "$HOST_ROOT"; fi
  rm -rf "$TMP"
}
trap cleanup EXIT
if test "$HOST_INTEGRATION" -eq 1; then
  test "$(uname -s)" = Linux
  for tool in sudo systemd-tmpfiles getent node npm; do command -v "$tool" >/dev/null; done
  sudo -n true
fi

cat >"$TMP/main.tf" <<EOF
variable "continuous_enabled" {
  type = bool
  default = true
}
locals {
  rendered = templatefile("${AWS_ROOT}/cloud-init.tftpl", {
    continuous_enabled = var.continuous_enabled
    aws_region = "us-east-1"
    ami_id = "ami-0123456789abcdef0"
    evidence_bucket = "fixture-evidence"
    log_group_name = "/fixture/csd"
    source_commit = "5945bb84511c64610452ed3efe9c7c3a0027509e"
    source_repository_url = "https://github.com/f5-sales-demo/traffic-generator.git"
    aws_cli_version = "2.31.0"
    aws_cli_archive_url = "https://example.invalid/awscliv2.zip"
    aws_cli_archive_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    cloudwatch_agent_version = "1.300073.2b1889-1"
    cloudwatch_agent_package_url = "https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb?versionId=gBsjqYJfnfEGrqGYPyWw1Ct8qjfwnNSz"
    cloudwatch_agent_package_sha256 = "f25c81f42627ac481b51215e8e6f989208ab266f8b224ffd66a208061e790f1c"
    node_archive_url = "https://example.invalid/node.tar.xz"
    node_archive_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    chrome_archive_url = "https://example.invalid/chrome.zip"
    chrome_archive_sha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    playwright_core_version = "1.55.0"
    deployment_manifest_version = "1.1.0"
    deployment_manifest_sha256 = "$(sha256sum "$REPO_ROOT/suites/csd-violations/scenarios.mjs" | cut -d' ' -f1)"
    target_url = "https://client-side-defense.f5-sales-demo.com"
  })
}
output "rendered" { value = local.rendered }
EOF

terraform -chdir="$TMP" init -backend=false -input=false >/dev/null
# Provider-free fixture plans expose outputs without console stdin, which the
# GitHub setup-terraform output wrapper does not forward to its child process.
terraform -chdir="$TMP" plan -refresh=false -input=false -lock=false -out="$TMP/enabled.tfplan" >/dev/null
terraform -chdir="$TMP" show -json "$TMP/enabled.tfplan" | jq -r '.planned_values.outputs.rendered.value' >"$TMP/cloud-init.yaml"
TF_VAR_continuous_enabled=false terraform -chdir="$TMP" plan -refresh=false -input=false -lock=false -out="$TMP/disabled.tfplan" >/dev/null
terraform -chdir="$TMP" show -json "$TMP/disabled.tfplan" | jq -r '.planned_values.outputs.rendered.value' >"$TMP/cloud-init-disabled.yaml"

awk '
  /^  - path: \/usr\/local\/sbin\/csd-bootstrap$/ { found=1; next }
  found && /^    content: \|$/ { body=1; next }
  body && /^runcmd:$/ { exit }
  body { sub(/^      /, ""); print }
' "$TMP/cloud-init.yaml" >"$TMP/csd-bootstrap"

test -s "$TMP/csd-bootstrap"
bash -n "$TMP/csd-bootstrap"
test "$(grep -Ec '^  - /usr/local/sbin/csd-bootstrap$' "$TMP/cloud-init.yaml")" -eq 1
test "$(grep -Ec '^runcmd:$' "$TMP/cloud-init.yaml")" -eq 1
if grep -Eq '^  - - /bin/bash$' "$TMP/cloud-init.yaml"; then
  exit 1
fi

# Exercise the rendered production helpers with real offline Debian packages.
# Ubuntu supplies dpkg-deb; do not replace metadata reads with a shell mock.
for tool in dpkg-deb curl sha256sum; do command -v "$tool" >/dev/null; done
grep -E '^fetch\(\) \{' "$TMP/csd-bootstrap" >"$TMP/cloudwatch-functions"
test "$(wc -l <"$TMP/cloudwatch-functions")" -eq 1
awk '/^verify_cloudwatch_agent_package\(\) \{$/ { body=1 } body { print } body && /^\}$/ { exit }' "$TMP/csd-bootstrap" >>"$TMP/cloudwatch-functions"
grep -Fxq 'verify_cloudwatch_agent_package() {' "$TMP/cloudwatch-functions"
bash -n "$TMP/cloudwatch-functions"
grep -Fq 'curl -fSL --retry 4 -o "$3" "$1"' "$TMP/cloudwatch-functions"
grep -Fq 'echo "$2  $3" | sha256sum -c' "$TMP/cloudwatch-functions"
fetch_line=$(grep -nFx "  fetch 'https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb?versionId=gBsjqYJfnfEGrqGYPyWw1Ct8qjfwnNSz' 'f25c81f42627ac481b51215e8e6f989208ab266f8b224ffd66a208061e790f1c' /tmp/cw.deb" "$TMP/csd-bootstrap" | cut -d: -f1)
verify_line=$(grep -nFx "  verify_cloudwatch_agent_package /tmp/cw.deb '1.300073.2b1889-1'" "$TMP/csd-bootstrap" | cut -d: -f1)
install_line=$(grep -nFx '  dpkg -i /tmp/cw.deb' "$TMP/csd-bootstrap" | cut -d: -f1)
test "$fetch_line" -lt "$verify_line"
test "$verify_line" -lt "$install_line"
cat >"$TMP/cloudwatch-package-regression" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
source "$1"
fetch "$2" "$3" "$4"
verify_cloudwatch_agent_package "$4" "$5"
# This boundary must never be reached for an untrusted package; do not install fixtures.
printf 'verified-before-install\n' >"$6"
EOF
chmod +x "$TMP/cloudwatch-package-regression"
expected_cloudwatch_version=1.300073.2b1889-1
for fixture in valid wrong-name wrong-architecture wrong-version; do
  package_name=amazon-cloudwatch-agent
  package_architecture=amd64
  package_version=$expected_cloudwatch_version
  case "$fixture" in
  wrong-name) package_name=not-cloudwatch-agent ;;
  wrong-architecture) package_architecture=arm64 ;;
  wrong-version) package_version=1.300073.1b1859-1 ;;
  esac
  mkdir -p "$TMP/$fixture/DEBIAN"
  # Shared CI parents may carry setgid; Debian control metadata must not inherit it.
  chmod 00755 "$TMP/$fixture/DEBIAN"
  printf 'Package: %s\nArchitecture: %s\nVersion: %s\nMaintainer: Fixture <fixture@example.com>\nDescription: Offline CloudWatch metadata regression\n' \
    "$package_name" "$package_architecture" "$package_version" >"$TMP/$fixture/DEBIAN/control"
  dpkg-deb --build "$TMP/$fixture" "$TMP/$fixture.deb" >/dev/null
  fixture_digest=$(sha256sum "$TMP/$fixture.deb" | cut -d' ' -f1)
  set +e
  "$TMP/cloudwatch-package-regression" "$TMP/cloudwatch-functions" "file://$TMP/$fixture.deb" "$fixture_digest" \
    "$TMP/$fixture-fetched.deb" "$expected_cloudwatch_version" "$TMP/$fixture-install-boundary" >"$TMP/$fixture.log" 2>&1
  fixture_rc=$?
  set -e
  # All metadata cases must pass the real checksum first, not fail during download.
  grep -Fxq "$TMP/$fixture-fetched.deb: OK" "$TMP/$fixture.log"
  cmp "$TMP/$fixture.deb" "$TMP/$fixture-fetched.deb"
  if test "$fixture" = valid; then
    test "$fixture_rc" -eq 0
    grep -Fxq verified-before-install "$TMP/$fixture-install-boundary"
  else
    test "$fixture_rc" -ne 0
    test ! -e "$TMP/$fixture-install-boundary"
  fi
  printf '[OK] CloudWatch package %s: exit=%s, real checksum and dpkg-deb metadata gate\n' "$fixture" "$fixture_rc"
done
# A different real file supplies a deliberately mismatched real SHA256.
wrong_digest=$(sha256sum "$TMP/wrong-version.deb" | cut -d' ' -f1)
test "$wrong_digest" != "$(sha256sum "$TMP/valid.deb" | cut -d' ' -f1)"
set +e
"$TMP/cloudwatch-package-regression" "$TMP/cloudwatch-functions" "file://$TMP/valid.deb" "$wrong_digest" \
  "$TMP/checksum-fetched.deb" "$expected_cloudwatch_version" "$TMP/checksum-install-boundary" >"$TMP/checksum.log" 2>&1
checksum_rc=$?
set -e
test "$checksum_rc" -ne 0
grep -Fxq "$TMP/checksum-fetched.deb: FAILED" "$TMP/checksum.log"
cmp "$TMP/valid.deb" "$TMP/checksum-fetched.deb"
test ! -e "$TMP/checksum-install-boundary"
printf '[OK] CloudWatch checksum mismatch: exit=%s, stopped before install boundary\n' "$checksum_rc"
if test -n "${CLOUDWATCH_AGENT_VERIFIED_PACKAGE:-}"; then
  test -f "$CLOUDWATCH_AGENT_VERIFIED_PACKAGE"
  official_package=$(realpath "$CLOUDWATCH_AGENT_VERIFIED_PACKAGE")
  "$TMP/cloudwatch-package-regression" "$TMP/cloudwatch-functions" "file://$official_package" \
    f25c81f42627ac481b51215e8e6f989208ab266f8b224ffd66a208061e790f1c \
    "$TMP/official-fetched.deb" "$expected_cloudwatch_version" "$TMP/official-install-boundary"
  grep -Fxq verified-before-install "$TMP/official-install-boundary"
  printf '[OK] supplied official CloudWatch package: exact verified checksum, name, architecture and version\n'
fi

cat >"$TMP/ubuntu.sources" <<'EOF'
Types: deb
URIs: http://us-east-1.ec2.archive.ubuntu.com/ubuntu/
Suites: noble noble-updates

Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: noble

Types: deb
URIs: http://security.ubuntu.com/ubuntu/
Suites: noble-security
EOF

sed -i.bak -E \
  -e 's#http://([[:alnum:].-]*ec2\.archive\.ubuntu\.com)/ubuntu/?#https://\1/ubuntu/#g' \
  -e 's#http://(archive|security)\.ubuntu\.com/ubuntu/?#https://\1.ubuntu.com/ubuntu/#g' \
  "$TMP/ubuntu.sources"
grep -Fxq 'URIs: https://us-east-1.ec2.archive.ubuntu.com/ubuntu/' "$TMP/ubuntu.sources"
grep -Fxq 'URIs: https://archive.ubuntu.com/ubuntu/' "$TMP/ubuntu.sources"
grep -Fxq 'URIs: https://security.ubuntu.com/ubuntu/' "$TMP/ubuntu.sources"
if grep -Eq 'URIs:[[:space:]].*http://' "$TMP/ubuntu.sources"; then
  exit 1
fi

grep -Fq 'set -Eeuo pipefail' "$TMP/csd-bootstrap"
grep -Fq 'trap fail_bootstrap ERR' "$TMP/csd-bootstrap"
grep -Fq 'write_status failed "$stage"' "$TMP/csd-bootstrap"
grep -Fq 'jq -r .version /opt/traffic-generator/node_modules/playwright-core/package.json' "$TMP/csd-bootstrap"
grep -Fxq 'cd /opt/traffic-generator/runtime/npm' "$TMP/csd-bootstrap"
grep -Fq 'npm_env=(env HOME=/opt/traffic-generator/browser-profile PATH=/opt/node/bin:' "$TMP/csd-bootstrap"
grep -Fq 'sudo -u tgen "${npm_env[@]}" /opt/node/bin/npm install --ignore-scripts --omit=dev --save-exact' "$TMP/csd-bootstrap"
grep -Fxq '  mv node_modules /opt/traffic-generator/node_modules' "$TMP/csd-bootstrap"
grep -Fq 'install -d -o root -g root -m 0755 /opt/traffic-generator' "$TMP/csd-bootstrap"
grep -Fq 'chown root:root "$status_file.tmp"' "$TMP/csd-bootstrap"
grep -Fq 'chmod 0644 "$status_file.tmp"' "$TMP/csd-bootstrap"
awk '/^setup_runtime_directories\(\) \{$/ { body=1 } body { print } body && /^\}$/ { exit }' "$TMP/csd-bootstrap" >"$TMP/runtime-directories-function"
test -s "$TMP/runtime-directories-function"
grep -Fxq '  install -d -o root -g root -m 0755 /opt/traffic-generator /opt/traffic-generator/runtime' "$TMP/runtime-directories-function"
grep -Fq 'install -d -o tgen -g tgen -m 0750' "$TMP/runtime-directories-function"
for child in runtime/results runtime/npm browser-profile .cache .config .npm; do
  grep -Fq "/opt/traffic-generator/$child" "$TMP/runtime-directories-function"
done
setup_line=$(grep -nFx setup_runtime_directories "$TMP/csd-bootstrap" | cut -d: -f1)
tmpfiles_line=$(grep -nFx 'systemd-tmpfiles --create /etc/tmpfiles.d/csd-traffic-generator.conf' "$TMP/csd-bootstrap" | cut -d: -f1)
test "$setup_line" -lt "$tmpfiles_line"
grep -Fq 'install -d -m 0755 /run/sshd' "$TMP/csd-bootstrap"
grep -Fq "ss -H -ltn '( sport = :22 )' | grep -q LISTEN" "$TMP/csd-bootstrap"
cloudwatch_line=$(grep -n '^stage=cloudwatch-config$' "$TMP/csd-bootstrap" | cut -d: -f1)
services_line=$(grep -n '^stage=services$' "$TMP/csd-bootstrap" | cut -d: -f1)
test "$services_line" -gt "$cloudwatch_line"

awk '
  /^normalize_chrome_permissions\(\) \{$/ { body=1 }
  body { print }
  body && /^\}$/ { exit }
' "$TMP/csd-bootstrap" >"$TMP/chrome-permissions-function"
grep -Fqx '  chown -R root:root "$chrome_root"' "$TMP/chrome-permissions-function"
grep -Fqx '  find "$chrome_root" -type d -exec chmod 00755 {} +' "$TMP/chrome-permissions-function"
grep -Fqx '  chmod 4755 "$chrome_root/chrome_sandbox"' "$TMP/chrome-permissions-function"
cat >"$TMP/chrome-permissions-regression" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
umask 027
$(cat "$TMP/chrome-permissions-function")
chown() { :; }
chrome_root="$TMP/chrome-fixture"
install -d -m 0750 "\$chrome_root/nested/resources"
install -m 0750 /dev/null "\$chrome_root/chrome"
install -m 0750 /dev/null "\$chrome_root/chrome_sandbox"
install -m 0640 /dev/null "\$chrome_root/nested/resources/data.pak"
chmod 2750 "\$chrome_root" "\$chrome_root/nested" "\$chrome_root/nested/resources"
fixture_owner="\$(id -u):\$(id -g)"
normalize_chrome_permissions "\$chrome_root"
test "\$(stat -c '%u:%g:%a' "\$chrome_root")" = "\$fixture_owner:755"
test "\$(stat -c '%u:%g:%a' "\$chrome_root/nested/resources")" = "\$fixture_owner:755"
test "\$(stat -c '%u:%g:%a' "\$chrome_root/chrome")" = "\$fixture_owner:755"
test "\$(stat -c '%u:%g:%a' "\$chrome_root/chrome_sandbox")" = "\$fixture_owner:4755"
test "\$(stat -c '%u:%g:%a' "\$chrome_root/nested/resources/data.pak")" = "\$fixture_owner:644"
test -x "\$chrome_root/chrome"
if find "\$chrome_root" -perm /0002 -print -quit | grep -q .; then exit 1; fi
rm -rf "\$chrome_root"
EOF
chmod +x "$TMP/chrome-permissions-regression"
if ! bash -x "$TMP/chrome-permissions-regression" >"$TMP/chrome-permissions.log" 2>&1; then
  cat "$TMP/chrome-permissions.log" >&2
  exit 1
fi

awk '
  /^normalize_aws_cli_permissions\(\) \{$/ { body=1 }
  body { print }
  body && /^\}$/ { exit }
' "$TMP/csd-bootstrap" >"$TMP/aws-cli-permissions-function"
grep -Fqx '  find -P "$aws_cli_root" -type d -exec chown "$owner:$group" {} + -exec chmod 00750 {} +' "$TMP/aws-cli-permissions-function"
grep -Fqx '  find -P "$aws_cli_root" -type f -perm /u=x -exec chmod 0750 {} +' "$TMP/aws-cli-permissions-function"
grep -Fqx '  find -P "$aws_cli_root" -type f ! -perm /u=x -exec chmod 0640 {} +' "$TMP/aws-cli-permissions-function"
cat >"$TMP/aws-cli-permissions-regression" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
umask 027
$(cat "$TMP/aws-cli-permissions-function")
chown() {
  local owner_group=\$1
  shift
  command chown "\$(id -u):\$(id -g)" "\$@"
  test "\$owner_group" = "\$(id -un):\$(id -gn)"
}
aws_cli_root="$TMP/aws-cli-fixture"
install -d -m 0777 "\$aws_cli_root/v2/current/bin"
install -m 0777 /dev/null "\$aws_cli_root/v2/current/bin/aws"
install -m 0666 /dev/null "\$aws_cli_root/v2/current/data"
chmod 2777 "\$aws_cli_root" "\$aws_cli_root/v2" "\$aws_cli_root/v2/current" "\$aws_cli_root/v2/current/bin"
ln -s v2/current/bin/aws "\$aws_cli_root/aws"
link_target="\$(readlink "\$aws_cli_root/aws")"
normalize_aws_cli_permissions "\$aws_cli_root" "\$(id -un)" "\$(id -gn)"
fixture_owner="\$(id -u):\$(id -g)"
test "\$(stat -c '%u:%g:%a' "\$aws_cli_root")" = "\$fixture_owner:750"
test "\$(stat -c '%u:%g:%a' "\$aws_cli_root/v2/current/bin")" = "\$fixture_owner:750"
test "\$(stat -c '%u:%g:%a' "\$aws_cli_root/v2/current/bin/aws")" = "\$fixture_owner:750"
test "\$(stat -c '%u:%g:%a' "\$aws_cli_root/v2/current/data")" = "\$fixture_owner:640"
test "\$(readlink "\$aws_cli_root/aws")" = "\$link_target"
test -x "\$aws_cli_root/aws"
if find -P "\$aws_cli_root" \( -type d -o -type f \) -perm /0007 -print -quit | grep -q .; then exit 1; fi
rm -rf "\$aws_cli_root"
EOF
chmod +x "$TMP/aws-cli-permissions-regression"
if ! bash -x "$TMP/aws-cli-permissions-regression" >"$TMP/aws-cli-permissions.log" 2>&1; then
  cat "$TMP/aws-cli-permissions.log" >&2
  exit 1
fi

awk '
  /^      install -d -m 0755 \/run\/sshd$/ { body=1 }
  body && /^      stage=cloudwatch-config$/ { exit }
  body { sub(/^      /, ""); print }
' "${AWS_ROOT}/cloud-init.tftpl" >"$TMP/ssh-activation"
mkdir -p "$TMP/mock-bin"
cat >"$TMP/mock-bin/systemctl" <<'MOCK_SYSTEMCTL'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$SYSTEMCTL_LOG"
case "$*" in
  'is-active --quiet ssh.socket') exit 0 ;;
  'disable --now ssh.socket') exit 0 ;;
  'unmask ssh.service') exit 0 ;;
  'is-active --quiet ssh.service') test -f "$SYSTEMCTL_STATE" ;;
  'enable --now ssh.service') touch "$SYSTEMCTL_STATE" ;;
  'is-enabled --quiet ssh.service') test -f "$SYSTEMCTL_STATE" ;;
  'reload-or-restart ssh.service') test -f "$SYSTEMCTL_STATE" || exit 90 ;;
  *) exit 91 ;;
esac
MOCK_SYSTEMCTL
cat >"$TMP/mock-bin/sshd" <<'MOCK_SSHD'
#!/usr/bin/env bash
test "$*" = -t
MOCK_SSHD
cat >"$TMP/mock-bin/ss" <<'MOCK_SS'
#!/usr/bin/env bash
printf 'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n'
MOCK_SS
cat >"$TMP/mock-bin/install" <<'MOCK_INSTALL'
#!/usr/bin/env bash
test "$*" = '-d -m 0755 /run/sshd'
MOCK_INSTALL
chmod +x "$TMP/mock-bin/systemctl" "$TMP/mock-bin/sshd" "$TMP/mock-bin/ss" "$TMP/mock-bin/install"
cat >"$TMP/ssh-activation-regression" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
PATH="$TMP/mock-bin:\$PATH"
export SYSTEMCTL_LOG="$TMP/systemctl.log"
export SYSTEMCTL_STATE="$TMP/systemctl.state"
$(cat "$TMP/ssh-activation")
EOF
chmod +x "$TMP/ssh-activation-regression"
"$TMP/ssh-activation-regression"
grep -Fxq 'unmask ssh.service' "$TMP/systemctl.log"
grep -Fxq 'disable --now ssh.socket' "$TMP/systemctl.log"
grep -Fxq 'enable --now ssh.service' "$TMP/systemctl.log"
if grep -Fxq 'reload-or-restart ssh.service' "$TMP/systemctl.log"; then exit 1; fi
enable_line=$(grep -nFx 'enable --now ssh.service' "$TMP/systemctl.log" | cut -d: -f1)
final_active_line=$(grep -nFx 'is-active --quiet ssh.service' "$TMP/systemctl.log" | tail -n 1 | cut -d: -f1)
test "$final_active_line" -gt "$enable_line"

awk '
  /^write_status\(\) \{$/ { body=1 }
  body { print }
  body && /^trap fail_bootstrap ERR$/ { exit }
' "$TMP/csd-bootstrap" >"$TMP/status-functions"
cat >"$TMP/failing-helper-regression" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
status_file="$TMP/status.json"
stage=failing-helper
install() { :; }
chown() { :; }
chmod() { :; }
$(cat "$TMP/status-functions")
failing_helper() { return 23; }
write_status provisioning
failing_helper
EOF
chmod +x "$TMP/failing-helper-regression"
set +e
"$TMP/failing-helper-regression" >"$TMP/failing-helper.stdout" 2>"$TMP/failing-helper.stderr"
failure_rc=$?
set -e
test "$failure_rc" -eq 23
grep -Fxq 'bootstrap status=failed stage=failing-helper exit=23' "$TMP/failing-helper.stderr"
test "$(wc -l <"$TMP/failing-helper.stderr")" -eq 1
if grep -Eq 'csd-log-event|curl|aws|logger' "$TMP/status-functions"; then exit 1; fi
test "$(jq -r .status "$TMP/status.json")" = failed
test "$(jq -r .stage "$TMP/status.json")" = failing-helper
test "$(jq -r .error_stage "$TMP/status.json")" = failing-helper
# Hydration renders both modes without Terraform plan/apply or guest traffic.
grep -Fxq '      CONTINUOUS_ENABLED=1' "$TMP/cloud-init.yaml"
grep -Fxq '      CONTINUOUS_ENABLED=0' "$TMP/cloud-init-disabled.yaml"
grep -Fq 'continuous_enabled              = var.continuous_enabled' "$AWS_ROOT/main.tf"
grep -Fq 'variable "continuous_enabled"' "$AWS_ROOT/variables.tf"
grep -Fq 'output "continuous_enabled"' "$AWS_ROOT/outputs.tf"
grep -A5 -F 'variable "continuous_enabled"' "$AWS_ROOT/variables.tf" | grep -Fq 'default     = true'
extract_file() {
  awk -v target="$1" '
    $0 == "  - path: " target { found=1; next }
    found && /^    content: \|$/ { body=1; next }
    body && (/^  - path:/ || /^runcmd:/) { exit }
    body { sub(/^      /, ""); print }
  ' "$2"
}
for helper in csd-run csd-worker-health-check csd-log-event; do
  extract_file "/usr/local/bin/$helper" "$TMP/cloud-init.yaml" >"$TMP/$helper"
  bash -n "$TMP/$helper"
done
if grep -Eq 'flock|exec 9>' "$TMP/csd-run"; then exit 1; fi
for unit in csd-continuous.service csd-continuous.timer csd-worker-health.service csd-xvfb.service; do
  extract_file "/etc/systemd/system/$unit" "$TMP/cloud-init.yaml" >"$TMP/$unit"
  test -s "$TMP/$unit"
done
# Rendered unit contracts run in unit CI; actual systemd parsing is an explicit
# environment integration in tests/csd-host.integration.mjs.
grep -Fxq 'Requires=csd-worker-health.service' "$TMP/csd-continuous.service"
grep -Fxq 'After=csd-worker-health.service network-online.target systemd-tmpfiles-setup.service' "$TMP/csd-continuous.service"
grep -Fxq 'ExecStart=/opt/node/bin/node /opt/traffic-generator/source/suites/csd-violations/continuous.mjs tick' "$TMP/csd-continuous.service"
grep -Fxq 'TimeoutStartSec=1100s' "$TMP/csd-continuous.service"
grep -Fxq 'TimeoutStopSec=45s' "$TMP/csd-continuous.service"
grep -Fxq 'KillMode=control-group' "$TMP/csd-continuous.service"
grep -Fxq 'OnBootSec=30s' "$TMP/csd-continuous.timer"
grep -Fxq 'OnUnitInactiveSec=15s' "$TMP/csd-continuous.timer"
grep -Fxq 'AccuracySec=1s' "$TMP/csd-continuous.timer"
grep -Fxq 'Persistent=false' "$TMP/csd-continuous.timer"
grep -Fxq 'WantedBy=timers.target' "$TMP/csd-continuous.timer"
grep -Fxq 'Requires=csd-xvfb.service' "$TMP/csd-worker-health.service"
grep -Fxq 'Wants=network-online.target' "$TMP/csd-worker-health.service"
grep -Fxq 'TimeoutStartSec=120s' "$TMP/csd-worker-health.service"
grep -Fxq 'TimeoutStopSec=30s' "$TMP/csd-worker-health.service"
extract_file /etc/tmpfiles.d/csd-traffic-generator.conf "$TMP/cloud-init.yaml" >"$TMP/tmpfiles.conf"
grep -Fxq 'f /run/lock/csd-traffic-generator.lock 0660 root tgen -' "$TMP/tmpfiles.conf"
grep -Fxq 'd /opt/traffic-generator/runtime/continuous 0700 root root -' "$TMP/tmpfiles.conf"
for parent in /opt/traffic-generator /opt/traffic-generator/runtime; do
  grep -Fxq "d $parent 0755 root root -" "$TMP/tmpfiles.conf"
done
if grep -Eq '^d[[:space:]]+/run(/lock)?[[:space:]]' "$TMP/tmpfiles.conf"; then exit 1; fi
rw_paths=$(grep '^ReadWritePaths=' "$TMP/csd-xvfb.service")
for path in ${rw_paths#ReadWritePaths=}; do
  case "$path" in /opt/traffic-generator | /opt/traffic-generator/runtime) exit 1 ;; esac
done
grep -Fq 'sudo -u tgen env HOME=/opt/traffic-generator/browser-profile DISPLAY=:99' "$TMP/csd-worker-health-check"
grep -Fq 'chown root:root /opt/traffic-generator/status.json' "$TMP/csd-worker-health-check"
grep -Fq 'chmod 0644 /opt/traffic-generator/status.json' "$TMP/csd-worker-health-check"
extract_file /etc/logrotate.d/csd-traffic-generator "$TMP/cloud-init.yaml" >"$TMP/logrotate.conf"
for setting in daily 'size 10M' 'rotate 7' compress delaycompress copytruncate; do
  grep -Fxq "  $setting" "$TMP/logrotate.conf"
done
grep -Fq 'test -f "$1/suites/csd-violations/continuous.mjs"' "$TMP/csd-bootstrap"
grep -Fq '/opt/node/bin/node --check "$dst/suites/csd-violations/continuous.mjs"' "$TMP/csd-bootstrap"
sed "s#/opt/node/bin/node#$(command -v node)#g" "$TMP/csd-bootstrap" | awk '/^valid\(\) \{$/ { body=1 } body { print } body && /^\}$/ { exit }' >"$TMP/source-valid-function"
(
  source "$TMP/source-valid-function"
  fixture="$TMP/source-fixture"
  manifest=suites/csd-violations/scenarios.mjs
  mkdir -p "$fixture/suites/csd-violations"
  cp "$REPO_ROOT/$manifest" "$fixture/$manifest"
  touch "$fixture/suites/csd-violations/run.sh" "$fixture/suites/csd-violations/run.mjs"
  git init -q "$fixture"
  git -C "$fixture" add suites
  git -C "$fixture" -c user.name='Fixture' -c user.email='fixture@example.com' commit -qm fixture
  commit=$(git -C "$fixture" rev-parse HEAD)
  digest=$(sha256sum "$fixture/$manifest" | cut -d' ' -f1)
  if valid "$fixture"; then exit 1; fi
  touch "$fixture/suites/csd-violations/continuous.mjs"
  valid "$fixture"
  digest=invalid
  if valid "$fixture"; then exit 1; fi
  # Exact source bytes alone cannot authorize an old or incomplete manifest.
  for invalid in old-version missing-slot; do
    case "$invalid" in
    old-version) printf 'export const SCENARIO_NAMES = Array.from({length:14}, (_, i) => String(i)); export const SUITE_MANIFEST = {schemaVersion:"1.0.0", scenarios:SCENARIO_NAMES.map(name => ({name}))};\n' >"$fixture/$manifest" ;;
    missing-slot) printf 'export const SCENARIO_NAMES = Array.from({length:13}, (_, i) => String(i)); export const SUITE_MANIFEST = {schemaVersion:"1.1.0", scenarios:SCENARIO_NAMES.map(name => ({name}))};\n' >"$fixture/$manifest" ;;
    esac
    digest=$(sha256sum "$fixture/$manifest" | cut -d' ' -f1)
    if valid "$fixture"; then exit 1; fi
  done
)
node --input-type=module - "$REPO_ROOT" "$TMP/csd-run" <<'NODE'
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const root = process.argv[2];
const { SCENARIO_NAMES, SUITE_MANIFEST } = await import(pathToFileURL(`${root}/suites/csd-violations/scenarios.mjs`));
assert.equal(SUITE_MANIFEST.schemaVersion, '1.1.0');
assert.equal(SCENARIO_NAMES.length, 14);
assert.equal(new Set(SCENARIO_NAMES).size, 14);
const allowlist = readFileSync(process.argv[3], 'utf8').match(/^  ([a-z0-9|\-]+)\) ;;$/m)?.[1].split('|');
assert.deepEqual(allowlist, SCENARIO_NAMES);
assert.deepEqual(SCENARIO_NAMES.slice(11), ['header-omit-x-content-type-options', 'header-omit-x-frame-options', 'header-omit-cache-control']);
assert.match(readFileSync(`${root}/suites/csd-violations/run.mjs`, 'utf8'), /schemaVersion: 3/);
NODE
stop_line=$(grep -nFx 'systemctl disable --now csd-continuous.timer csd-continuous.service' "$TMP/csd-bootstrap" | head -n1 | cut -d: -f1)
source_line=$(grep -nFx 'stage=source' "$TMP/csd-bootstrap" | cut -d: -f1)
grep -Fq 'validateConfig(readFileSync("/etc/traffic-generator/runtime.env", "utf8"))' "$TMP/csd-worker-health-check"
test "$stop_line" -lt "$source_line"
grep -Fq 'test "$TARGET_URL" = https://client-side-defense.f5-sales-demo.com' "$TMP/csd-worker-health-check"
grep -Fq 'test "$(sha256sum /opt/traffic-generator/source/suites/csd-violations/scenarios.mjs' "$TMP/csd-worker-health-check"
# Exercise the actual rendered activation branches through a bounded command adapter.
for mode in enabled disabled; do
  yaml="$TMP/cloud-init.yaml"
  test "$mode" != disabled || yaml="$TMP/cloud-init-disabled.yaml"
  extract_file /usr/local/sbin/csd-bootstrap "$yaml" | awk '
    /^stage=services$/ { body=1; next }
    body && /^stage=ready$/ { exit }
    body { print }
  ' >"$TMP/activation-$mode"
  (
    set -Eeuo pipefail
    export MODE="$mode"
    export SYSTEMCTL_LOG="$TMP/activation-$mode.log"
    status_file="$TMP/ready-status.json"
    printf '{"status":"ready"}\n' >"$status_file"
    systemd-analyze() { test "$1" = verify; }
    systemctl() {
      printf '%s\n' "$*" >>"$SYSTEMCTL_LOG"
      case "$*" in
      'is-active --quiet csd-continuous.timer' | 'is-enabled --quiet csd-continuous.timer') test "$MODE" = enabled ;;
      'is-active --quiet csd-continuous.service') return 3 ;;
      *) return 0 ;;
      esac
    }
    systemd-analyze verify
    systemctl --version
    export -f systemctl systemd-analyze
    export status_file
    bash -e "$TMP/activation-$mode"
    printf '{"status":"failed"}\n' >"$status_file"
    if bash -e "$TMP/activation-$mode"; then exit 1; fi
  )
  grep -Fxq 'restart csd-worker-health.service' "$TMP/activation-$mode.log"
  if test "$mode" = enabled; then
    grep -Fxq 'enable --now csd-continuous.timer' "$TMP/activation-$mode.log"
  else
    grep -Fxq 'disable --now csd-continuous.timer csd-continuous.service' "$TMP/activation-$mode.log"
    if grep -Fxq 'enable --now csd-continuous.timer' "$TMP/activation-$mode.log"; then exit 1; fi
  fi
done
if test "$HOST_INTEGRATION" -eq 1; then
  HOST_ROOT=$(mktemp -d /tmp/csd-bootstrap-host.XXXXXX)
  fixture_user=$(id -un)
  fixture_uid=$(id -u)
  fixture_gid=$(id -g)
  # Use the caller's real non-root UID as the fixture tgen account.
  test "$fixture_uid" -ne 0
  test "$fixture_uid" -ne 65534
  sudo -n chown root:root "$HOST_ROOT"
  sudo -n chmod 0755 "$HOST_ROOT"
  sudo -n install -d -o root -g root -m 0755 "$HOST_ROOT/opt" "$HOST_ROOT/etc" "$HOST_ROOT/run"
  sudo -n install -d -o root -g root -m 1777 "$HOST_ROOT/run/lock"
  printf 'root:x:0:0:root:/root:/bin/sh\ntgen:x:%s:%s:fixture:/opt/traffic-generator:/bin/sh\n' "$fixture_uid" "$fixture_gid" | sudo -n tee "$HOST_ROOT/etc/passwd" >/dev/null
  printf 'root:x:0:\ntgen:x:%s:\n' "$fixture_gid" | sudo -n tee "$HOST_ROOT/etc/group" >/dev/null
  sudo -n chmod 0644 "$HOST_ROOT/etc/passwd" "$HOST_ROOT/etc/group"
  sudo -n install -d -o "$fixture_uid" -g "$fixture_gid" -m 0750 "$HOST_ROOT/opt/traffic-generator"
  sudo -n install -d -o root -g root -m 0755 "$HOST_ROOT/opt/traffic-generator/runtime"
  printf 'd /opt/traffic-generator/runtime/continuous 0700 root root -\n' | sudo -n tee "$HOST_ROOT/etc/old-tmpfiles.conf" >/dev/null
  set +e
  # The caller owns TMP; only the tmpfiles process needs privilege.
  # shellcheck disable=SC2024
  sudo -n systemd-tmpfiles --root="$HOST_ROOT" --create "$HOST_ROOT/etc/old-tmpfiles.conf" >"$TMP/old-tmpfiles.log" 2>&1
  old_rc=$?
  set -e
  test "$old_rc" -ne 0
  grep -Eiq 'unsafe.*(path|transition)' "$TMP/old-tmpfiles.log"
  printf '[RED reproduced] old hierarchy rejected (exit=%s)\n' "$old_rc"
  cat "$TMP/old-tmpfiles.log"
  # Extracted production code changes only fixture root paths and account IDs.
  sed -e "s#/opt/traffic-generator#$HOST_ROOT/opt/traffic-generator#g" \
    -e "s/-o tgen -g tgen/-o $fixture_uid -g $fixture_gid/g" \
    "$TMP/runtime-directories-function" >"$TMP/host-runtime-setup"
  printf '\nsetup_runtime_directories\n' >>"$TMP/host-runtime-setup"
  sudo -n bash "$TMP/host-runtime-setup"
  # Tmpfiles resolves absolute production paths beneath --root and tgen via fixture NSS.
  # The caller reads its rendered config; tee alone writes the root fixture.
  # shellcheck disable=SC2024
  sudo -n tee "$HOST_ROOT/etc/tmpfiles.conf" <"$TMP/tmpfiles.conf" >/dev/null
  sudo -n systemd-tmpfiles --root="$HOST_ROOT" --create "$HOST_ROOT/etc/tmpfiles.conf"
  test "$(stat -c '%u:%g:%a' "$HOST_ROOT/run/lock")" = 0:0:1777
  sudo -n systemd-tmpfiles --root="$HOST_ROOT" --create "$HOST_ROOT/etc/tmpfiles.conf"
  test "$(stat -c '%u:%g:%a' "$HOST_ROOT/run/lock")" = 0:0:1777
  root_parent="$HOST_ROOT/opt/traffic-generator"
  continuous="$root_parent/runtime/continuous"
  printf 'frozen-upload-state\n' | sudo -n tee "$continuous/sentinel" >/dev/null
  sudo -n chmod 0600 "$continuous/sentinel"
  sentinel_digest=$(sudo -n sha256sum "$continuous/sentinel" | cut -d' ' -f1)
  sed -e "s#/opt/traffic-generator#$HOST_ROOT/opt/traffic-generator#g" "$TMP/status-functions" >"$TMP/host-status-functions"
  printf '\nstatus_file=%q\nstage=host-fixture\nwrite_status ready\n' "$root_parent/status.json" >>"$TMP/host-status-functions"
  sudo -n bash "$TMP/host-status-functions"
  assert_host_permissions() {
    for parent in "$HOST_ROOT" "$HOST_ROOT/opt" "$root_parent" "$root_parent/runtime" "$HOST_ROOT/run"; do
      test "$(stat -c '%u:%g:%a' "$parent")" = 0:0:755
      sudo -n -u "$fixture_user" test -x "$parent"
      if sudo -n -u "$fixture_user" test -w "$parent"; then exit 1; fi
    done
    test "$(sudo -n stat -c '%u:%g:%a' "$continuous")" = 0:0:700
    test "$(stat -c '%u:%g:%a' "$root_parent/status.json")" = 0:0:644
    sudo -n -u "$fixture_user" test -r "$root_parent/status.json"
    if sudo -n -u "$fixture_user" test -w "$root_parent/status.json"; then exit 1; fi
    for child in runtime/results runtime/npm browser-profile .cache .config .npm; do
      test "$(stat -c '%u:%g:%a' "$root_parent/$child")" = "$fixture_uid:$fixture_gid:750"
      sudo -n -u "$fixture_user" test -w "$root_parent/$child"
    done
    test "$(stat -c '%u:%g:%a' "$HOST_ROOT/run/lock/csd-traffic-generator.lock")" = "0:$fixture_gid:660"
    test "$(stat -c '%u:%g:%a' "$HOST_ROOT/run/lock")" = 0:0:1777
    sudo -n -u "$fixture_user" test -w "$HOST_ROOT/run/lock"
    sudo -n -u "$fixture_user" node - "$HOST_ROOT/run/lock" <<'NODE'
const fs = require('fs');
const dir = process.argv[2];
const own = dir + '/fixture-user.lock';
const protectedLock = dir + '/csd-traffic-generator.lock';
const inode = fs.statSync(protectedLock).ino;
fs.writeFileSync(own, 'user-owned lock', { flag: 'wx' });
for (const operation of [() => fs.unlinkSync(protectedLock), () => fs.renameSync(own, protectedLock)]) {
  let denied = false;
  try { operation(); } catch (error) {
    if (!['EPERM', 'EACCES'].includes(error.code)) throw error;
    denied = true;
  }
  if (!denied) throw new Error('sticky directory allowed root-owned lock replacement');
}
if (fs.statSync(protectedLock).ino !== inode) throw new Error('root-owned lock inode changed');
fs.unlinkSync(own);
NODE
    test "$(sudo -n stat -c '%u:%g:%a' "$continuous/sentinel")" = 0:0:600
    test "$(sudo -n sha256sum "$continuous/sentinel" | cut -d' ' -f1)" = "$sentinel_digest"
  }
  assert_host_permissions
  printf '[GREEN] fresh tmpfiles twice preserves root-owned run/lock 1777 and sticky lock protection\n'
  # Real offline npm package: ignore-scripts must suppress this failing hook.
  sudo -n -u "$fixture_user" mkdir "$root_parent/runtime/npm/package-fixture"
  printf '{"name":"bootstrap-offline-fixture","version":"1.0.0","main":"index.js","scripts":{"install":"exit 97"}}\n' | sudo -n -u "$fixture_user" tee "$root_parent/runtime/npm/package-fixture/package.json" >/dev/null
  printf 'module.exports = "offline-ok";\n' | sudo -n -u "$fixture_user" tee "$root_parent/runtime/npm/package-fixture/index.js" >/dev/null
  host_node=$(command -v node)
  host_npm=$(command -v npm)
  host_path="$(dirname "$host_node"):/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  sudo -n -u "$fixture_user" env PATH="$host_path" HOME="$root_parent/browser-profile" npm_config_cache="$root_parent/browser-profile/.npm" \
    "$host_npm" --prefix "$root_parent/runtime/npm/package-fixture" pack "$root_parent/runtime/npm/package-fixture" --ignore-scripts --pack-destination "$root_parent/runtime/npm" >/dev/null
  sudo -n -u "$fixture_user" env PATH="$host_path" HOME="$root_parent/browser-profile" npm_config_cache="$root_parent/browser-profile/.npm" \
    "$host_npm" --prefix "$root_parent/runtime/npm" install --offline --ignore-scripts --omit=dev --save-exact --no-audit --no-fund "$root_parent/runtime/npm/bootstrap-offline-fixture-1.0.0.tgz"
  # Match root promotion of tgen-owned child while retaining stable NODE_PATH.
  sudo -n mv "$root_parent/runtime/npm/node_modules" "$root_parent/node_modules"
  test "$(stat -c '%u:%g' "$root_parent/node_modules")" = "$fixture_uid:$fixture_gid"
  sudo -n -u "$fixture_user" env HOME="$root_parent/browser-profile" NODE_PATH="$root_parent/node_modules" \
    "$host_node" -e 'if (require("bootstrap-offline-fixture") !== "offline-ok") process.exit(1); require("fs").writeFileSync(process.env.HOME + "/probe", "writable");'
  sudo -n -u "$fixture_user" env HOME="$root_parent" "$host_node" -e 'for (const p of [".cache", ".config", ".npm"]) require("fs").writeFileSync(process.env.HOME + "/" + p + "/probe", "writable");'
  for iteration in 1 2; do
    sudo -n rm -rf -- "$HOST_ROOT/run/lock"
    # Reboot recreates the distribution-owned sticky lock directory, not application config.
    sudo -n install -d -o root -g root -m 1777 "$HOST_ROOT/run/lock"
    sudo -n bash "$TMP/host-runtime-setup"
    sudo -n systemd-tmpfiles --root="$HOST_ROOT" --create "$HOST_ROOT/etc/tmpfiles.conf"
    test "$(stat -c '%u:%g:%a' "$HOST_ROOT/run/lock")" = 0:0:1777
    sudo -n systemd-tmpfiles --root="$HOST_ROOT" --create "$HOST_ROOT/etc/tmpfiles.conf"
    assert_host_permissions
    sudo -n -u "$fixture_user" test -r "$root_parent/browser-profile/probe"
    sudo -n -u "$fixture_user" env NODE_PATH="$root_parent/node_modules" "$host_node" -e 'if (require("bootstrap-offline-fixture") !== "offline-ok") process.exit(1)'
    printf '[GREEN] reboot/rerun %s preserves run/lock 1777, sticky lock protection, ownership, modes, status, npm and continuous digest\n' "$iteration"
  done
  printf '[OK] real systemd-tmpfiles unsafe-path regression and offline unprivileged npm integration\n'
fi
printf '[OK] rendered bootstrap syntax, Chrome permission normalization, inherited ERR status transition, SSH activation, ordering, and URI rewrites\n'
