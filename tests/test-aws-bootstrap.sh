#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
AWS_ROOT="${REPO_ROOT}/terraform/aws"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

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
    cloudwatch_agent_version = "1.300000.0b1"
    cloudwatch_agent_package_url = "https://example.invalid/amazon-cloudwatch-agent.deb"
    cloudwatch_agent_package_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    node_archive_url = "https://example.invalid/node.tar.xz"
    node_archive_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    chrome_archive_url = "https://example.invalid/chrome.zip"
    chrome_archive_sha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    playwright_core_version = "1.55.0"
    deployment_manifest_version = "1.0.0"
    deployment_manifest_sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
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
grep -Fq 'jq -r .version node_modules/playwright-core/package.json' "$TMP/csd-bootstrap"
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
failing_helper() { false; }
write_status provisioning
failing_helper
EOF
chmod +x "$TMP/failing-helper-regression"
if "$TMP/failing-helper-regression"; then exit 1; fi
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
extract_file /etc/logrotate.d/csd-traffic-generator "$TMP/cloud-init.yaml" >"$TMP/logrotate.conf"
for setting in daily 'size 10M' 'rotate 7' compress delaycompress copytruncate; do
  grep -Fxq "  $setting" "$TMP/logrotate.conf"
done
grep -Fq 'test -f "$1/suites/csd-violations/continuous.mjs"' "$TMP/csd-bootstrap"
grep -Fq '/opt/node/bin/node --check "$dst/suites/csd-violations/continuous.mjs"' "$TMP/csd-bootstrap"
awk '/^valid\(\) \{$/ { body=1 } body { print } body && /^\}$/ { exit }' "$TMP/csd-bootstrap" >"$TMP/source-valid-function"
(
  source "$TMP/source-valid-function"
  fixture="$TMP/source-fixture"
  manifest=suites/csd-violations/scenarios.mjs
  mkdir -p "$fixture/suites/csd-violations"
  printf 'export const fixture = true;\n' >"$fixture/$manifest"
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
)
stop_line=$(grep -nFx 'systemctl disable --now csd-continuous.timer csd-continuous.service' "$TMP/csd-bootstrap" | head -n1 | cut -d: -f1)
source_line=$(grep -nFx 'stage=source' "$TMP/csd-bootstrap" | cut -d: -f1)
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
printf '[OK] rendered bootstrap syntax, Chrome permission normalization, inherited ERR status transition, SSH activation, ordering, and URI rewrites\n'
