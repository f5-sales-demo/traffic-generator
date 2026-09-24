#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
AWS_ROOT="${REPO_ROOT}/terraform/aws"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat >"$TMP/main.tf" <<EOF
locals {
  rendered = templatefile("${AWS_ROOT}/cloud-init.tftpl", {
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
    target_url = "https://example.invalid"
  })
}
output "rendered" { value = local.rendered }
EOF

terraform -chdir="$TMP" init -backend=false -input=false >/dev/null
terraform -chdir="$TMP" apply -auto-approve -input=false >/dev/null
terraform -chdir="$TMP" output -raw rendered >"$TMP/cloud-init.yaml"

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
"$TMP/chrome-permissions-regression"

awk '
  /^normalize_aws_cli_permissions\(\) \{$/ { body=1 }
  body { print }
  body && /^\}$/ { exit }
' "$TMP/csd-bootstrap" >"$TMP/aws-cli-permissions-function"
grep -Fqx '  find -P "$aws_cli_root" -type d -exec chown "$owner:$group" {} + -exec chmod 0750 {} +' "$TMP/aws-cli-permissions-function"
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
"$TMP/aws-cli-permissions-regression"

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
printf '[OK] rendered bootstrap syntax, Chrome permission normalization, inherited ERR status transition, SSH activation, ordering, and URI rewrites\n'
