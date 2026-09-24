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
cloudwatch_line=$(grep -n '^stage=cloudwatch-config$' "$TMP/csd-bootstrap" | cut -d: -f1)
services_line=$(grep -n '^stage=services$' "$TMP/csd-bootstrap" | cut -d: -f1)
test "$services_line" -gt "$cloudwatch_line"

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
printf '[OK] rendered bootstrap syntax, inherited ERR status transition, ordering, and URI rewrites\n'
