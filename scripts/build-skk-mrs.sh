#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: build-skk-mrs.sh <upstream Clash directory> <output directory> <mihomo binary>
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '%s\n' "$*"
}

trim() {
  local value=$1
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

has_rules() {
  local source_file=$1
  local raw_line line

  while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
    line=$(trim "${raw_line%$'\r'}")
    [[ -z "$line" || "$line" == \#* || "$line" == //* ]] && continue
    return 0
  done <"$source_file"

  return 1
}

run_convert() {
  local behavior=$1
  local source_file=$2
  local target_file=$3
  local convert_log
  convert_log="$work_dir/convert-$(basename "$target_file").log"

  if ! "$mihomo_bin" convert-ruleset "$behavior" text "$source_file" "$target_file" >"$convert_log" 2>&1; then
    cat "$convert_log" >&2
    die "Mihomo failed to convert $source_file"
  fi

  if grep -Eiq 'invalid (domain|ipcidr)|panic:' "$convert_log"; then
    cat "$convert_log" >&2
    die "Mihomo reported invalid entries in $source_file"
  fi

  [[ -s "$target_file" ]] || die "Mihomo produced an empty file for $source_file"
}

[[ $# -eq 3 ]] || {
  usage
  exit 2
}

upstream_clash_dir=$1
output_dir=$2
mihomo_bin=$3

[[ -d "$upstream_clash_dir/domainset" ]] || die "missing upstream domainset directory: $upstream_clash_dir/domainset"
[[ -d "$upstream_clash_dir/ip" ]] || die "missing upstream IP directory: $upstream_clash_dir/ip"
[[ -f "$mihomo_bin" && -x "$mihomo_bin" ]] || die "Mihomo binary is not executable: $mihomo_bin"

case "$output_dir" in
  '' | / | . | ..)
    die "refusing unsafe output directory: $output_dir"
    ;;
esac

work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT

stage_dir="$work_dir/output"
mkdir -p "$stage_dir/domainset" "$stage_dir/ip"

mapfile -d '' domain_files < <(
  find "$upstream_clash_dir/domainset" -maxdepth 1 -type f -name '*.txt' -print0 | sort -z
)
((${#domain_files[@]} > 0)) || die "no domainset files found"

domain_count=0
for source_file in "${domain_files[@]}"; do
  file_name=$(basename "$source_file")
  rule_name=${file_name%.txt}

  if ! has_rules "$source_file"; then
    [[ "$file_name" == 'reject_sukka.txt' ]] || die "unexpected empty domainset: $file_name"
    log "skipped domainset/$file_name (deprecated and empty)"
    continue
  fi

  run_convert domain "$source_file" "$stage_dir/domainset/$rule_name.mrs"
  domain_count=$((domain_count + 1))
  log "converted domainset/$file_name"
done

# Only these two upstream files use the optimized ipcidr text format. The
# remaining Clash/ip files are classical rule sets and cannot be stored in MRS.
ip_files=(
  "$upstream_clash_dir/ip/china_ip.txt"
  "$upstream_clash_dir/ip/china_ip_ipv6.txt"
)
ip_count=0
for source_file in "${ip_files[@]}"; do
  [[ -f "$source_file" ]] || die "missing upstream IP rule: $source_file"
  file_name=$(basename "$source_file")
  rule_name=${file_name%.txt}

  rule_count=0
  while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
    line=$(trim "${raw_line%$'\r'}")
    [[ -z "$line" || "$line" == \#* || "$line" == //* ]] && continue
    [[ "$line" == */* && "$line" != *,* ]] || die "unexpected non-CIDR entry in ip/$file_name: $line"
    rule_count=$((rule_count + 1))
  done <"$source_file"
  ((rule_count > 0)) || die "empty IP rule set: $file_name"

  run_convert ipcidr "$source_file" "$stage_dir/ip/$rule_name.mrs"
  ip_count=$((ip_count + 1))
  log "converted ip/$file_name"
done

((ip_count > 0)) || die "no compatible IP rules were converted"

mkdir -p "$(dirname "$output_dir")"
rm -rf -- "$output_dir"
mv -- "$stage_dir" "$output_dir"

log "done: $domain_count domainset files and $ip_count IP files"
