#!/usr/bin/env bash
#
# mail_dns_diag.sh - Smart Mail DNS Diagnostic
#
# Usage:
#   ./mail_dns_diag.sh [options] domain.com
#
# Options:
#   -s, --selector <selector>   DKIM selector (e.g., 'default', 'mail', etc.)
#   -l, --local                 Use local resolver instead of public (1.1.1.1)
#   -j, --json                  Output results as JSON
#   --no-color                  Disable color output
#   -h, --help                  Show help and exit
#   -v, --version               Show version and exit
#
# Example:
#   ./mail_dns_diag.sh -s mailcow example.com
#
# Author: Paul
# Version: 3.1.0
# License: MIT
#

set -euo pipefail

VERSION="3.1.0"
PUBLIC_RESOLVER="1.1.1.1"
DEFAULT_TIMEOUT=3

# --- Color Output Setup ---
COLOR_ENABLED=1
if [[ ! -t 1 || "${TERM:-}" == "dumb" ]]; then
  COLOR_ENABLED=0
fi

# Allow --no-color to override
for arg in "$@"; do
  if [[ "$arg" == "--no-color" ]]; then
    COLOR_ENABLED=0
    break
  fi
done

if [[ $COLOR_ENABLED -eq 1 ]]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  CYAN='\033[0;36m'
  NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

# --- Globals ---
MODE="public"
JSON_MODE=0
DKIM_SELECTOR=""
DOMAIN=""
declare -A summary
declare -A tips
declare -A details

# --- Utility Functions ---

usage() {
  printf "%b\n" "${CYAN}mail_dns_diag.sh v$VERSION - Smart Mail DNS Diagnostic${NC}

Usage:
  $0 [options] domain.com

Options:
  -s, --selector <selector>   DKIM selector (e.g., 'default', 'mail', etc.)
  -l, --local                 Use local resolver instead of public (1.1.1.1)
  -j, --json                  Output results as JSON
  --no-color                  Disable color output
  -h, --help                  Show help and exit
  -v, --version               Show version and exit

Example:
  $0 -s mailcow example.com

Checks:
  MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, DANE/TLSA, DNSSEC, NS, IPv6, PTR

"
}

print_version() {
  echo "mail_dns_diag.sh v$VERSION"
}

color_echo() {
  local color="$1"; shift
  local color_code=""
  if [[ -n "$color" ]]; then
    color_code="${!color}"
  fi
  if [[ $JSON_MODE -eq 0 && $COLOR_ENABLED -eq 1 ]]; then
    printf "%b\n" "${color_code}$*${NC}"
  elif [[ $JSON_MODE -eq 0 ]]; then
    printf "%s\n" "$*"
  fi
}

section() {
  color_echo GREEN "\n== $1 =="
}

missing() {
  color_echo RED "Not found!"
}

tip() {
  local key="$1"
  shift
  tips["$key"]+="${tips[$key]:+;;}$*"
  color_echo YELLOW "Tip: $*"
}

require_tools() {
  for tool in dig awk grep sed head tr date; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      color_echo RED "Required tool '$tool' not found. Please install it."
      exit 1
    fi
  done
}

# Escape for JSON string
json_escape() {
  sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g; s/\n/\\n/g'
}

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    -s|--selector)
      DKIM_SELECTOR="$2"
      shift 2
      ;;
    -l|--local)
      MODE="local"
      shift
      ;;
    -j|--json)
      JSON_MODE=1
      shift
      ;;
    --no-color)
      COLOR_ENABLED=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -v|--version)
      print_version
      exit 0
      ;;
    -*)
      color_echo RED "Unknown option: $1"
      usage
      exit 1
      ;;
    *)
      if [[ -z "$DOMAIN" ]]; then
        DOMAIN="$1"
      else
        color_echo RED "Unexpected argument: $1"
        usage
        exit 1
      fi
      shift
      ;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
  usage
  exit 1
fi

require_tools

# --- Domain Validation and Normalization ---
normalize_domain() {
  local domain="$1"
  # If user gives mail.example.com, suggest example.com
  if [[ "$domain" =~ ^mail\.([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$ ]]; then
    local basedomain="${BASH_REMATCH[1]}"
    color_echo YELLOW "It looks like you entered a mail host: $domain"
    color_echo YELLOW "For mail DNS checks, you probably want the base domain: $basedomain"
    tip "DOMAIN" "Try: $0 $basedomain"
    exit 1
  fi
  # Basic domain validation
  if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    color_echo RED "Invalid domain: $domain"
    exit 1
  fi
}
normalize_domain "$DOMAIN"

# --- Resolver Setup ---
if [[ "$MODE" == "public" ]]; then
  RESOLVER="@${PUBLIC_RESOLVER}"
  color_echo CYAN "Using public resolver: $PUBLIC_RESOLVER"
else
  RESOLVER=""
  color_echo CYAN "Using local system resolver"
fi

HOSTNAME="$(hostname)"
START_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
START_EPOCH="$(date -u +%s)"

# --- DNS Check Functions ---

check_mx() {
  section "MX Records"
  local mx_output
  mx_output=$(dig $RESOLVER +timeout=$DEFAULT_TIMEOUT +short MX "$DOMAIN" || true)
  details[MX]="$mx_output"
  if [[ -z "$mx_output" ]]; then
    missing
    tip "MX" "No MX records found. Your domain cannot receive email."
    summary[MX]="FAIL"
    return 1
  else
    color_echo "" "$mx_output"
    tip "MX" "Ensure MX hostnames have A/AAAA records and are reachable."
    summary[MX]="PASS"
    MX_OUTPUT="$mx_output"
  fi
}

check_spf() {
  section "SPF Record"
  local spf_output
  spf_output=$(dig $RESOLVER +timeout=$DEFAULT_TIMEOUT +short TXT "$DOMAIN" | grep -i 'v=spf1' || true)
  details[SPF]="$spf_output"
  if [[ -z "$spf_output" ]]; then
    missing
    tip "SPF" "No SPF record found. Add a TXT record like: 'v=spf1 ... ~all'"
    summary[SPF]="FAIL"
  else
    color_echo "" "$spf_output"
    summary[SPF]="PASS"
    if echo "$spf_output" | grep -q '\-all'; then
      tip "SPF" "SPF ends with '-all' (hard fail). Strict, blocks all not listed."
    elif echo "$spf_output" | grep -q '~all'; then
      tip "SPF" "SPF ends with '~all' (soft fail). More permissive."
    fi
    if echo "$spf_output" | grep -q 'include:'; then
      tip "SPF" "SPF uses 'include:'. Ensure included domains are valid."
    fi
    tip "SPF" "Test SPF with mxtoolbox.com/spf.aspx or dmarcian.com/spf-survey/"
  fi
}

check_dmarc() {
  section "DMARC Record"
  local dmarc_output
  dmarc_output=$(dig $RESOLVER +timeout=$DEFAULT_TIMEOUT +short TXT "_dmarc.$DOMAIN" | grep -i 'v=DMARC1' || true)
  details[DMARC]="$dmarc_output"
  if [[ -z "$dmarc_output" ]]; then
    missing
    tip "DMARC" "No DMARC record found. Add a TXT record at _dmarc.$DOMAIN."
    summary[DMARC]="FAIL"
  else
    color_echo "" "$dmarc_output"
    summary[DMARC]="PASS"
    if echo "$dmarc_output" | grep -qi 'p=none'; then
      tip "DMARC" "DMARC policy is 'none'. Only monitors, does not enforce."
    elif echo "$dmarc_output" | grep -qi 'p=quarantine'; then
      tip "DMARC" "DMARC policy is 'quarantine'. Failing mail may go to spam."
    elif echo "$dmarc_output" | grep -qi 'p=reject'; then
      tip "DMARC" "DMARC policy is 'reject'. Strictest, blocks spoofed mail."
    fi
    if echo "$dmarc_output" | grep -qi 'rua='; then
      tip "DMARC" "Aggregate reports (rua) enabled. Monitor the mailbox."
    fi
    if echo "$dmarc_output" | grep -qi 'ruf='; then
      tip "DMARC" "Forensic reports (ruf) enabled. May contain sensitive data."
    fi
    tip "DMARC" "Test DMARC with dmarcian.com/dmarc-inspector/"
  fi
}

check_mta_sts() {
  section "MTA-STS Record"
  local mtasts_output
  mtasts_output=$(dig $RESOLVER +timeout=$DEFAULT_TIMEOUT +short TXT "_mta-sts.$DOMAIN" | grep -o 'v=STSv1;.*' || true)
  details[MTA-STS]="$mtasts_output"
  if [[ -z "$mtasts_output" ]]; then
    missing
    tip "MTA-STS" "No MTA-STS record found. Add TXT at _mta-sts.$DOMAIN."
    summary[MTA-STS]="FAIL"
  else
    color_echo "" "$mtasts_output"
    summary[MTA-STS]="PASS"
    tip "MTA-STS" "Serve policy at https://mta-sts.$DOMAIN/.well-known/mta-sts.txt"
    tip "MTA-STS" "Test with https://mta-sts.mailhardener.com/"
  fi
}

check_tlsrpt() {
  section "TLS-RPT Record"
  local tlsrpt_output
  tlsrpt_output=$(dig $RESOLVER +timeout=$DEFAULT_TIMEOUT +short TXT "_smtp._tls.$DOMAIN" | grep -o 'v=TLSRPTv1;.*' || true)
  details[TLS-RPT]="$tlsrpt_output"
  if [[ -z "$tlsrpt_output" ]]; then
    missing
    tip "TLS-RPT" "No TLS-RPT record found. Add TXT at _smtp._tls.$DOMAIN."
    summary[TLS-RPT]="FAIL"
  else
    color_echo "" "$tlsrpt_output"
    summary[TLS-RPT]="PASS"
    tip "TLS-RPT" "TLS-RPT record found. Monitor the reporting address."
  fi
}

check_dkim() {
  section "DKIM Record"
  if [[ -n "$DKIM_SELECTOR" ]]; then
    local dkim_domain dkim_output
    dkim_domain="$DKIM_SELECTOR._domainkey.$DOMAIN"
    dkim_output=$(dig $RESOLVER +timeout=$DEFAULT_TIMEOUT +short TXT "$dkim_domain" | tr -d '"' | tr -d '\n')
    details[DKIM]="$dkim_output"
    if [[ -z "$dkim_output" ]]; then
      color_echo RED "No DKIM record found for selector '${DKIM_SELECTOR}'!"
      tip "DKIM" "Check your mail server's DKIM settings and DNS."
      summary[DKIM]="FAIL"
    else
      color_echo "" "$dkim_output"
      summary[DKIM]="PASS"
      if echo "$dkim_output" | grep -q 'v=DKIM1'; then
        tip "DKIM" "DKIM record found. Ensure your server signs with this selector."
      else
        tip "DKIM" "DKIM record may be malformed. Should start with 'v=DKIM1;'."
      fi
    fi
  else
    color_echo YELLOW "No DKIM selector provided. Skipping DKIM check."
    tip "DKIM" "Provide a selector with -s to check DKIM."
    summary[DKIM]="SKIP"
  fi
}

check_dane() {
  section "DANE/TLSA Record (_25._tcp.mail.$DOMAIN)"
  local tlsa_output
  tlsa_output=$(dig $RESOLVER +timeout=$DEFAULT_TIMEOUT +short TLSA "_25._tcp.mail.$DOMAIN" || true)
  details[DANE]="$tlsa_output"
  if [[ -z "$tlsa_output" ]]; then
    missing
    tip "DANE" "No DANE/TLSA record found. DANE requires DNSSEC."
    summary[DANE]="FAIL"
  else
    color_echo "" "$tlsa_output"
    summary[DANE]="PASS"
    tip "DANE" "Ensure your mail server's TLS cert matches the TLSA record."
  fi
}

check_dnssec() {
  section "DNSSEC Status"
  local dnssec_output
  dnssec_output="$(dig $RESOLVER +timeout=$DEFAULT_TIMEOUT +dnssec SOA "$DOMAIN")"
  details[DNSSEC]="$dnssec_output"
  if echo "$dnssec_output" | grep -q "RRSIG"; then
    color_echo GREEN "DNSSEC: Present"
    tip "DNSSEC" "DNSSEC is enabled. Protects from DNS spoofing."
    summary[DNSSEC]="PASS"
  else
    color_echo RED "DNSSEC: Not present"
    tip "DNSSEC" "Consider enabling DNSSEC at your DNS provider."
    summary[DNSSEC]="FAIL"
  fi
}

check_ns() {
  section "Name Servers"
  local ns_output
  ns_output=$(dig $RESOLVER +timeout=$DEFAULT_TIMEOUT +short NS "$DOMAIN" || true)
  details[NS]="$ns_output"
  if [[ -z "$ns_output" ]]; then
    missing
    tip "NS" "No NS records found. Set authoritative name servers."
    summary[NS]="FAIL"
  else
    color_echo "" "$ns_output"
    tip "NS" "Use at least two geographically separated name servers."
    summary[NS]="PASS"
  fi
}

check_ipv6_mx() {
  section "IPv6 (AAAA) for MX Hosts"
  if [[ -z "${MX_OUTPUT:-}" ]]; then
    color_echo YELLOW "No MX records to check for IPv6."
    summary[IPv6]="SKIP"
    return
  fi
  local mx_hosts found=0
  mx_hosts=$(echo "$MX_OUTPUT" | awk '{print $2}' | sed 's/\.$//')
  local ipv6_details=""
  for mx in $mx_hosts; do
    local aaaa
    aaaa=$(dig $RESOLVER +timeout=$DEFAULT_TIMEOUT +short AAAA "$mx")
    if [[ -n "$aaaa" ]]; then
      color_echo "" "$mx: ${GREEN}$aaaa${NC}"
      tip "IPv6" "MX host $mx supports IPv6."
      ipv6_details+="$mx: $aaaa"$'\n'
      found=1
    else
      color_echo "" "$mx: ${YELLOW}No AAAA record (IPv4-only)${NC}"
      tip "IPv6" "Add AAAA record for $mx for IPv6 support if desired."
      ipv6_details+="$mx: No AAAA record"$'\n'
    fi
  done
  details[IPv6]="$ipv6_details"
  summary[IPv6]=$([[ $found -eq 1 ]] && echo "PASS" || echo "FAIL")
}

check_ptr_mx() {
  section "Reverse DNS for MX Hosts"
  if [[ -z "${MX_OUTPUT:-}" ]]; then
    color_echo YELLOW "No MX records to check for PTR."
    summary[PTR]="SKIP"
    return
  fi
  local mx_hosts found=0
  mx_hosts=$(echo "$MX_OUTPUT" | awk '{print $2}' | sed 's/\.$//')
  local ptr_details=""
  for mx in $mx_hosts; do
    local ip ptr
    ip=$(dig $RESOLVER +timeout=$DEFAULT_TIMEOUT +short "$mx" | head -n1)
    if [[ -n "$ip" ]]; then
      ptr=$(dig $RESOLVER +timeout=$DEFAULT_TIMEOUT +short -x "$ip")
      if [[ -n "$ptr" ]]; then
        color_echo "" "$mx ($ip): ${GREEN}$ptr${NC}"
        tip "PTR" "PTR record found for $mx ($ip)."
        ptr_details+="$mx ($ip): $ptr"$'\n'
        found=1
      else
        color_echo "" "$mx ($ip): ${RED}No PTR record${NC}"
        tip "PTR" "Set PTR at your IP provider for $mx ($ip)."
        ptr_details+="$mx ($ip): No PTR record"$'\n'
      fi
    else
      color_echo "" "$mx: ${RED}No A record found${NC}"
      tip "PTR" "MX hostname $mx must resolve to an IP address."
      ptr_details+="$mx: No A record found"$'\n'
    fi
  done
  details[PTR]="$ptr_details"
  summary[PTR]=$([[ $found -eq 1 ]] && echo "PASS" || echo "FAIL")
}

# --- JSON Output Function ---
print_json() {
  local elapsed=$1
  echo '{'
  echo "  \"domain\": \"$(echo "$DOMAIN" | json_escape)\","
  echo "  \"host\": \"$(echo "$HOSTNAME" | json_escape)\","
  echo "  \"start\": \"$(echo "$START_TIME" | json_escape)\","
  echo "  \"end\": \"$(echo "$END_TIME" | json_escape)\","
  echo "  \"elapsed\": $elapsed,"
  echo "  \"checks\": {"
  local first=1
  for key in MX SPF DMARC DKIM MTA-STS TLS-RPT DANE DNSSEC NS IPv6 PTR; do
    [[ $first -eq 0 ]] && echo ','
    first=0
    printf "    \"%s\": {\n" "$key"
    printf "      \"result\": \"%s\"" "${summary[$key]:-SKIP}"
    # Print details if present
    if [[ -n "${details[$key]:-}" ]]; then
      printf ",\n      \"details\": \"%s\"" "$(echo "${details[$key]}" | tr -d '\r' | tr '\n' ' ' | json_escape)"
    fi
    # Print tips as array
    if [[ -n "${tips[$key]:-}" ]]; then
      printf ",\n      \"tips\": ["
      IFS=';;' read -ra tiparr <<< "${tips[$key]}"
      for i in "${!tiparr[@]}"; do
        [[ $i -gt 0 ]] && printf ', '
        printf "\"%s\"" "$(echo "${tiparr[$i]}" | json_escape)"
      done
      printf "]"
    fi
    printf "\n    }"
  done
  echo
  echo "  }"
  echo '}'
}

# --- Main Execution ---

if [[ $JSON_MODE -eq 0 ]]; then
  color_echo CYAN "------------------------------------------------------------"
  color_echo CYAN "  mail_dns_diag.sh v$VERSION - Smart Mail DNS Diagnostic"
  color_echo CYAN "------------------------------------------------------------"
  echo "Host: $HOSTNAME"
  echo "Start time: $START_TIME"
  echo "Mode: $MODE"
  echo "Domain: $DOMAIN"
  if [[ -n "$DKIM_SELECTOR" ]]; then
    echo "DKIM selector: $DKIM_SELECTOR"
  else
    echo "DKIM selector: (not provided)"
  fi
  color_echo CYAN "------------------------------------------------------------"
fi

# Run checks
check_mx
check_spf
check_dmarc
check_mta_sts
check_tlsrpt
check_dkim
check_dane
check_dnssec
check_ns
check_ipv6_mx
check_ptr_mx

END_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
END_EPOCH="$(date -u +%s)"
ELAPSED=$((END_EPOCH - START_EPOCH))

if [[ $JSON_MODE -eq 1 ]]; then
  print_json "$ELAPSED"
else
  # --- Summary Table ---
  color_echo CYAN "\nSummary:"
  printf "%-10s : %s\n" "Check" "Result"
  printf "%-10s : %s\n" "-----" "------"
  for key in MX SPF DMARC DKIM MTA-STS TLS-RPT DANE DNSSEC NS IPv6 PTR; do
    printf "%-10s : %s\n" "$key" "${summary[$key]:-SKIP}"
  done

  color_echo CYAN "\nAll done! mail_dns_diag.sh v$VERSION signing off on host $HOSTNAME."
  echo "Start: $START_TIME | End: $END_TIME | Elapsed: ${ELAPSED}s"
  color_echo CYAN "Goodbye!"
fi

# Exit non-zero if any check failed
for key in "${!summary[@]}"; do
  [[ "${summary[$key]}" == "FAIL" ]] && exit 1
done
exit 0