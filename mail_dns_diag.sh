#!/usr/bin/env bash
#
# mail_dns_diag.sh - Smart Mail DNS Diagnostic
# --------------------------------------------
# Checks all essential DNS records for a mail domain.
# Usage: ./mail_dns_diag.sh domain.com [dkim_selector]
#

set -euo pipefail

VERSION="1.0.0"
HOSTNAME="$(hostname)"
START_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# Colors for clarity
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Friendly intro
echo -e "${CYAN}Hello! This is mail_dns_diag.sh v$VERSION"
echo -e "Running on host: ${HOSTNAME}"
echo -e "Start time: $START_TIME"
echo -e "Let's check your mail DNS records!${NC}\n"

if [[ $# -lt 1 ]]; then
  echo -e "${YELLOW}Usage:${NC} $0 domain.com [dkim_selector]"
  exit 1
fi

DOMAIN="$1"
DKIM_SELECTOR="${2:-}"

section() {
  echo -e "\n${GREEN}== $1 ==${NC}"
}

missing() {
  echo -e "${RED}Not found!${NC}"
}

# MX Records
section "MX Records"
if ! dig +short MX "$DOMAIN" | grep -q .; then
  missing
else
  dig +short MX "$DOMAIN"
fi

# SPF Record
section "SPF Record"
if ! dig +short TXT "$DOMAIN" | grep -i 'v=spf1' | grep -q .; then
  missing
else
  dig +short TXT "$DOMAIN" | grep -i 'v=spf1'
fi

# DMARC Record
section "DMARC Record"
if ! dig +short TXT "_dmarc.$DOMAIN" | grep -i 'v=DMARC1' | grep -q .; then
  missing
else
  dig +short TXT "_dmarc.$DOMAIN" | grep -i 'v=DMARC1'
fi

# MTA-STS Record
section "MTA-STS Record"
if ! dig +short TXT "_mta-sts.$DOMAIN" | grep -q .; then
  missing
else
  dig +short TXT "_mta-sts.$DOMAIN"
fi

# TLS-RPT Record
section "TLS-RPT Record"
if ! dig +short TXT "_smtp._tls.$DOMAIN" | grep -q .; then
  missing
else
  dig +short TXT "_smtp._tls.$DOMAIN"
fi

# DKIM Record
section "DKIM Record"
if [[ -n "$DKIM_SELECTOR" ]]; then
  DKIM_DOMAIN="$DKIM_SELECTOR._domainkey.$DOMAIN"
  if ! dig +short TXT "$DKIM_DOMAIN" | grep -q .; then
    echo -e "${YELLOW}Selector '${DKIM_SELECTOR}' not found!${NC}"
  else
    dig +short TXT "$DKIM_DOMAIN"
  fi
else
  echo -e "${YELLOW}No DKIM selector provided. Skipping DKIM check.${NC}"
fi

# DANE/TLSA Record (for mail.$DOMAIN, port 25)
section "DANE/TLSA Record (_25._tcp.mail.$DOMAIN)"
if ! dig +short TLSA "_25._tcp.mail.$DOMAIN" | grep -q .; then
  missing
else
  dig +short TLSA "_25._tcp.mail.$DOMAIN"
fi

# DNSSEC Status
section "DNSSEC Status"
if dig +dnssec +short SOA "$DOMAIN" | grep -q "RRSIG"; then
  echo -e "${GREEN}DNSSEC: Present${NC}"
else
  echo -e "${RED}DNSSEC: Not present${NC}"
fi

# Name Servers
section "Name Servers"
if ! dig +short NS "$DOMAIN" | grep -q .; then
  missing
else
  dig +short NS "$DOMAIN"
fi

# IPv6 Support
section "IPv6 (AAAA) for MX Hosts"
MX_HOSTS=$(dig +short MX "$DOMAIN" | awk '{print $2}' | sed 's/\.$//')
if [[ -z "$MX_HOSTS" ]]; then
  echo -e "${YELLOW}No MX records to check for IPv6.${NC}"
else
  for mx in $MX_HOSTS; do
    AAAA=$(dig +short AAAA "$mx")
    if [[ -n "$AAAA" ]]; then
      echo -e "$mx: ${GREEN}$AAAA${NC}"
    else
      echo -e "$mx: ${RED}No AAAA record${NC}"
    fi
  done
fi

# Reverse DNS for MX hosts
section "Reverse DNS for MX Hosts"
if [[ -z "$MX_HOSTS" ]]; then
  echo -e "${YELLOW}No MX records to check for PTR.${NC}"
else
  for mx in $MX_HOSTS; do
    IP=$(dig +short "$mx" | head -n1)
    if [[ -n "$IP" ]]; then
      PTR=$(dig +short -x "$IP")
      if [[ -n "$PTR" ]]; then
        echo -e "$mx ($IP): ${GREEN}$PTR${NC}"
      else
        echo -e "$mx ($IP): ${RED}No PTR record${NC}"
      fi
    else
      echo -e "$mx: ${RED}No A record found${NC}"
    fi
  done
fi

END_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo -e "\n${CYAN}All done! mail_dns_diag.sh v$VERSION signing off on host $HOSTNAME."
echo -e "Start: $START_TIME | End: $END_TIME"
echo -e "Goodbye!${NC}"
