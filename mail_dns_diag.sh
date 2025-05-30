#!/usr/bin/env bash
#
# mail_dns_diag.sh - Smart Mail DNS Diagnostic
# --------------------------------------------
# Checks all essential DNS records for a mail domain.
# Usage: ./mail_dns_diag.sh domain.com [dkim_selector] [--local]
#

set -euo pipefail

VERSION="1.3.0"
HOSTNAME="$(hostname)"
START_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
PUBLIC_RESOLVER="1.1.1.1"
LOCAL_RESOLVER=""

# Colors for clarity
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

usage() {
  echo -e "${YELLOW}Usage:${NC} $0 domain.com [dkim_selector] [--local]"
  echo -e "  domain.com      - The domain you want to check (required)"
  echo -e "  dkim_selector   - DKIM selector (optional, e.g., 'default', 'mail', 'mailcow')"
  echo -e "                    DKIM selectors are set in your mail server config and DNS."
  echo -e "                    If unsure, check your mail server or DNS for TXT records like:"
  echo -e "                    'selector._domainkey.domain.com'"
  echo -e "  --local         - Use your local system resolver instead of a public one"
  echo -e ""
  echo -e "${CYAN}Tip:${NC} If you don't know your DKIM selector, try leaving it blank or check your mail server's DKIM settings."
  echo -e "      Common selectors: 'default', 'mail', 'mailcow', or your server's hostname."
  echo -e ""
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

DOMAIN="$1"
DKIM_SELECTOR="${2:-}"
MODE="public"

if [[ "${3:-}" == "--local" ]]; then
  MODE="local"
fi

if [[ "$MODE" == "public" ]]; then
  RESOLVER="@${PUBLIC_RESOLVER}"
  echo -e "${CYAN}Using public resolver: $PUBLIC_RESOLVER (recommended for most checks)${NC}"
else
  RESOLVER="$LOCAL_RESOLVER"
  echo -e "${CYAN}Using local system resolver (your network's DNS)${NC}"
fi

# Friendly intro
echo -e "${CYAN}"
echo "------------------------------------------------------------"
echo "  mail_dns_diag.sh v$VERSION - Smart Mail DNS Diagnostic"
echo "------------------------------------------------------------"
echo "Host: $HOSTNAME"
echo "Start time: $START_TIME"
echo "Mode: $MODE"
echo "Domain: $DOMAIN"
if [[ -n "$DKIM_SELECTOR" ]]; then
  echo "DKIM selector: $DKIM_SELECTOR"
else
  echo "DKIM selector: (not provided)"
fi
echo "------------------------------------------------------------"
echo -e "${NC}"

section() {
  echo -e "\n${GREEN}== $1 ==${NC}"
}

missing() {
  echo -e "${RED}Not found!${NC}"
}

tip() {
  echo -e "${YELLOW}Tip:${NC} $1"
}

# MX Records
section "MX Records"
MX_OUTPUT=$(dig $RESOLVER +short MX "$DOMAIN")
if [[ -z "$MX_OUTPUT" ]]; then
  missing
  tip "No MX records found. Your domain cannot receive email. Add at least one MX record pointing to your mail server's FQDN. Example: '10 mail.example.com.'"
else
  echo "$MX_OUTPUT"
  tip "MX records define which servers receive email for your domain. Lower preference values have higher priority. Ensure your MX hostnames have corresponding A/AAAA records and are reachable from the public internet."
fi

# SPF Record
section "SPF Record"
SPF_OUTPUT=$(dig $RESOLVER +short TXT "$DOMAIN" | grep -i 'v=spf1' || true)
if [[ -z "$SPF_OUTPUT" ]]; then
  missing
  tip "No SPF record found. SPF helps prevent sender address forgery. Add a TXT record like: 'v=spf1 ip4:YOUR.MAIL.IP include:otherdomain.com ~all'. Use '~all' for softfail or '-all' for strict fail."
else
  echo "$SPF_OUTPUT"
  if echo "$SPF_OUTPUT" | grep -q '\-all'; then
    tip "Your SPF ends with '-all' (hard fail). This is strict and blocks all senders not listed. Make sure all legitimate sending IPs are included."
  elif echo "$SPF_OUTPUT" | grep -q '~all'; then
    tip "Your SPF ends with '~all' (soft fail). This is more permissive and may allow some spoofed mail. Consider '-all' for stricter enforcement if you are confident in your configuration."
  fi
  if echo "$SPF_OUTPUT" | grep -q 'include:'; then
    tip "Your SPF uses 'include:'. Ensure all included domains have valid SPF records and do not exceed the 10 DNS lookup limit."
  fi
  tip "Test your SPF with tools like 'mxtoolbox.com/spf.aspx' or 'dmarcian.com/spf-survey/'."
fi

# DMARC Record
section "DMARC Record"
DMARC_OUTPUT=$(dig $RESOLVER +short TXT "_dmarc.$DOMAIN" | grep -i 'v=DMARC1' || true)
if [[ -z "$DMARC_OUTPUT" ]]; then
  missing
  tip "No DMARC record found. DMARC helps protect your domain from spoofing and phishing. Add a TXT record at _dmarc.$DOMAIN with: 'v=DMARC1; p=quarantine; rua=mailto:you@yourdomain.com'. Use 'p=reject' for strict enforcement."
else
  echo "$DMARC_OUTPUT"
  if echo "$DMARC_OUTPUT" | grep -qi 'p=none'; then
    tip "Your DMARC policy is 'none'. This only monitors and does not enforce. Use 'quarantine' or 'reject' for stronger protection."
  elif echo "$DMARC_OUTPUT" | grep -qi 'p=quarantine'; then
    tip "Your DMARC policy is 'quarantine'. Messages failing DMARC may be sent to spam. Consider 'reject' for even stronger protection."
  elif echo "$DMARC_OUTPUT" | grep -qi 'p=reject'; then
    tip "Your DMARC policy is 'reject'. This is the strictest setting and will block spoofed mail. Monitor reports to ensure no legitimate mail is blocked."
  fi
  if echo "$DMARC_OUTPUT" | grep -qi 'rua='; then
    tip "Aggregate reports (rua) are enabled. Make sure the mailbox is monitored or use a DMARC analytics service."
  fi
  if echo "$DMARC_OUTPUT" | grep -qi 'ruf='; then
    tip "Forensic reports (ruf) are enabled. These may contain sensitive data. Only use if you need detailed failure reports."
  fi
  tip "Test your DMARC with 'dmarcian.com/dmarc-inspector/' or 'mxtoolbox.com/dmarc.aspx'."
fi

# MTA-STS Record
section "MTA-STS Record"
MTASTS_OUTPUT=$(dig $RESOLVER +short TXT "_mta-sts.$DOMAIN" || true)
if [[ -z "$MTASTS_OUTPUT" ]]; then
  missing
  tip "No MTA-STS record found. MTA-STS enforces TLS for SMTP delivery to your domain. Add a TXT record at _mta-sts.$DOMAIN with: 'v=STSv1; id=YYYYMMDD'. Also serve a policy file at https://mta-sts.$DOMAIN/.well-known/mta-sts.txt."
else
  echo "$MTASTS_OUTPUT"
  tip "MTA-STS TXT record found. Ensure you also serve a valid policy file at https://mta-sts.$DOMAIN/.well-known/mta-sts.txt. Use a unique 'id' value for each policy update."
  tip "Test your MTA-STS with 'https://mta-sts.mailhardener.com/' or 'https://aykevl.nl/apps/mta-sts/'"
fi

# TLS-RPT Record
section "TLS-RPT Record"
TLSRPT_OUTPUT=$(dig $RESOLVER +short TXT "_smtp._tls.$DOMAIN" || true)
if [[ -z "$TLSRPT_OUTPUT" ]]; then
  missing
  tip "No TLS-RPT record found. TLS-RPT lets you receive reports about failed or downgraded TLS connections. Add a TXT record at _smtp._tls.$DOMAIN with: 'v=TLSRPTv1; rua=mailto:you@yourdomain.com'."
else
  echo "$TLSRPT_OUTPUT"
  tip "TLS-RPT record found. Make sure the reporting address is monitored and can handle JSON reports from various providers."
  tip "Review TLS-RPT reports to detect and fix mail transport security issues."
fi

# DKIM Record
section "DKIM Record"
if [[ -n "$DKIM_SELECTOR" ]]; then
  DKIM_DOMAIN="$DKIM_SELECTOR._domainkey.$DOMAIN"
  DKIM_OUTPUT=$(dig $RESOLVER +short TXT "$DKIM_DOMAIN" || true)
  if [[ -z "$DKIM_OUTPUT" ]]; then
    echo -e "${RED}No DKIM record found for selector '${DKIM_SELECTOR}'!${NC}"
    tip "No DKIM record found for selector '$DKIM_SELECTOR'. DKIM is essential for email authentication. Check your mail server's DKIM settings and ensure the selector matches your DNS."
    tip "Common selectors: 'default', 'mail', 'mailcow', or your server's hostname. You can find the selector in your mail server's DKIM configuration or by inspecting the 'DKIM-Signature' header of a sent email."
  else
    echo "$DKIM_OUTPUT"
    if echo "$DKIM_OUTPUT" | grep -q 'v=DKIM1'; then
      tip "DKIM record found. DKIM helps verify that your emails are not altered in transit. Make sure your mail server is signing outgoing mail with this selector."
      tip "Test DKIM by sending a mail to a Gmail or Outlook address and inspecting the headers, or use 'https://www.appmaildev.com/en/dkim/' or 'https://www.mail-tester.com/'."
    else
      tip "DKIM record found, but it may be malformed. Ensure it starts with 'v=DKIM1;'."
    fi
  fi
else
  echo -e "${YELLOW}No DKIM selector provided. Skipping DKIM check.${NC}"
  tip "DKIM is important for email authentication. If you want to check it, provide a selector as the second argument."
  tip "You can find your DKIM selector in your mail server's DKIM settings or by looking at the 'DKIM-Signature' header in a sent email."
fi

# DANE/TLSA Record (for mail.$DOMAIN, port 25)
section "DANE/TLSA Record (_25._tcp.mail.$DOMAIN)"
TLSA_OUTPUT=$(dig $RESOLVER +short TLSA "_25._tcp.mail.$DOMAIN" || true)
if [[ -z "$TLSA_OUTPUT" ]]; then
  missing
  tip "No DANE/TLSA record found. DANE provides cryptographic binding of your mail server's TLS certificate to DNS. This is advanced and requires DNSSEC. Only a few mail providers support DANE."
else
  echo "$TLSA_OUTPUT"
  tip "DANE/TLSA record found. Ensure your mail server's TLS certificate matches the TLSA record. DANE requires DNSSEC to be effective."
  tip "Test DANE with 'https://dane.sys4.de/' or 'https://danecheck.org/'."
fi

# DNSSEC Status (improved parsing)
section "DNSSEC Status"
DNSSEC_OUTPUT="$(dig $RESOLVER +dnssec SOA "$DOMAIN")"
if echo "$DNSSEC_OUTPUT" | grep -q "RRSIG"; then
  echo -e "${GREEN}DNSSEC: Present${NC}"
  tip "DNSSEC is enabled. This protects your domain from DNS spoofing and cache poisoning. Make sure to monitor for DNSSEC signing or rollover issues."
  tip "Test DNSSEC with 'https://dnssec-analyzer.verisignlabs.com/' or 'https://internet.nl/'."
else
  echo -e "${RED}DNSSEC: Not present${NC}"
  tip "DNSSEC is not enabled. Consider enabling it at your DNS provider for extra security. DNSSEC is required for DANE/TLSA to be effective."
fi

# Name Servers
section "Name Servers"
NS_OUTPUT=$(dig $RESOLVER +short NS "$DOMAIN" || true)
if [[ -z "$NS_OUTPUT" ]]; then
  missing
  tip "No NS records found. Your domain must have at least one authoritative name server. Check your domain registrar's settings."
else
  echo "$NS_OUTPUT"
  tip "Name servers are responsible for serving your DNS records. Use at least two geographically separated name servers for redundancy."
fi

# IPv6 Support
section "IPv6 (AAAA) for MX Hosts"
MX_HOSTS=$(echo "$MX_OUTPUT" | awk '{print $2}' | sed 's/\.$//')
if [[ -z "$MX_HOSTS" ]]; then
  echo -e "${YELLOW}No MX records to check for IPv6.${NC}"
else
  for mx in $MX_HOSTS; do
    AAAA=$(dig $RESOLVER +short AAAA "$mx")
    if [[ -n "$AAAA" ]]; then
      echo -e "$mx: ${GREEN}$AAAA${NC}"
      tip "Your MX host $mx supports IPv6. This is great for future-proofing and global reachability."
    else
      echo -e "$mx: ${YELLOW}No AAAA record (IPv4-only is normal if you don't run IPv6 on this host)${NC}"
      tip "No AAAA record for $mx. If your mail server is IPv4-only, this is expected. If you want to support IPv6 mail delivery, add an AAAA record and ensure your server is listening on IPv6."
    fi
  done
fi

# Reverse DNS for MX hosts
section "Reverse DNS for MX Hosts"
if [[ -z "$MX_HOSTS" ]]; then
  echo -e "${YELLOW}No MX records to check for PTR.${NC}"
else
  for mx in $MX_HOSTS; do
    IP=$(dig $RESOLVER +short "$mx" | head -n1)
    if [[ -n "$IP" ]]; then
      PTR=$(dig $RESOLVER +short -x "$IP")
      if [[ -n "$PTR" ]]; then
        echo -e "$mx ($IP): ${GREEN}$PTR${NC}"
        tip "PTR record found for $mx ($IP). Reverse DNS is critical for mail deliverability. The PTR should match your mail server's hostname and the HELO/EHLO string."
      else
        echo -e "$mx ($IP): ${RED}No PTR record${NC}"
        tip "No PTR record for $mx ($IP). Many mail providers will reject or mark as spam mail from servers without reverse DNS. Set the PTR at your IP provider."
      fi
    else
      echo -e "$mx: ${RED}No A record found${NC}"
      tip "No A record found for $mx. Check your MX and A records. The MX hostname must resolve to an IP address."
    fi
  done
fi

END_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

echo -e "\n${CYAN}All done! mail_dns_diag.sh v$VERSION signing off on host $HOSTNAME."
echo -e "Start: $START_TIME | End: $END_TIME"
echo -e "Goodbye!${NC}"