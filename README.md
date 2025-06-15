# mail_dns_diag.sh

**mail_dns_diag.sh** is a smart, modern, and deeply technical Bash script for diagnosing and auditing all essential DNS and mail security records for any domain.  
It provides actionable, context-aware tips after each check, making it a powerful tool for both mail admins and learners.

---

## 🚀 Quick Start

Run the latest version directly (requires `bash` and `dig`):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Paul1404/mail_dns_diag.sh/main/mail_dns_diag.sh) yourdomain.com
```

- Replace `yourdomain.com` with your domain.
- Optionally provide a DKIM selector (e.g., `default`, `mail`, `mailcow`) with `-s`.
- For JSON output, add `--json`.

---

## Features

- **Checks all key DNS and mail security records:**
  - MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DANE/TLSA, DNSSEC, PTR, AAAA, NS
- **Deep-dive, context-aware technical tips** after each check
- **Public resolver (1.1.1.1) by default**; use `--local` for your system resolver
- **Friendly, clear, and colorized output** (auto-detects terminal, or use `--no-color`)
- **JSON output** for automation and CI/CD (`--json`)
- **Usage info and DKIM selector guidance**
- **No dependencies except `bash` and `dig`**

---

## Usage

```bash
./mail_dns_diag.sh [options] domain.com

Options:
  -s, --selector <selector>   DKIM selector (e.g., 'default', 'mail', etc.)
  -l, --local                 Use local resolver instead of public (1.1.1.1)
  -j, --json                  Output results as JSON
  --no-color                  Disable color output
  -h, --help                  Show help and exit
  -v, --version               Show version and exit
```

**Examples:**

```bash
./mail_dns_diag.sh example.com
./mail_dns_diag.sh -s mailcow example.com
./mail_dns_diag.sh --json example.com
./mail_dns_diag.sh --local --no-color example.com
```

---

## Why Use This Script?

- **Instantly audit your mail domain’s DNS and security posture**
- **Get actionable, technical advice** for every check
- **Perfect for Mailcow, Postfix, or any self-hosted/managed mail server**
- **Great for learning and troubleshooting**
- **Integrates with automation and CI/CD via JSON output**

---

## Requirements

- `bash`
- `dig` (from `bind-utils` or similar package)

---

## License

MIT License

---

## Contributing

Pull requests and suggestions are welcome!  
Feel free to open issues for feature requests or bug reports.

---

**Happy mail auditing!**