# mail_dns_diag.sh

**mail_dns_diag.sh** is a smart, modern, and deeply technical Bash script for diagnosing and auditing all essential DNS and mail security records for any domain.
It provides actionable, context-aware tips after each check, making it a powerful tool for both mail admins and learners.

---

## 🚀 Quick Start (One-liner)

Run the latest version directly (requires `bash` and `dig`):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Paul1404/mail_dns_diag.sh/refs/heads/main/mail_dns_diag.sh) yourdomain.com [dkim_selector]
```

- Replace `yourdomain.com` with your domain.
- Optionally provide a DKIM selector (e.g., `default`, `mail`, `mailcow`).

---

## Features

- **Checks all key DNS and mail security records:**
  - MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DANE/TLSA, DNSSEC, PTR, AAAA, NS
- **Deep-dive, context-aware technical tips** after each check
- **Public resolver (1.1.1.1) by default**; use `--local` for your system resolver
- **Friendly, clear, and colorized output**
- **Usage info and DKIM selector guidance**
- **No dependencies except `bash` and `dig`**

---

## Usage

```bash
./mail_dns_diag.sh domain.com [dkim_selector] [--local]
```

- `domain.com` – The domain you want to check (required)
- `dkim_selector` – DKIM selector (optional, e.g., `default`, `mail`, `mailcow`)
- `--local` – Use your local system resolver instead of the public resolver

**Example:**

```bash
./mail_dns_diag.sh example.com mailcow
```

---

## Why Use This Script?

- **Instantly audit your mail domain’s DNS and security posture**
- **Get actionable, technical advice** for every check
- **Perfect for Mailcow, Postfix, or any self-hosted/managed mail server**
- **Great for learning and troubleshooting**

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