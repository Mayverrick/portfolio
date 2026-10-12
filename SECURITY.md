# Security Architecture & Vulnerability Disclosure Policy

## 1. High-Assurance Security Architecture

This web application implements a defense-in-depth, military-grade security posture engineered to mitigate OWASP Top 10 client-side risks, Cross-Site Scripting (XSS), Clickjacking, Reverse Tabnabbing, and automated abuse.

### Defensive Layers

| Layer | Implementation | Security Objective |
| :--- | :--- | :--- |
| **Content Security Policy (CSP)** | CSP Level 3 (`default-src 'none'`, `script-src 'self'`) | Eliminates inline execution vectors, bans unauthorized origins, prevents XSS |
| **Anti-Clickjacking** | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, JS Frame-Busting Guard | Neutralizes UI redressing and iframe clickjacking attempts |
| **MIME Sniffing Defense** | `X-Content-Type-Options: nosniff` | Prevents browsers from interpreting non-executable types as executable |
| **Referrer Protection** | `Referrer-Policy: strict-origin-when-cross-origin` | Protects privacy and prevents URL leakages to third parties |
| **Permissions Policy** | Hardware, Sensors, Battery, Payment & Mic access disabled | Isolates device capabilities from browser exploitation |
| **Anti-Bot & Automation** | Stealth honeypot + Human Time-Gate Challenge (3s minimum interaction) | Blocks headless automated crawlers and form-spam bots |
| **Client Rate Limiting** | Token-Bucket sliding window (max 3 submissions / 15m, 20s cooldown) | Mitigates flood abuse and Denial-of-Service against form endpoints |
| **Input Sanitization** | Unicode NFC normalization, ASCII control character stripping, length constraints | Prevents payload injection and control-char evasion |
| **DOM XSS Immunity** | Strict use of `textContent` and DOM nodes instead of raw `innerHTML` | Guarantees zero DOM-based injection vulnerabilities |
| **Reverse Tabnabbing** | Enforced `rel="noopener noreferrer"` on all external links | Prevents `window.opener` exploitation and target tab hijacking |

---

## 2. Universal Deployment Headers

Security headers are deployed across all target platforms:
- **Cloudflare Pages & Netlify**: [`_headers`](./_headers)
- **Vercel**: [`vercel.json`](./vercel.json)
- **Apache 2.4+**: [`.htaccess`](./.htaccess)
- **Nginx**: [`nginx.conf`](./nginx.conf)
- **Static / GitHub Pages Fallback**: Native `<meta>` tags in [`index.html`](./index.html)

---

## 3. Reporting a Vulnerability

If you discover a security vulnerability in this project, please follow responsible disclosure guidelines:

- **Contact**: Send vulnerability reports directly to `Mrifeanyi.mi@gmail.com`.
- **Response Time**: We acknowledge receipt of vulnerability reports within 48 hours and strive to issue a resolution within 7 business days.
- **Scope**: Please do not perform disruptive testing (Denial of Service, physical attacks, or social engineering).
