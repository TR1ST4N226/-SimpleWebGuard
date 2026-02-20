# SimpleWebGuard

**Web Vulnerability Auditor** - A Black-Box security scanner for automated reconnaissance during penetration testing.

![Node.js](https://img.shields.io/badge/Node.js->=16.0.0-green.svg)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Security](https://img.shields.io/badge/Security-Penetration%20Testing-red.svg)

---

## 📝 Description

SimpleWebGuard is a **Black-Box** web security auditing tool developed in **Node.js**. It automates the reconnaissance phase of penetration testing by analyzing the attack surface of web applications through HTTP responses and network configuration—without requiring backend or database access.

The tool focuses on detecting **server misconfigurations**, which are often the primary entry point for complex attacks like:
- 🔴 Cross-Site Scripting (XSS)
- 🔴 Clickjacking
- 🔴 Man-in-the-Middle (MitM) attacks

---

## ⚙️ Features

### 1️⃣ **Security Headers Analysis**
Analyzes the presence and configuration of critical security headers:
- ✅ **Content-Security-Policy (CSP)** - XSS protection
- ✅ **Strict-Transport-Security (HSTS)** - Force HTTPS
- ✅ **X-Frame-Options** - Clickjacking protection
- ✅ **X-Content-Type-Options** - MIME-sniffing protection
- ✅ **X-XSS-Protection** - Legacy XSS filter
- ✅ **Referrer-Policy** - Referer leakage control
- ✅ **Permissions-Policy** - Browser feature control

### 2️⃣ **Server Fingerprinting**
Extracts information from HTTP headers to identify:
- 🔍 Server type and version (`Server`, `X-Powered-By`)
- 🔍 Technology stack detection (PHP, ASP.NET, Express.js, etc.)
- ⚠️ Version disclosure vulnerabilities (CVE identification)

### 3️⃣ **SSL/TLS Configuration Check**
Verifies the security of encrypted connections:
- 🔒 Certificate validity and expiration
- 🔒 Certificate issuer (CA verification)
- 🔒 Cipher strength and TLS version
- 🔒 HTTP → HTTPS redirection check

### 4️⃣ **Port Scanning (Network Reconnaissance)**
Lightweight TCP port scanner that detects exposed services:
- 🌐 Common web ports (80, 443, 8080, 8443)
- 🚨 Dangerous services (FTP, Telnet, RDP)
- 🗄️ Database ports (MySQL, PostgreSQL, MongoDB, Redis)

---

## 📋 Prerequisites

Before running SimpleWebGuard, ensure you have:

- **Node.js** v16.0.0 or higher → [Download Node.js](https://nodejs.org/)
- **npm** (included with Node.js)

---

## 🚀 Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/SimpleWebGuard.git
cd SimpleWebGuard
```

### 2. Install dependencies
```bash
npm install
```

### 3. Run the tool
```bash
npm start
```

Or directly:
```bash
node src/index.js
```

---

## 💻 Usage

### Interactive Mode (Recommended)
Simply run the tool and enter the target URL when prompted:
```bash
npm start
```

```
Enter target URL (e.g., https://example.com): https://target-site.com
```

### Command Line Mode
Pass the URL as an argument:
```bash
npm start https://example.com
```

Or:
```bash
node src/index.js https://example.com
```

---

## 📊 Example Output

```
═══════════════════════════════════════════════════════════════════
   SimpleWebGuard - Web Vulnerability Auditor
  Black-Box Security Scanner for Web Applications
═══════════════════════════════════════════════════════════════════

Target: https://example.com

▸ Server Fingerprinting
  ✗ Server: nginx/1.18.0
  ⚠ [MEDIUM] Server header discloses version information.
  ℹ Detected: Nginx web server

▸ Security Headers Analysis
  ✗ Content-Security-Policy: Missing
  ⚠ [HIGH] CSP header is missing. Site is vulnerable to XSS attacks.
  
  ✓ Strict-Transport-Security: Present
  ℹ Value: max-age=31536000; includeSubDomains
  
  ✓ X-Frame-Options: DENY
  ✗ X-Content-Type-Options: Missing
  ⚠ [LOW] X-Content-Type-Options header is missing.

▸ SSL/TLS Configuration
  ✓ HTTPS: Enabled
  ✓ Certificate Status: Valid
  ℹ Valid until: Dec 31, 2026 (340 days remaining)
  ✓ Certificate Issuer: Let's Encrypt
  ✓ Cipher Suite: TLS_AES_128_GCM_SHA256
  ℹ Protocol: TLSv1.3
  ℹ TLS version is secure (TLSv1.3) ✓

▸ Port Scanning
Scanning common ports on example.com...

Found 2 open port(s):

  ✗ Port 22: SSH - OPEN
  ⚠ [MEDIUM] SSH port is open. Ensure strong passwords/keys.
  
  ✓ Port 443: HTTPS - OPEN

═══════════════════════════════════════════════════════════════════
                         Scan Complete
═══════════════════════════════════════════════════════════════════
```

---

## 📁 Project Structure

```
SimpleWebGuard/
├── src/
│   ├── scanners/
│   │   ├── headerScanner.js      # Security headers analysis
│   │   ├── serverFingerprint.js  # Server identification
│   │   ├── sslChecker.js         # SSL/TLS verification
│   │   └── portScanner.js        # TCP port scanning
│   ├── utils/
│   │   ├── logger.js             # Colored console output
│   │   └── validator.js          # Input validation
│   └── index.js                  # Main entry point
├── package.json
├── .gitignore
├── README.md
└── LICENSE
```

---

## 🛠️ Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| [axios](https://www.npmjs.com/package/axios) | ^1.13.5 | HTTP requests and header extraction |
| [chalk](https://www.npmjs.com/package/chalk) | ^5.6.2 | Terminal output coloring |
| [validator](https://www.npmjs.com/package/validator) | ^13.15.26 | URL and input validation |

---

## ⚠️ Legal Disclaimer

**IMPORTANT:** SimpleWebGuard is intended for **authorized security testing only**.

- ✅ **DO** use this tool on systems you own or have explicit permission to test
- ❌ **DO NOT** scan systems without authorization
- ⚖️ Unauthorized access to computer systems may be illegal in your jurisdiction

**The developers assume no liability for misuse of this tool.**

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🔗 Resources

- **OWASP Security Headers**: https://owasp.org/www-project-secure-headers/
- **Mozilla Observatory**: https://observatory.mozilla.org/
- **SSL Labs**: https://www.ssllabs.com/ssltest/

## 📞 Support

If you find this tool useful, please ⭐ star this repository!

For issues or feature requests, open an issue on GitHub.
