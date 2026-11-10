# SafarSaathi Production Enterprise Architecture (v2.0)
### Assam's Direct E-Rickshaw Radar & Carpooling Super App

100% Direct Driver Payment • ₹0 Platform Commission • Encrypted Communications • Real-Time Cloud Sync

---

## 🏗️ Architecture Overview

SafarSaathi is built as a **decoupled, security-hardened production platform**:

1. **Frontend Client Layer (PWA & Mobile)**:
   - Hosted statically on **GitHub Pages** (or any CDN): `https://amanroy030892-netizen.github.io`
   - Real-time map radar via Leaflet.js and OpenStreetMap.
   - Driver 5-step onboarding wizard (Live Camera Selfie, ₹100 License Fee, 12-Digit UTR submission).
   - Real-time dual-engine synchronization (Firebase Realtime Database + Backend REST API).

2. **Backend Authoritative Server (`server.js`)**:
   - Zero-dependency Node.js enterprise core server (`node server.js`).
   - Cryptographically salted Scrypt master credential verification.
   - HMAC-SHA256 signed bearer session tokens (8-hour automatic expiration).
   - Server-side atomic duplicate UTR validation (prevents replay and spoofing attacks).
   - Authoritative data persistence (`data/production_db.json`).
   - 1-click cloud deployment ready via `Dockerfile` and `render.yaml`.

3. **Database & Security Layer**:
   - Locked-down Firebase Realtime Database (`database.rules.json`).
   - All unauthorized writes are strictly blocked.
   - Driver radar endpoints sanitize and strip all personal identity documents, bank UTRs, and phone numbers.

---

## 🔒 Security Hardening Highlights

- **Zero Hardcoded Secrets**: All passwords, API keys, and keystore credentials have been purged from the repository.
- **Dynamic Credential Derivation**: Passwords are verified strictly via Scrypt with dynamic 16-byte salts and constant-time comparison (`crypto.timingSafeEqual`).
- **No Client-Side State Dependency**: System-wide approval queues and active driver licensing live authoritatively on the server.
- **No Mock / Demo Relics**: Seeded dummy accounts, fake OTPs, and mock driver records have been removed.

---

## 🚀 Deployment Instructions

### 1. Static Frontend (GitHub Pages)
1. Commit and push repository files to the `main` branch.
2. In **Settings -> Pages**, set source branch to `main` and directory to `/ (root)`.
3. Frontend portal is live at: `https://amanroy030892-netizen.github.io`
4. Admin portal is live at: `https://amanroy030892-netizen.github.io/admin.html`

### 2. Backend API Server (Node.js / Docker / Cloud)
Run locally or on a cloud VPS:
```bash
npm start
# or: node server.js
```

Or deploy to **Render.com / Railway / Cloud Run** using the included `render.yaml` or `Dockerfile`:
- Copy `.env.example` to `.env`
- Set `ADMIN_PASSWORD` and `SESSION_SECRET` in your environment.

---

## 📦 Package File Manifest

| File | Purpose |
| :--- | :--- |
| `index.html` / `app.html` | Production Client Web App (Passenger & Driver portals, GPS Radar) |
| `admin.html` | Isolated Master Security Hub with dual-engine authentication |
| `server.js` | Authoritative Node.js Backend Server (Zero external dependencies) |
| `database.rules.json` | Production Firebase Security Rules |
| `Dockerfile` | Container configuration for cloud hosting |
| `render.yaml` | 1-Click Cloud Deployment Blueprint |
| `capacitor.config.json` | Android App configuration for native build |
| `manifest.json` & `sw.js` | Progressive Web App (PWA) offline cache and install manifest |
| `.env.example` | Production environment configuration template |

---

## 📄 License & Compliance

Developed for urban and rural transit enablement across Assam. All transactions are peer-to-peer (100% direct driver compensation, zero middleman commission).
