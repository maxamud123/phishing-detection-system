# Phishing Detection System

A full-stack phishing URL detection platform with real-time threat analysis, role-based access control, and audit logging.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + TypeScript + Vite |
| Styling | Tailwind CSS + shadcn/ui |
| Backend | Node.js (no framework) |
| Database | MongoDB |
| Real-time | WebSocket |
| Detection | Heuristics, Typosquatting, RDAP, [Phishing.Database](https://github.com/Phishing-Database), VirusTotal, Google Safe Browsing |

## Roles

| Role | Capabilities |
|------|-------------|
| **Admin** | Full access — manage users, view audit logs, all features |
| **User** | Scan URLs, submit and manage reports, view analytics |

---

## Prerequisites

- [Git](https://git-scm.com/downloads)
- [Node.js v18+](https://nodejs.org) (LTS)
- [MongoDB Community](https://www.mongodb.com/try/download/community) — running locally

---

## Setup

### 1. Clone and install

```bash
git clone https://github.com/maxamud123/phishing-detection-system.git
cd phishing-detection-system
npm install
cd server && npm install && cd ..
```

### 2. Environment files

**Backend** — copy and edit `server/.env`:

```bash
copy server\.env.example server\.env
```

**Frontend** (optional) — copy `.env.example` to `.env` in the project root if you need a custom WebSocket URL.

Required for local dev:
- `MONGODB_URI` — MongoDB connection string
- `ADMIN_EMAIL` / `ADMIN_PASSWORD` — seeded admin (use a **strong** password before deploying)

Optional:
- `GROQ_API_KEY` — AI chat ([Groq Console](https://console.groq.com))
- `VIRUSTOTAL_API_KEY`, `GOOGLE_SAFE_BROWSING_KEY` — deeper scanning
- `SMTP_*` — email threat alerts

**Phishing.Database** (on by default): on backend startup the server downloads active phishing domains and links from [phish.co.za](https://phish.co.za/latest/) ([GitHub org](https://github.com/Phishing-Database)) and caches them under `server/data/`. Scans check this blocklist automatically — no API key required. Set `PHISHING_DB_ENABLED=false` to disable.

### 3. Run the backend

```bash
cd server
node index.js
```

API + WebSocket: `http://localhost:3001`

### 4. Run the frontend

In a **second terminal** at the project root:

```bash
npm run dev
```

App: `http://localhost:5173`

---

## First-Time Login

On startup the backend seeds an **Admin** account from `server/.env` (`ADMIN_EMAIL` / `ADMIN_PASSWORD`).

**Default credentials** (if you have not changed `server/.env`):

| Field | Value |
|-------|--------|
| Email | `admin@phishguard.local` |
| Password | `Admin@1234` |

If you copied `server/.env.example` and set a new `ADMIN_PASSWORD`, use that value instead — the database keeps the password from when the admin was first created.

Sign in at `http://localhost:5173`, or use **Create Account** to register as a **User** (admins can promote users in the Admin panel).

**Password policy:** at least 8 characters with uppercase, lowercase, and a number.

---

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start Vite dev server |
| `npm run build` | Production build |
| `npm run typecheck` | TypeScript check |
| `npm run lint` | ESLint (frontend) |
| `npm test` | Vitest unit tests |
| `npm run test:server` | Node test runner (backend) |

---

## Project Structure

```
phishing-detection-system/
├── src/                    # React frontend
│   ├── app/
│   │   ├── components/     # Dashboard, Scanner, Reports, Analytics, Admin
│   │   ├── hooks/          # Health polling, WebSocket notifications
│   │   ├── lib/            # API client, env, password policy
│   │   └── App.tsx
│   └── styles/
├── server/
│   ├── index.js            # HTTP server + routes
│   ├── controllers/        # Auth, scans, health, chat, …
│   └── .env.example
└── package.json
```
