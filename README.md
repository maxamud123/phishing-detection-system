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
| Detection | Heuristics, Typosquatting, RDAP, VirusTotal, Google Safe Browsing |

## Roles

| Role | Capabilities |
|------|-------------|
| **Admin** | Full access — manage users, view audit logs, all features |
| **Analyst** | Scan URLs, view reports, view analytics |
| **Viewer** | View scans and reports (read-only) |

---

## Prerequisites

Install these before starting:

- [Git](https://git-scm.com/downloads)
- [Node.js v18+](https://nodejs.org) — download the LTS version
- [MongoDB Community](https://www.mongodb.com/try/download/community) — make sure it is running

---

## Setup

### 1. Clone the repository

```
git clone https://github.com/maxamud123/phishing-detection-system.git
cd phishing-detection-system
```

### 2. Install frontend dependencies

```
npm install
```

### 3. Install backend dependencies

```
cd server
npm install
cd ..
```

### 4. Configure environment variables

**Windows (Command Prompt):**
```
copy server\.env.example server\.env
```

**Mac / Linux:**
```
cp server/.env.example server/.env
```

Open `server/.env` in any text editor. MongoDB must be running — all other values are optional.

### 5. Run the backend

Open a terminal, go into the server folder, and start it:

```
cd server
node index.js
```

Backend runs on `http://localhost:3001`

### 6. Run the frontend

Open a **second terminal** in the project root and run:

```
npm run dev
```

Frontend runs on `http://localhost:5173`

---

## First-Time Login

On first run the database is empty. Open `http://localhost:5173` and click **Create Account**.

The **first account** created is automatically assigned the **Admin** role. All accounts after that register as Analyst by default.

---

## API Keys (Optional)

The system works without API keys using built-in heuristic detection. To enable deeper scanning:

- **VirusTotal** — free key at [virustotal.com](https://www.virustotal.com/gui/my-apikey)
- **Google Safe Browsing** — enable the API in [Google Cloud Console](https://console.cloud.google.com)

Add both to `server/.env`.

---

## Project Structure

```
phishing-detection-system/
├── src/                    # React frontend
│   ├── app/
│   │   ├── components/     # Dashboard, Scanner, Reports, Analytics, Admin
│   │   ├── lib/            # API client, WebSocket, utilities
│   │   └── App.tsx         # Root component + routing
│   └── styles/             # Global CSS + Tailwind
├── server/
│   ├── index.js            # Backend — HTTP server, auth, all API routes
│   └── .env.example        # Environment variable template
├── public/
└── package.json
```
