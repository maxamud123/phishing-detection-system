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

- [Node.js](https://nodejs.org/) v18 or higher
- [MongoDB](https://www.mongodb.com/try/download/community) running locally (or a MongoDB Atlas URI)

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/maxamud123/phishing-detection-system.git
cd phishing-detection-system
```

### 2. Install frontend dependencies

```bash
npm install
```

### 3. Install backend dependencies

```bash
cd server
npm install
cd ..
```

### 4. Configure environment variables

```bash
cp server/.env.example server/.env
```

Open `server/.env` and fill in your values. At minimum MongoDB must be running — all other values are optional.

### 5. Run the backend

```bash
cd server
node index.js
```

Backend starts on `http://localhost:3001`

### 6. Run the frontend (new terminal)

```bash
npm run dev
```

Frontend starts on `http://localhost:5173`

---

## First-Time Login

On first run the database is empty. Go to `http://localhost:5173` and click **Create Account**.

The **first account** registered is automatically assigned the **Admin** role. All subsequent accounts register as Analyst by default.

---

## API Keys (Optional)

The system works without API keys using built-in heuristic detection. To enable deeper scanning:

- **VirusTotal** — get a free key at [virustotal.com](https://www.virustotal.com/gui/my-apikey)
- **Google Safe Browsing** — enable the API in [Google Cloud Console](https://console.cloud.google.com)

Add both keys to `server/.env`.

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
