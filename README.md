# Low Interaction Honeypot — Network Attack Detection & Alert System
**Melchisedeck Lucian Komba | BCS Final Year Project | KIU Tanzania | 2026**

## Project Structure

```
Honeypot Project/
├── honeypot/               # Honeypot capture modules
│   ├── web/                # Fake university website (Flask)
│   ├── services/           # SSH / FTP / DB port emulators
│   └── engine/             # Attack detection & logging engine
├── dashboard/              # Admin dashboard REST API (FastAPI)
│   ├── models/             # SQLAlchemy ORM models
│   ├── schemas/            # Pydantic request/response schemas
│   ├── routers/            # API route handlers
│   ├── services/           # Business logic (auth, alerts, reports)
│   └── websocket/          # Socket.IO live feed
├── frontend/               # React admin dashboard (Vite + Tailwind)
│   └── src/
│       ├── pages/          # Full page components
│       ├── components/     # Feature-based UI components
│       ├── hooks/          # Custom React hooks
│       ├── store/          # Global state (Zustand)
│       └── utils/          # Helper functions
├── workers/                # Celery background tasks (email + SMS alerts)
├── migrations/             # Alembic database migration scripts
├── tests/                  # Unit, integration, and scenario tests
├── nginx/                  # Nginx reverse proxy configuration
├── docs/                   # API documentation and diagrams
├── scripts/                # Start, stop, backup, test scripts
└── backup/                 # Database backup storage
```

## Quick Start
```bash
cp .env.example .env        # Fill in your credentials
docker-compose up -d        # Start all services
```

## Tech Stack
- **Backend:** Python 3.11, FastAPI, SQLAlchemy, Celery, Redis
- **Frontend:** React 18, Vite, Tailwind CSS, Recharts, Leaflet
- **Database:** MySQL 8 / PostgreSQL 16
- **Alerts:** Twilio (SMS), SMTP (Email)
- **Deployment:** Docker Compose, Nginx, Ubuntu Server 22.04
