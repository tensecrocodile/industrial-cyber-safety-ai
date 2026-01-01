# Industrial Cyber Safety AI Platform

**Enterprise-grade AI-powered security system** with Data Loss Prevention (DLP), multiple firewall control, network security, endpoint protection, DPDP/GDPR compliance, anomaly detection, and unified admin dashboard.

## Overview

This platform provides **end-to-end cybersecurity** for industrial OT/IT environments with:
- Real-time threat detection via AI/ML anomaly detection
- Data governance & compliance (DPDP, GDPR, data classification)
- Endpoint DLP with USB/network/upload controls
- Multiple firewall & network segmentation management
- Network Access Control (NAC) with device posture checking
- Unified admin console with dynamic dashboards
- Full audit logging and incident response automation

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│          ADMIN DESKTOP CONSOLE (Electron + React)   │
│     - Dynamic Dashboard | Policy Editor | SIEM      │
│     - Incident Response | Reports | Compliance      │
└──────────────────┬──────────────────────────────────┘
                   │ (Secure API: TLS + JWT)
                   ↓
┌─────────────────────────────────────────────────────┐
│          BACKEND SERVICES (FastAPI + PostgreSQL)    │
│ ┌──────────────┬──────────────┬──────────────────┐  │
│ │ DLP Engine   │ AI Anomaly   │ Firewall         │  │
│ │ (File/USB)   │ Detection    │ Controller       │  │
│ └──────────────┴──────────────┴──────────────────┘  │
│ ┌──────────────┬──────────────┬──────────────────┐  │
│ │ NAC Manager  │ Compliance   │ Data Governance  │  │
│ │ (Device Auth)│ Engine       │ (Catalog + Rules)│  │
│ └──────────────┴──────────────┴──────────────────┘  │
│ ┌──────────────────────────────────────────────────┐ │
│ │ Event Store (PostgreSQL) + Cache (Redis)        │ │
│ └──────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────┬─┘
                                                      ↓
        ┌─────────────────────────────────────────────────────┐
        │  ENDPOINT AGENTS & NETWORK CONTROLLERS              │
        │  (Windows/Linux DLP Agents)                         │
        │  (NGFW, Host Firewalls, NAC, PLC Gateways)        │
        └─────────────────────────────────────────────────────┘
```

---

## Key Components

### 1. **Endpoint DLP Agent** (Python, Windows/Linux)
- Real-time file, USB, clipboard, print, and network monitoring
- Content inspection with data classification
- Policy enforcement (block/quarantine/log)
- TLS termination & encrypted uploads

### 2. **AI Anomaly Detection Engine** (PyTorch + Scikit-learn)
- User/device behavior profiling
- Policy violation detection
- Risk scoring and alert triage
- Playbook-based automated responses

### 3. **Firewall & Network Control** (Multi-layer)
- NGFW integration (policy push via API)
- Host-based firewall rules (Windows Defender, iptables)
- Microsegmentation & zero-trust policies
- Network Access Control (802.1X, RADIUS)

### 4. **Data Governance & Compliance**
- Data classification & tagging engine
- Consent registry & purpose management
- DPDP Act compliance (India): minimisation, security logs, DPIA
- GDPR compliance: data subject rights, breach notifications
- Policy engine for retention, jurisdiction, legal basis

### 5. **Desktop Admin Console** (Electron + React)
- Live threat dashboard with KPIs
- Data protection & compliance posture view
- Policy editor for DLP, firewall, NAC
- Incident management & playbook execution
- Exportable audit logs & compliance reports
- Admin-only access with role-based controls

---

## Installation & Setup

### Prerequisites
- Python 3.9+
- PostgreSQL 12+
- Redis 6+
- Node.js 16+ (for desktop app)
- Docker (optional, for containerized deployment)

### Backend Setup

```bash
# Clone repo
git clone https://github.com/tensecrocodile/industrial-cyber-safety-ai.git
cd industrial-cyber-safety-ai/backend

# Install dependencies
pip install -r requirements.txt

# Setup database
python -m alembic upgrade head

# Create admin user
python scripts/create_admin.py --username admin --password <secure_password>

# Start backend server
uvicorn main:app --host 0.0.0.0 --port 8000 --ssl-keyfile=certs/key.pem --ssl-certfile=certs/cert.pem
```

### Desktop Admin App Setup

```bash
cd ../desktop

# Install dependencies
npm install

# Start development mode
npm run dev

# Build for production
npm run build
```

### Endpoint Agent Setup

```bash
cd ../agents/dlp-agent

# Install dependencies
pip install -r requirements.txt

# Configure
cp config.example.yaml config.yaml
# Edit config.yaml with backend API endpoint

# Run as service
python setup_service.py  # Windows Service
# OR systemctl start dlp-agent  # Linux systemd
```

---

## Features

### 🔒 Data Loss Prevention (DLP)
- **Channels Monitored**: USB, Email, Cloud Uploads, Network Shares, Printing, Clipboard
- **Content Inspection**: Pattern matching, ML-based PII detection, custom rules
- **Actions**: Block, Quarantine, Log, Notify, Isolate device

### 🤖 AI-Powered Threat Detection
- **Anomaly Types**: Unusual file access, mass data transfers, privilege escalation, lateral movement
- **Scoring**: Risk scores (0-100) with explainability
- **Auto-Response**: Playbooks for containment, isolation, and alerts

### 🔥 Firewall & Network Control
- **Multi-layer Segmentation**: DMZ, OT zone, IT zone, guest network
- **Zero-Trust Policies**: Least-privilege by default
- **Dynamic Rules**: Auto-learned safe traffic in 30 days
- **Protocols**: HTTP/HTTPS, FTP, SSH, OT protocols (Modbus, OPC UA)

### 🔐 Compliance & Governance
- **DPDP (India)**:
  - Consent management for each data category
  - Proof of "reasonable security safeguards"
  - Breach notification workflows
  - Data retention & deletion schedules

- **GDPR**:
  - Data Subject Access Request (DSAR) workflows
  - Privacy Impact Assessment (DPIA) templates
  - Cross-border data transfer controls
  - Automatic encryption & pseudonymization

---

## API Examples

### 1. Create DLP Policy

```bash
curl -X POST http://localhost:8000/api/dlp/policies \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block USB Copy",
    "channels": ["usb", "external_drive"],
    "data_types": ["personal_data", "ip"],
    "action": "block",
    "severity": "high"
  }'
```

### 2. Trigger Incident Response

```bash
curl -X POST http://localhost:8000/api/incidents/response \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "john.doe",
    "device_id": "WKS-001",
    "action": "isolate",
    "reason": "anomaly_detected"
  }'
```

### 3. Export Compliance Report

```bash
curl -X GET "http://localhost:8000/api/compliance/report?type=dpdp&start=2025-01-01&end=2025-12-31" \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  > compliance_report_2025.pdf
```

---

## Project Structure

```
industrial-cyber-safety-ai/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                 # FastAPI entry point
│   │   ├── models/                 # Database models
│   │   ├── routes/                 # API endpoints
│   │   ├── services/
│   │   │   ├── dlp_service.py     # DLP logic
│   │   │   ├── anomaly_detection.py # AI models
│   │   │   ├── firewall_controller.py
│   │   │   ├── compliance_engine.py # DPDP/GDPR
│   │   │   └── nac_manager.py
│   │   ├── ml_models/              # Trained models
│   │   └── utils/
│   ├── tests/
│   ├── migrations/                 # Alembic DB migrations
│   ├── requirements.txt
│   └── Dockerfile
├── agents/
│   └── dlp-agent/
│       ├── dlp_agent.py            # Main agent loop
│       ├── file_monitor.py         # File system monitoring
│       ├── usb_monitor.py          # USB events
│       ├── network_monitor.py      # Network traffic
│       ├── config.yaml             # Configuration
│       └── requirements.txt
├── desktop/
│   ├── src/
│   │   ├── main.ts                 # Electron main process
│   │   ├── preload.ts              # Context isolation
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx       # Main dashboard
│   │   │   ├── DLPPolicies.tsx
│   │   │   ├── FirewallRules.tsx
│   │   │   ├── Compliance.tsx
│   │   │   └── Incidents.tsx
│   │   ├── components/             # React components
│   │   ├── services/               # API calls
│   │   └── styles/                 # CSS/tailwind
│   ├── package.json
│   └── tsconfig.json
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DPDP_GDPR_IMPLEMENTATION.md
│   ├── API.md
│   ├── DEPLOYMENT.md
│   └── TROUBLESHOOTING.md
├── docker-compose.yml              # Full stack setup
├── .gitignore
├── LICENSE (MIT)
└── README.md
```

---

## Security Hardening

✅ **In Transit**: TLS 1.3 + HSTS
✅ **At Rest**: AES-256-GCM encryption for sensitive data
✅ **Authentication**: JWT + mTLS for agents
✅ **Access Control**: RBAC with admin approval workflows
✅ **Audit Logging**: Immutable logs with tamper detection
✅ **Secret Management**: HashiCorp Vault or AWS Secrets Manager
✅ **Code Scanning**: GitHub security scanning + SAST/DAST

---

## Compliance Checklist

### DPDP Act (India)
- [ ] Data minimisation implemented
- [ ] Consent registry active
- [ ] Security audit logs exportable
- [ ] Breach notification workflow ready
- [ ] Storage limitation enforced
- [ ] Approved by Data Protection Board (if required)

### GDPR (EU)
- [ ] Data Subject Request handlers active
- [ ] Privacy Policy & DPA templates included
- [ ] Right to erasure ("forget me") automated
- [ ] Right to restrict processing implemented
- [ ] Right to data portability available
- [ ] DPIA template provided

---

## Roadmap

- [x] Core DLP engine with USB/email controls
- [x] AI anomaly detection with UEBA
- [ ] Multi-cloud firewall orchestration (AWS, Azure, GCP)
- [ ] Advanced threat hunting dashboard
- [ ] Integration with SIEM (Splunk, ELK)
- [ ] OT protocol support (Modbus, Profinet)
- [ ] Automated incident playbooks (SOAR)
- [ ] Mobile app for on-the-go monitoring
- [ ] ML model marketplace for custom use cases

---

## Testing

```bash
# Run unit tests
pytest backend/tests/unit/ -v

# Run integration tests
pytest backend/tests/integration/ -v

# Run security scans
bandit -r backend/app/
safety check

# Desktop app tests
cd desktop && npm test
```

---

## Contributing

Contributions welcome! Please follow:
1. Fork the repo
2. Create feature branch (`git checkout -b feature/your-feature`)
3. Commit changes with security best practices
4. Push to branch & create Pull Request
5. Code review + security scanning required

---

## Support & Documentation

- **Docs**: See `/docs` folder
- **Issues**: GitHub Issues for bugs & feature requests
- **Security**: Report vulnerabilities to security@example.com (no public disclosure)

---

## License

MIT License - See LICENSE file

---

## Authors

- **Your Name** - Lead Security Architect & Developer
- Data Security & AI/ML Integration

---

## Disclaimer

This system handles **sensitive security data**. Deployment requires:
- Professional security assessment
- Compliance validation with legal team
- Incident response plan
- Regular penetration testing
- Admin user authentication & 2FA
