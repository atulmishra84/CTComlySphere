# Overview

CT ComplySphere Visibility & Governance Platform is a comprehensive security and compliance management system designed specifically for AI agents operating in healthcare environments. The platform provides automated discovery, security scanning, risk assessment, and compliance evaluation against major healthcare frameworks including HIPAA, HITRUST CSF, FDA SaMD, GDPR, SOC 2 Type II, and NIST AI RMF. It supports multiple deployment protocols (Kubernetes, Docker, REST APIs, gRPC, WebSocket, MQTT, GraphQL, ROS) and offers multi-cloud management capabilities across AWS, Azure, and GCP.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Core Technology Stack
- **Backend Framework**: Flask with SQLAlchemy ORM for database operations
- **Database**: PostgreSQL (production) via DATABASE_URL environment variable
- **Frontend**: Bootstrap 5.3 light theme with Inter font, Chart.js, D3.js
- **Server**: Gunicorn with `--reuse-port --reload` on port 5000

## Application Structure
- **Modular Scanner Architecture**: Protocol-specific scanners inherit from `BaseScanner` abstract class
- **Blueprints**: `remediation`, `audit`, `onboarding`, `environment_scanner`, `integrations`, `model_registry`
- **Compliance Engine**: Framework-agnostic evaluation system with configurable rules and scoring
- **Analytics Pipeline**: `engines/predictive_engine.py` — linear regression 30-day forecast, anomaly detection, risk heatmaps
- **Control Gap Detection**: `engines/gap_detection_engine.py` — keyword-routing evidence checker across 13 control categories (audit_logging, authentication_method, encryption_status, phi_exposure, etc.)
- **Multi-Cloud Support**: Real cloud API scanning (AWS boto3, Azure, GCP); async background scan threads; live progress polling
- **Framework Controls**: `/frameworks` — view/enable/disable frameworks and 63 built-in control points across HIPAA, HITRUST, FDA SaMD, GDPR, SOC 2, NIST AI RMF
- **Compliance Rule Builder**: `/compliance/rules` — no-code AND/OR condition builder with severity/action config and framework tags
- **Control Gap Analysis**: `/compliance/gaps` — automated control gap detection, filterable detail table, manual attestation

## Routes (all return HTTP 200)
| Route | Page |
|---|---|
| `/` | Dashboard (live KPIs, 5 charts) |
| `/scan/results` | Security Scan Results |
| `/shadow-ai` | Shadow AI Systems |
| `/shadow-ai/high-risk` | High-Risk Shadow AI |
| `/analytics` | Analytics Dashboard |
| `/predictive-analytics` | Predictive Analytics |
| `/multi-cloud` | Multi-Cloud Management |
| `/cloud-scan` | Live Cloud Scan |
| `/compliance/report` | Compliance Reports |
| `/compliance/gaps` | Control Gap Analysis |
| `/compliance/rules` | Compliance Rule Builder |
| `/frameworks` | Framework Controls |
| `/clawbots` | Clawbot Detection |
| `/playbooks` | Agent Registration Playbooks |
| `/agent-deployment` | Collector Agents |
| `/continuous_scanning` | Continuous Monitoring |
| `/integrations` | Integrations (K8s, Docker, MCP) |
| `/agents/classification` | Agent Registry |
| `/model-registry` | AI Model Registry |
| `/knowledge` | Knowledge Base |

## Data Models (models.py)
- **AIAgent**: Core entity with protocol, cloud_provider, ai_type (AIAgentType enum), audit_logging, authentication_method, encryption fields
- **AIAgentType enum**: TRADITIONAL_ML, GENAI, AGENTIC_AI, COMPUTER_VISION, NLP, RECOMMENDATION, PREDICTIVE_ANALYTICS, AUTONOMOUS_SYSTEM, CONVERSATIONAL_AI, MULTIMODAL_AI, CLAWBOT
- **ScanResult**: risk_score, risk_level (RiskLevel enum), vulnerabilities_found, phi_exposure_detected
- **ComplianceEvaluation**: framework (ComplianceFramework enum), compliance_score, is_compliant, findings
- **ComplianceRule**: Custom compliance rules with condition builder (AND/OR logic)
- **ControlGapRecord**: Tracks control gap status (IMPLEMENTED/PARTIAL/NOT_IMPLEMENTED/NOT_APPLICABLE) per agent/framework/control
- **FrameworkConfig + ControlPoint**: 6 frameworks, 63 built-in controls

## Security Architecture
- **Risk Scoring Engine**: Weighted vulnerability assessment with healthcare-specific risk factors
- **PHI Detection**: Automated detection of Protected Health Information exposure
- **Continuous Monitoring**: Webhook-based continuous scanning with configurable schedules
- **Audit Trail**: Blueprint at `/audit/*` with comprehensive event logging
- **Shadow AI Detection**: Type-based detection (Unauthorized Process AI, Containerized Shadow AI, etc.)

## Dashboard (Live Data)
The dashboard (`/`) pulls all real data from PostgreSQL:
- KPI cards: total agents, total scans, compliance %, shadow AI count, PHI exposures, control gaps
- Risk distribution doughnut (from ScanResult.risk_level)
- Framework compliance bar (from ComplianceEvaluation)
- AI type breakdown polar area (from AIAgent.ai_type)
- Protocol mix horizontal bar (from AIAgent.protocol)
- 7-day scan timeline (real counts per day from ScanResult.created_at)
- Recent scan activity table (last 8 scans)
- Compliance framework summary with progress bars
- Control gap status card

## Frontend Theme
- **Color system**: Light background (`#f8fafc`), white cards, blue primary (#3b82f6 / #2563eb)
- **All pages must use light theme** — no dark backgrounds (#1a1f2e etc.)
- **Chart.js grid**: `rgba(0,0,0,0.05)`, ticks: `#6b7280`
- **Gradient utilities**: `.bg-gradient-primary`, `.bg-gradient-success`, etc. defined in `custom.css`

## Sidebar Structure (base.html)
All section headings use `.sidebar-heading.fw-semibold.text-uppercase` for consistency.

1. **Main**: Dashboard, Continuous Scanning, Analytics, Predictive Analytics
2. **AI & Scanning**: Scan Results, Agent Registry, Clawbot Detection, Model Registry, Playbooks
3. **Shadow AI Detection**: Shadow AI Systems, High-Risk Shadow AI, Shadow AI Remediation
4. **Compliance & Security**: Compliance Reports, Audit Trail, Framework Controls, Rule Builder, Control Gap Analysis
5. **Integration & Management**: Integrations, Multi-Cloud, Live Cloud Scan, Collector Agents
6. **Customer Management**: Customer Onboarding
7. **Resources**: Knowledge Base

Active sidebar link uses exact-match first, then longest-prefix fallback (JS in base.html).

# External Dependencies

## Core Framework
- Flask, Flask-SQLAlchemy, Gunicorn, Werkzeug ProxyFix

## Frontend CDN
- Bootstrap 5.3.0, Font Awesome 6.4.0, Chart.js, D3.js v7, Google Fonts Inter

## Cloud SDKs (optional, graceful fallback)
- AWS: boto3 (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION)
- Azure: azure-mgmt-* (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID)
- GCP: google-api-python-client (GCP_SERVICE_ACCOUNT_JSON)

## Healthcare Compliance Frameworks
- HIPAA / HITECH, HITRUST CSF, FDA SaMD, GDPR, SOC 2 Type II, NIST AI RMF
