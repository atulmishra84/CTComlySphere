# Overview

Healthcare AI Compliance Platform is a comprehensive security and compliance management system designed specifically for AI agents operating in healthcare environments. The platform provides automated discovery, security scanning, risk assessment, and compliance evaluation against major healthcare frameworks including HIPAA, HITRUST CSF, FDA SaMD, GDPR, and SOC 2 Type II. It supports multiple deployment protocols (Kubernetes, Docker, REST APIs, gRPC, WebSocket, MQTT, GraphQL) and offers multi-cloud management capabilities across AWS, Azure, and GCP.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Core Technology Stack
- **Backend Framework**: Flask with SQLAlchemy ORM for database operations
- **Database**: SQLite for development with configurable PostgreSQL support via environment variables
- **Frontend**: Bootstrap-based responsive web interface with dark theme
- **Visualization**: Chart.js and D3.js for analytics dashboards and data flow diagrams

## Application Structure
- **Modular Scanner Architecture**: Protocol-specific scanners inherit from `BaseScanner` abstract class, supporting Kubernetes, Docker, REST APIs, gRPC, WebSocket, MQTT, GraphQL, and now ROS/VEX Clawbot protocols
- **Clawbot Scanner**: Dedicated scanner (`scanners/clawbot_scanner.py`) that discovers robotic AI agents via ROS network scanning, MQTT broker detection, REST endpoint fingerprinting, and VEX controller discovery
- **Compliance Engine**: Framework-agnostic evaluation system with configurable compliance rules and scoring algorithms
- **Analytics Pipeline**: Predictive analytics engine with risk scoring, trend analysis, and security forecasting
- **Multi-Cloud Support**: Abstracted cloud deployment manager supporting AWS, Azure, and GCP

## Data Models
- **AIAgent**: Core entity representing discovered AI systems with metadata, protocol information, and discovery timestamps
- **AIAgentType.CLAWBOT**: New agent type for autonomous robotic manipulators (surgical robots, lab handlers, medication dispensers, patient assist robots, rehabilitation robots)
- **ScanResult**: Security scan outcomes with risk scores, vulnerability counts, and PHI exposure detection
- **ComplianceEvaluation**: Framework-specific compliance assessments with scoring and remediation recommendations
- **Enum-based Classifications**: Standardized risk levels, scan statuses, and compliance frameworks

## Security Architecture
- **Risk Scoring Engine**: Weighted vulnerability assessment with healthcare-specific risk factors
- **PHI Detection**: Automated detection of Protected Health Information exposure
- **Continuous Monitoring**: Webhook-based continuous scanning with configurable schedules
- **Audit Trail**: Comprehensive logging and tracking of all security events and compliance changes

## Integration Points
- **Protocol Discovery**: Network scanning and service detection across multiple protocols
- **Cloud API Integration**: Native cloud provider APIs for deployment management
- **Webhook System**: Event-driven architecture for real-time monitoring and alerting

# External Dependencies

## Core Framework Dependencies
- **Flask**: Web framework with SQLAlchemy extension for database operations
- **SQLAlchemy**: ORM with declarative base model configuration
- **Werkzeug**: WSGI utilities including proxy fix middleware

## Frontend Dependencies
- **Bootstrap**: Dark theme CSS framework from Replit CDN
- **Font Awesome**: Icon library for UI components
- **Chart.js**: Data visualization library for dashboards
- **D3.js**: Advanced data visualization for network diagrams

## Cloud Provider Integrations
- **AWS Services**: Kubernetes, EC2, Lambda, and other AI/ML services
- **Azure Services**: Container instances, machine learning services
- **Google Cloud Platform**: Compute engine, AI platform services

## Protocol Support
- **Container Orchestration**: Kubernetes API, Docker daemon communication
- **Web Protocols**: HTTP/HTTPS REST APIs, WebSocket connections
- **Messaging**: MQTT broker communication, gRPC service detection
- **Query Languages**: GraphQL endpoint scanning and analysis

## Healthcare Compliance Frameworks
- **HIPAA**: Administrative, physical, and technical safeguards validation
- **HITRUST CSF**: Common Security Framework compliance assessment
- **FDA SaMD**: Software as Medical Device regulatory requirements
- **GDPR**: European data protection regulation compliance
- **SOC 2 Type II**: Service organization security controls

## Optional Integrations
- **Database**: PostgreSQL for production deployments (configurable via DATABASE_URL)
- **Monitoring**: Webhook endpoints for continuous scanning integration
- **Analytics**: Predictive modeling libraries for security trend analysis