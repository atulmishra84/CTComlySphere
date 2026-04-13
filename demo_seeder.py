"""
CT ComplySphere — Demo Data Seeder
Simulates Contoso Health Systems, an Azure-deployed healthcare AI environment.
Called automatically on first startup when the database is empty.
"""
import random
import secrets
import logging
from datetime import datetime, timedelta

log = logging.getLogger(__name__)


def rnd_date(days_ago_max=90, days_ago_min=0):
    delta = random.randint(days_ago_min, days_ago_max)
    return datetime.utcnow() - timedelta(days=delta, hours=random.randint(0, 23))


AGENTS = [
    {"name": "azure-openai-clinical-gpt4",        "type": "Generative AI",        "ai_type": "GENAI",           "protocol": "rest_api",  "endpoint": "https://contoso-health-oai.openai.azure.com/openai/deployments/gpt-4",                    "version": "gpt-4-turbo-2024",    "cloud_provider": "azure", "region": "eastus",       "model_family": "GPT-4",           "risk": "HIGH",     "risk_score": 72, "phi": True,  "vulns": 5,  "owner_org": "Contoso Health Systems",           "deploy_env": "production", "deploy_method": "azure_openai_service",     "autonomy": "medium", "capabilities": ["text", "reasoning", "medical_qa"]},
    {"name": "aks-diagnostic-imaging-model",       "type": "Medical Imaging AI",   "ai_type": "TRADITIONAL_ML",  "protocol": "rest_api",  "endpoint": "http://imaging-svc.contoso-aks.svc.cluster.local:8080",                                   "version": "v3.2.1",              "cloud_provider": "azure", "region": "westeurope",   "model_family": "ResNet-50",       "risk": "CRITICAL", "risk_score": 88, "phi": True,  "vulns": 9,  "owner_org": "Radiology — Contoso",              "deploy_env": "production", "deploy_method": "kubernetes",               "autonomy": "high",   "capabilities": ["image_classification", "dicom_analysis"]},
    {"name": "azure-ml-patient-risk-scorer",       "type": "Predictive Analytics", "ai_type": "TRADITIONAL_ML",  "protocol": "rest_api",  "endpoint": "https://contoso-aml.eastus.inference.ml.azure.com/score",                                "version": "v2.4.0",              "cloud_provider": "azure", "region": "eastus",       "model_family": "XGBoost",         "risk": "HIGH",     "risk_score": 65, "phi": True,  "vulns": 4,  "owner_org": "Clinical Analytics — Contoso",     "deploy_env": "production", "deploy_method": "azure_ml_endpoint",        "autonomy": "low",    "capabilities": ["risk_scoring", "readmission_prediction"]},
    {"name": "aks-medication-reconciliation-bot",  "type": "Agentic AI",           "ai_type": "AGENTIC_AI",      "protocol": "rest_api",  "endpoint": "http://med-rec-bot.contoso-aks.svc.cluster.local:3000",                                   "version": "v1.8.3",              "cloud_provider": "azure", "region": "northeurope",  "model_family": "GPT-3.5",         "risk": "CRITICAL", "risk_score": 91, "phi": True,  "vulns": 11, "owner_org": "Pharmacy — Contoso",               "deploy_env": "production", "deploy_method": "kubernetes",               "autonomy": "high",   "capabilities": ["medication_review", "drug_interaction"]},
    {"name": "azure-cognitive-speech-transcriber", "type": "Multimodal AI",        "ai_type": "GENAI",           "protocol": "rest_api",  "endpoint": "https://contoso-speech.cognitiveservices.azure.com/speechtotext/v3.1",                    "version": "v3.1",                "cloud_provider": "azure", "region": "eastus",       "model_family": "Whisper",         "risk": "HIGH",     "risk_score": 68, "phi": True,  "vulns": 3,  "owner_org": "Clinical Documentation — Contoso", "deploy_env": "production", "deploy_method": "azure_cognitive_services",  "autonomy": "low",    "capabilities": ["speech_to_text", "clinical_notes"]},
    {"name": "aks-ehr-nlp-extractor",              "type": "NLP AI",               "ai_type": "TRADITIONAL_ML",  "protocol": "grpc",      "endpoint": "ehr-nlp.contoso-aks.svc.cluster.local:50051",                                            "version": "v4.1.0",              "cloud_provider": "azure", "region": "eastus2",      "model_family": "BioBERT",         "risk": "MEDIUM",   "risk_score": 48, "phi": True,  "vulns": 2,  "owner_org": "Health Informatics — Contoso",     "deploy_env": "production", "deploy_method": "kubernetes",               "autonomy": "low",    "capabilities": ["ner", "icd10_coding", "phi_extraction"]},
    {"name": "azure-bot-patient-triage",           "type": "Conversational AI",    "ai_type": "GENAI",           "protocol": "websocket", "endpoint": "wss://contoso-triage-bot.azurewebsites.net/api/messages",                                 "version": "v2.0.1",              "cloud_provider": "azure", "region": "westus2",      "model_family": "GPT-3.5",         "risk": "HIGH",     "risk_score": 70, "phi": True,  "vulns": 6,  "owner_org": "Patient Experience — Contoso",     "deploy_env": "production", "deploy_method": "azure_bot_service",        "autonomy": "medium", "capabilities": ["symptom_triage", "appointment_scheduling"]},
    {"name": "aks-claims-fraud-detector",          "type": "Anomaly Detection",    "ai_type": "TRADITIONAL_ML",  "protocol": "rest_api",  "endpoint": "http://fraud-det.contoso-aks.svc.cluster.local:7080",                                    "version": "v1.5.2",              "cloud_provider": "azure", "region": "eastus",       "model_family": "Isolation Forest","risk": "MEDIUM",   "risk_score": 42, "phi": False, "vulns": 1,  "owner_org": "Revenue Cycle — Contoso",          "deploy_env": "production", "deploy_method": "kubernetes",               "autonomy": "low",    "capabilities": ["anomaly_detection", "fraud_scoring"]},
    {"name": "azure-ml-drug-dosage-optimizer",     "type": "Prescriptive AI",      "ai_type": "TRADITIONAL_ML",  "protocol": "rest_api",  "endpoint": "https://dosage-opt.eastus.inference.ml.azure.com/score",                                 "version": "v3.0.0",              "cloud_provider": "azure", "region": "eastus",       "model_family": "LightGBM",        "risk": "CRITICAL", "risk_score": 95, "phi": True,  "vulns": 13, "owner_org": "Clinical Pharmacology — Contoso",  "deploy_env": "production", "deploy_method": "azure_ml_endpoint",        "autonomy": "high",   "capabilities": ["dosage_calculation", "adverse_event_pred"]},
    {"name": "aci-llm-research-summarizer",        "type": "Generative AI",        "ai_type": "GENAI",           "protocol": "rest_api",  "endpoint": "http://40.112.53.21:8080/api/summarize",                                                  "version": "v1.2.0",              "cloud_provider": "azure", "region": "westeurope",   "model_family": "LLaMA-70B",       "risk": "MEDIUM",   "risk_score": 55, "phi": False, "vulns": 3,  "owner_org": "Research & Innovation — Contoso",  "deploy_env": "staging",    "deploy_method": "azure_container_instances", "autonomy": "medium", "capabilities": ["text_summarization", "literature_review"]},
    {"name": "aks-ecg-arrhythmia-detector",        "type": "Medical AI",           "ai_type": "TRADITIONAL_ML",  "protocol": "grpc",      "endpoint": "ecg-det.contoso-aks.svc.cluster.local:50052",                                            "version": "v2.1.4",              "cloud_provider": "azure", "region": "uksouth",      "model_family": "CNN-LSTM",         "risk": "CRITICAL", "risk_score": 87, "phi": True,  "vulns": 8,  "owner_org": "Cardiology — Contoso",             "deploy_env": "production", "deploy_method": "kubernetes",               "autonomy": "high",   "capabilities": ["ecg_analysis", "arrhythmia_detection"]},
    {"name": "azure-openai-clinical-coder",        "type": "Generative AI",        "ai_type": "GENAI",           "protocol": "rest_api",  "endpoint": "https://contoso-health-oai.openai.azure.com/openai/deployments/gpt-4-coder",             "version": "gpt-4-0125-preview",  "cloud_provider": "azure", "region": "eastus",       "model_family": "GPT-4",           "risk": "HIGH",     "risk_score": 74, "phi": True,  "vulns": 5,  "owner_org": "Medical Coding — Contoso",         "deploy_env": "production", "deploy_method": "azure_openai_service",     "autonomy": "medium", "capabilities": ["icd11_coding", "cpt_coding", "hcc_risk"]},
    {"name": "aks-sepsis-early-warning",           "type": "Predictive AI",        "ai_type": "TRADITIONAL_ML",  "protocol": "rest_api",  "endpoint": "http://sepsis-warn.contoso-aks.svc.cluster.local:9090",                                  "version": "v5.0.2",              "cloud_provider": "azure", "region": "eastus",       "model_family": "Random Forest",   "risk": "CRITICAL", "risk_score": 85, "phi": True,  "vulns": 10, "owner_org": "Intensive Care — Contoso",         "deploy_env": "production", "deploy_method": "kubernetes",               "autonomy": "high",   "capabilities": ["early_warning", "vitals_analysis"]},
    {"name": "azure-databricks-genomics-ml",       "type": "Bioinformatics AI",    "ai_type": "TRADITIONAL_ML",  "protocol": "rest_api",  "endpoint": "https://adb-7788.azuredatabricks.net/model/genomics/v2/invocations",                     "version": "v2.0.0",              "cloud_provider": "azure", "region": "eastus",       "model_family": "DeepVariant",     "risk": "HIGH",     "risk_score": 63, "phi": True,  "vulns": 4,  "owner_org": "Genomics Lab — Contoso",           "deploy_env": "production", "deploy_method": "azure_databricks",         "autonomy": "medium", "capabilities": ["variant_calling", "snp_analysis", "pgx"]},
    {"name": "shadow-unregistered-chatbot-3f",     "type": "Shadow AI",            "ai_type": "GENAI",           "protocol": "rest_api",  "endpoint": "http://10.30.14.55:8765/chat",                                                           "version": "unknown",             "cloud_provider": "azure", "region": "eastus",       "model_family": "Unknown",         "risk": "CRITICAL", "risk_score": 97, "phi": True,  "vulns": 16, "owner_org": "UNKNOWN — Shadow AI",              "deploy_env": "production", "deploy_method": "unknown",                  "autonomy": "full",   "capabilities": ["uncontrolled_chat", "phi_access"]},
    {"name": "aks-mental-health-assistant",        "type": "Conversational AI",    "ai_type": "GENAI",           "protocol": "websocket", "endpoint": "wss://mental-health.contoso-aks.svc.cluster.local:8443",                                  "version": "v1.0.4",              "cloud_provider": "azure", "region": "westus2",      "model_family": "GPT-3.5-FT",      "risk": "HIGH",     "risk_score": 78, "phi": True,  "vulns": 7,  "owner_org": "Behavioral Health — Contoso",      "deploy_env": "production", "deploy_method": "kubernetes",               "autonomy": "high",   "capabilities": ["therapy_support", "crisis_detection"]},
    {"name": "azure-ml-readmission-predictor",     "type": "Predictive Analytics", "ai_type": "TRADITIONAL_ML",  "protocol": "rest_api",  "endpoint": "https://readmit-pred.eastus.inference.ml.azure.com/score",                               "version": "v3.1.0",              "cloud_provider": "azure", "region": "eastus",       "model_family": "CatBoost",        "risk": "MEDIUM",   "risk_score": 45, "phi": True,  "vulns": 2,  "owner_org": "Population Health — Contoso",      "deploy_env": "production", "deploy_method": "azure_ml_endpoint",        "autonomy": "low",    "capabilities": ["30day_readmission", "risk_stratification"]},
    {"name": "aks-pathology-slide-analyzer",       "type": "Medical Imaging AI",   "ai_type": "TRADITIONAL_ML",  "protocol": "graphql",   "endpoint": "http://pathology-ai.contoso-aks.svc.cluster.local:4000/graphql",                         "version": "v2.3.0",              "cloud_provider": "azure", "region": "northeurope",  "model_family": "ViT-B16",         "risk": "HIGH",     "risk_score": 76, "phi": True,  "vulns": 6,  "owner_org": "Pathology — Contoso",              "deploy_env": "production", "deploy_method": "kubernetes",               "autonomy": "high",   "capabilities": ["histopathology", "tumor_grading"]},
    {"name": "azure-cognitive-health-search",      "type": "Search AI",            "ai_type": "TRADITIONAL_ML",  "protocol": "rest_api",  "endpoint": "https://contoso-health-search.search.windows.net/indexes/clinical",                      "version": "2024-03-01-preview",  "cloud_provider": "azure", "region": "eastus",       "model_family": "ada-002",         "risk": "LOW",      "risk_score": 22, "phi": False, "vulns": 0,  "owner_org": "Digital Health — Contoso",         "deploy_env": "production", "deploy_method": "azure_ai_search",          "autonomy": "low",    "capabilities": ["semantic_search", "hybrid_search"]},
    {"name": "shadow-ml-model-dev-team",           "type": "Shadow AI",            "ai_type": "TRADITIONAL_ML",  "protocol": "rest_api",  "endpoint": "http://172.20.5.88:5001/predict",                                                        "version": "dev-20240301",        "cloud_provider": "azure", "region": "eastus",       "model_family": "Sklearn",         "risk": "HIGH",     "risk_score": 82, "phi": True,  "vulns": 9,  "owner_org": "UNKNOWN — Dev Shadow",             "deploy_env": "production", "deploy_method": "unknown",                  "autonomy": "medium", "capabilities": ["unregistered_pred", "phi_access"]},
    {"name": "azure-openai-claims-processor",      "type": "Generative AI",        "ai_type": "GENAI",           "protocol": "rest_api",  "endpoint": "https://contoso-health-oai.openai.azure.com/openai/deployments/gpt-4-claims",            "version": "gpt-4-0125-preview",  "cloud_provider": "azure", "region": "eastus",       "model_family": "GPT-4",           "risk": "HIGH",     "risk_score": 69, "phi": True,  "vulns": 5,  "owner_org": "Revenue Cycle — Contoso",          "deploy_env": "production", "deploy_method": "azure_openai_service",     "autonomy": "medium", "capabilities": ["claims_extraction", "denial_prediction"]},
    {"name": "aks-surgical-planning-assistant",    "type": "Agentic AI",           "ai_type": "AGENTIC_AI",      "protocol": "rest_api",  "endpoint": "http://surgical-plan.contoso-aks.svc.cluster.local:8090",                                "version": "v1.3.1",              "cloud_provider": "azure", "region": "uksouth",      "model_family": "GPT-4 Fine-tuned","risk": "CRITICAL", "risk_score": 93, "phi": True,  "vulns": 12, "owner_org": "Surgery — Contoso",                "deploy_env": "production", "deploy_method": "kubernetes",               "autonomy": "high",   "capabilities": ["surgical_planning", "risk_stratification"]},
]

RISK_LEVEL_MAP = {"LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}

VULN_BANK = {
    "CRITICAL": [
        "Unauthenticated PHI endpoint exposed to internet",
        "SQL injection in model API input layer",
        "Unencrypted PHI in model response payload",
        "Hardcoded API credentials found in container image",
        "Model weights accessible without authentication",
    ],
    "HIGH": [
        "Missing input validation on inference endpoint",
        "JWT token has no expiry configured",
        "CORS wildcard origin on PHI API",
        "Model output includes raw PHI fields",
        "No rate limiting on inference API",
    ],
    "MEDIUM": [
        "HTTP used instead of HTTPS on internal route",
        "Audit log missing for data access events",
        "Container running as root user",
        "Response caching not disabled for PHI endpoints",
        "Verbose error messages leak model architecture",
    ],
    "LOW": [
        "Missing security response headers",
        "Default timeout values not overridden",
        "No automated dependency vulnerability scanning",
    ],
}

FW_FINDINGS = {
    "HIPAA": [
        {"control": "§164.312(a)(1)", "title": "Access Control",              "status": "FAIL",    "detail": "Role-based access not enforced on model API"},
        {"control": "§164.312(e)(1)", "title": "Transmission Security",       "status": "PASS",    "detail": "TLS 1.3 configured on all endpoints"},
        {"control": "§164.308(a)(1)", "title": "Security Management Process", "status": "PARTIAL", "detail": "Risk analysis not updated in 12+ months"},
        {"control": "§164.312(b)",    "title": "Audit Controls",              "status": "FAIL",    "detail": "Model inference calls not in audit trail"},
    ],
    "HITRUST_CSF": [
        {"control": "01.a",  "title": "Access Control Policy", "status": "PASS",    "detail": "Policy documented and approved"},
        {"control": "09.aa", "title": "Monitoring System Use", "status": "FAIL",    "detail": "No Azure Monitor integration for AI workloads"},
        {"control": "10.b",  "title": "Input Data Validation", "status": "PARTIAL", "detail": "Input sanitization present but incomplete"},
    ],
    "FDA_SAMD": [
        {"control": "21 CFR Part 11",          "title": "Electronic Records",     "status": "FAIL",    "detail": "Audit trail incomplete for model decision inputs"},
        {"control": "SaMD Risk Classification", "title": "Risk Category",          "status": "PASS",    "detail": "Classified as Class II SaMD — controls appropriate"},
        {"control": "Post-Market Surveillance", "title": "Performance Monitoring", "status": "PARTIAL", "detail": "Monitoring configured but drift alerting missing"},
    ],
    "GDPR": [
        {"control": "Art. 22", "title": "Automated Decision-Making", "status": "PARTIAL", "detail": "Human oversight mechanism exists but undocumented"},
        {"control": "Art. 35", "title": "DPIA",                      "status": "FAIL",    "detail": "Data Protection Impact Assessment not completed"},
        {"control": "Art. 17", "title": "Right to Erasure",          "status": "PASS",    "detail": "Patient data deletion pipeline operational"},
    ],
    "SOC2_TYPE_II": [
        {"control": "CC6.1", "title": "Logical Access Security", "status": "PASS",    "detail": "Azure AD with MFA enforced for all operators"},
        {"control": "CC7.2", "title": "System Monitoring",       "status": "PARTIAL", "detail": "Azure Sentinel configured but AI rules missing"},
        {"control": "CC9.2", "title": "Risk Mitigation",         "status": "FAIL",    "detail": "Vendor risk assessment for OpenAI not completed"},
    ],
}

FW_BASE_SCORES = {
    "HIPAA": 72, "HITRUST_CSF": 68, "FDA_SAMD": 60, "GDPR": 75, "SOC2_TYPE_II": 80,
}


def seed_demo_data(app, db):
    from models import (
        AIAgent, AIAgentType, ScanResult, ScanStatus, RiskLevel,
        ComplianceEvaluation, ComplianceFramework,
        RegistrationPlaybook, RemediationWorkflow, RemediationTriggerType,
        AuditTrail, DeployedAgent, CustomerOnboarding, WebhookConfig,
    )

    with app.app_context():
        log.warning("Auto-seeding Contoso Health Systems demo data...")

        # ── 1. AI AGENTS ──────────────────────────────────────────────────────
        created_agents = []
        for a in AGENTS:
            existing = AIAgent.query.filter_by(name=a["name"]).first()
            if existing:
                created_agents.append(existing)
                continue
            try:
                ai_type_enum = AIAgentType[a["ai_type"]]
            except KeyError:
                ai_type_enum = AIAgentType.TRADITIONAL_ML

            agent = AIAgent(
                name=a["name"],
                type=a["type"],
                ai_type=ai_type_enum,
                protocol=a["protocol"],
                endpoint=a["endpoint"],
                version=a.get("version"),
                discovered_at=rnd_date(60, 1),
                last_scanned=rnd_date(7, 0),
                cloud_provider=a.get("cloud_provider"),
                region=a.get("region"),
                model_family=a.get("model_family"),
                capabilities=a.get("capabilities", []),
                autonomy_level=a.get("autonomy", "low"),
                planning_capability=a.get("autonomy") in ("high", "full"),
                memory_enabled=a.get("autonomy") in ("high", "full"),
                owner_organization=a.get("owner_org"),
                deployment_environment=a.get("deploy_env"),
                deployment_method=a.get("deploy_method"),
                audit_logging=random.choice([True, True, False]),
                active_sessions=random.randint(0, 50),
                agent_metadata={
                    "azure_resource_group": "contoso-health-rg",
                    "azure_subscription": "sub-contoso-prod-001",
                    "azure_tenant": "contoso-health.onmicrosoft.com",
                    "tags": {"env": a.get("deploy_env"), "team": a.get("owner_org", "").split("—")[0].strip()},
                    "encryption_at_rest": True,
                    "encryption_in_transit": random.choice([True, True, True, False]),
                    "vnet_integrated": random.choice([True, True, False]),
                },
            )
            db.session.add(agent)
            db.session.flush()
            created_agents.append(agent)
        db.session.commit()
        log.warning(f"  Seeded {len(created_agents)} AI Agents")

        # ── 2. SCAN RESULTS ───────────────────────────────────────────────────
        scan_types = ["rest_api_scan", "kubernetes_scan", "docker_scan", "vulnerability_scan", "phi_detection"]
        scan_count = 0
        for agent in created_agents:
            a_data = next((a for a in AGENTS if a["name"] == agent.name), None)
            if not a_data:
                continue
            rl_str = a_data["risk"]
            rs = a_data["risk_score"]
            vulns_n = a_data["vulns"]
            phi = a_data["phi"]
            try:
                rl = RiskLevel[rl_str]
            except KeyError:
                rl = RiskLevel.MEDIUM
            bank = VULN_BANK.get(rl_str, VULN_BANK["MEDIUM"])
            for scan_type in random.sample(scan_types, k=random.randint(2, 4)):
                vuln_details = [
                    {"severity": rl_str, "description": d, "cve": f"CVE-2024-{random.randint(10000, 99999)}"}
                    for d in random.sample(bank, min(2, max(1, vulns_n)))
                ]
                sr = ScanResult(
                    ai_agent_id=agent.id,
                    scan_type=scan_type,
                    status=ScanStatus.COMPLETED,
                    risk_score=float(rs) + random.uniform(-3, 3),
                    risk_level=rl,
                    vulnerabilities_found=vulns_n,
                    phi_exposure_detected=phi,
                    scan_duration=round(random.uniform(1.2, 45.8), 2),
                    created_at=rnd_date(30, 0),
                    scan_data={
                        "scanner": "ct-complysphere-azure",
                        "environment": "azure",
                        "tenant": "contoso-health.onmicrosoft.com",
                        "vulnerabilities": vuln_details,
                    },
                    recommendations=[
                        {"priority": "HIGH",   "action": "Enable Azure Private Endpoint for all inference APIs"},
                        {"priority": "HIGH",   "action": "Apply Azure Policy HIPAA initiative to resource group"},
                        {"priority": "MEDIUM", "action": "Enable Microsoft Defender for Cloud on AKS cluster"},
                        {"priority": "MEDIUM", "action": "Configure Azure Monitor alerts for PHI access anomalies"},
                        {"priority": "LOW",    "action": "Integrate Azure Key Vault for all model API secrets"},
                    ][:random.randint(2, 5)],
                )
                db.session.add(sr)
                scan_count += 1
        db.session.commit()
        log.warning(f"  Seeded {scan_count} Scan Results")

        # ── 3. COMPLIANCE EVALUATIONS ─────────────────────────────────────────
        eval_count = 0
        for agent in created_agents:
            a_data = next((a for a in AGENTS if a["name"] == agent.name), None)
            rl_str = a_data["risk"] if a_data else "MEDIUM"
            for fw_name, base in FW_BASE_SCORES.items():
                try:
                    fw = ComplianceFramework[fw_name]
                except KeyError:
                    continue
                adj = base - (25 if rl_str == "CRITICAL" else 12 if rl_str == "HIGH" else -15 if rl_str == "LOW" else 0)
                score = max(10, min(99, adj + random.randint(-10, 10)))
                findings = FW_FINDINGS.get(fw_name, [])
                ce = ComplianceEvaluation(
                    ai_agent_id=agent.id,
                    framework=fw,
                    compliance_score=float(score),
                    is_compliant=score >= 70,
                    findings=random.sample(findings, min(3, len(findings))),
                    recommendations=[
                        f"Enforce {fw_name} controls via Azure Policy initiative",
                        "Enable Defender for Cloud compliance dashboard",
                        "Configure Azure Monitor drift alerts",
                        "Schedule quarterly CISO review",
                    ][:random.randint(2, 4)],
                    evaluated_at=rnd_date(14, 0),
                    evaluator_version="ct-complysphere-2.0",
                )
                db.session.add(ce)
                eval_count += 1
        db.session.commit()
        log.warning(f"  Seeded {eval_count} Compliance Evaluations")

        # ── 4. REGISTRATION PLAYBOOKS ─────────────────────────────────────────
        playbooks = [
            ("Azure OpenAI HIPAA Onboarding",
             "Register and harden Azure OpenAI deployments for HIPAA compliance.",
             "1. Verify Azure BAA\n2. Enable Private Endpoint\n3. Enable Azure Diagnostics\n4. Apply Content Filtering\n5. Register in Inventory"),
            ("AKS Healthcare Workload Security Baseline",
             "Apply CIS Kubernetes benchmark and HIPAA safeguards to AKS AI workloads.",
             "1. Enable Azure Policy for AKS\n2. Enable Defender for Containers\n3. Pod Security Admission\n4. Network Policy Enforcement\n5. RBAC Hardening"),
            ("FDA SaMD Model Lifecycle Registration",
             "Ensure all SaMD AI models have audit trail and post-market surveillance configured.",
             "1. SaMD Risk Classification\n2. Design Documentation\n3. Validation Evidence\n4. Post-Market Monitoring\n5. 510(k) Evidence Package"),
            ("Shadow AI Remediation — Urgent",
             "Emergency remediation for unauthorized AI deployments.",
             "1. Network Isolation via NSG\n2. File Security Incident Report\n3. PHI Exposure Assessment\n4. Breach Notification Review\n5. Root Cause Analysis"),
            ("GDPR Data Processing AI Audit",
             "Audit AI systems for GDPR Article 35 compliance and configure right-to-erasure pipelines.",
             "1. Data Inventory Mapping\n2. Complete DPIA\n3. Verify Consent Mechanisms\n4. Test Erasure Pipeline"),
        ]
        pb_count = 0
        for name, desc, plain in playbooks:
            if not RegistrationPlaybook.query.filter_by(name=name).first():
                db.session.add(RegistrationPlaybook(
                    name=name, description=desc, plain_english_config=plain,
                    is_active=True, created_at=rnd_date(45, 10),
                ))
                pb_count += 1
        db.session.commit()
        log.warning(f"  Seeded {pb_count} Registration Playbooks")

        # ── 5. REMEDIATION WORKFLOWS ──────────────────────────────────────────
        rw_defs = [
            ("PHI Exposure — Immediate Isolation",     "Isolates any Azure AI endpoint on PHI exposure detection.",          "security"),
            ("Critical Risk Agent — Escalation",       "Escalation workflow for CRITICAL risk AI agents.",                   "compliance"),
            ("Azure Policy Non-Compliance Auto-Fix",   "Applies Azure Policy remediation tasks for HIPAA control failures.", "compliance"),
            ("Shadow AI Network Block",                "Applies Azure NSG deny rules to block detected shadow AI.",         "security"),
            ("Quarterly Compliance Report Generation", "Generates quarterly HIPAA/HITRUST reports for CISO office.",        "compliance"),
        ]
        rw_count = 0
        for name, desc, wf_type in rw_defs:
            if not RemediationWorkflow.query.filter_by(name=name).first():
                db.session.add(RemediationWorkflow(
                    name=name, description=desc, workflow_type=wf_type,
                    trigger_type=RemediationTriggerType.SCHEDULED_MAINTENANCE,
                    created_by="system",
                    actions=[
                        {"type": "notify", "target": "ciso@contoso-health.com", "template": "compliance_alert"},
                        {"type": "ticket", "system": "ServiceNow", "priority": "P1"},
                    ],
                    created_at=rnd_date(60, 10),
                ))
                rw_count += 1
        db.session.commit()
        log.warning(f"  Seeded {rw_count} Remediation Workflows")

        # ── 6. AUDIT TRAIL ────────────────────────────────────────────────────
        audit_rows = [
            ("scan",       "system",      "execute",  "scan",       "Full scan: 22 Azure AI agents evaluated — 4 CRITICAL, 9 HIGH"),
            ("compliance", "system",      "evaluate", "evaluation", "HIPAA compliance run — 14 agents non-compliant"),
            ("security",   "system",      "detect",   "agent",      "Shadow AI detected: shadow-unregistered-chatbot-3f at 10.30.14.55"),
            ("user_action","sarah.chen",  "create",   "agent",      "Registered AKS Sepsis Early Warning System in compliance inventory"),
            ("user_action","james.park",  "execute",  "playbook",   "Executed: Shadow AI Remediation — Step 1: Network Isolation"),
            ("scan",       "system",      "execute",  "scan",       "CRITICAL: aks-medication-reconciliation-bot — PHI exposure confirmed"),
            ("compliance", "azure_policy","apply",    "policy",     "HIPAA Azure Policy initiative applied to AKS cluster contoso-aks-prod"),
            ("compliance", "system",      "evaluate", "evaluation", "FDA SaMD evaluation: 4 of 6 SaMD agents require remediation"),
            ("security",   "lisa.wong",   "create",   "incident",   "Security incident #INC-2024-0847 opened for shadow AI PHI exposure"),
            ("user_action","james.park",  "execute",  "playbook",   "Azure OpenAI HIPAA Onboarding — Step 3: Enable Azure Diagnostics"),
            ("scan",       "system",      "execute",  "scan",       "Continuous scan #1203 complete — 2 new vulnerabilities discovered"),
            ("user_action","sarah.chen",  "create",   "agent",      "Registered Azure ML Patient Risk Scorer in FDA SaMD inventory"),
            ("compliance", "system",      "evaluate", "evaluation", "GDPR Art.35 DPIA flagged 3 agents requiring assessment"),
            ("system",     "system",      "heartbeat","agent",      "Heartbeat: vm-collector-weu-01 — 8 agents discovered this cycle"),
            ("security",   "system",      "detect",   "agent",      "Shadow AI: shadow-ml-model-dev-team accessing PHI without authorisation"),
        ]
        at_count = 0
        for cat, user, action, res_type, desc in audit_rows:
            at = AuditTrail(
                event_type=cat,
                event_category=cat,
                action=action,
                user_id=user,
                resource_type=res_type,
                resource_name="azure-contoso-health",
                event_description=desc,
                outcome="warning" if any(w in desc.lower() for w in ["shadow", "critical", "non-compliant", "exposure", "incident"]) else "success",
                event_data={"environment": "azure", "tenant": "contoso-health.onmicrosoft.com"},
            )
            if hasattr(at, "created_at"):
                at.created_at = rnd_date(60, 0)
            elif hasattr(at, "timestamp"):
                at.timestamp = rnd_date(60, 0)
            db.session.add(at)
            at_count += 1
        db.session.commit()
        log.warning(f"  Seeded {at_count} Audit Trail entries")

        # ── 7. DEPLOYED AGENTS (COLLECTORS) ──────────────────────────────────
        collectors = [
            ("Contoso Health Systems",           "Azure EastUS Production",     "vm-collector-eastus-01.contoso-health.com",  "10.30.0.15",  "Ubuntu 22.04 LTS",         "1.3.2", 847,  12),
            ("Contoso Health Systems",           "Azure WestEurope Production", "vm-collector-weu-01.contoso-health.com",     "10.40.0.22",  "Ubuntu 22.04 LTS",         "1.3.2", 634,   8),
            ("Contoso Health Systems",           "Azure NorthEurope AKS Node",  "aks-node-collector.contoso-aks.local",       "10.50.1.100", "Azure Linux (CBL-Mariner)", "1.3.1", 1203, 15),
            ("Contoso Health Systems",           "Azure UKSouth Cardiology",    "vm-cardio-collector-01.contoso-health.com",  "10.60.0.8",   "RHEL 8.9",                 "1.3.0", 412,   6),
            ("Contoso Health Systems — Staging", "Azure EastUS Staging",        "vm-collector-staging-01.contoso-health.com", "10.31.0.10",  "Ubuntu 22.04 LTS",         "1.2.9",  89,   4),
        ]
        coll_count = 0
        for cust, env, host, ip, os_info, ver, reports, discovered in collectors:
            if not DeployedAgent.query.filter_by(hostname=host).first():
                db.session.add(DeployedAgent(
                    agent_id=f"da-azure-{secrets.token_hex(6)}",
                    customer_name=cust,
                    environment_label=env,
                    api_token=secrets.token_hex(32),
                    status="active",
                    last_heartbeat=rnd_date(1, 0),
                    agent_version=ver,
                    hostname=host,
                    ip_address=ip,
                    os_info=os_info,
                    scan_interval_minutes=60,
                    enabled_scanners=["rest_api", "kubernetes", "docker", "grpc"],
                    scan_targets=["10.30.0.0/24", "10.40.0.0/24", "10.50.0.0/16"],
                    total_reports=reports,
                    last_report_at=rnd_date(2, 0),
                    agents_discovered_total=discovered,
                    created_at=rnd_date(90, 30),
                ))
                coll_count += 1
        db.session.commit()
        log.warning(f"  Seeded {coll_count} Collector Agents")

        # ── 8. CUSTOMER ONBOARDING ────────────────────────────────────────────
        if not CustomerOnboarding.query.filter_by(customer_id="cust-contoso-001").first():
            db.session.add(CustomerOnboarding(
                customer_id="cust-contoso-001",
                organization_name="Contoso Health Systems",
                primary_contact_email="sarah.chen@contoso-health.com",
                industry_type="healthcare",
                onboarding_status="in_progress",
                current_step="scan_configuration",
                completion_percentage=72.0,
                deployment_type="cloud",
                cloud_providers=["azure"],
                compliance_requirements=["hipaa", "hitrust", "fda_samd", "gdpr", "soc2"],
                security_level="enterprise",
                sso_enabled=True,
                mfa_enabled=True,
                api_access_enabled=True,
                steps_completed=["welcome", "basic_info", "compliance_selection", "cloud_config", "agent_deployment", "initial_scan"],
            ))
            db.session.commit()
            log.warning("  Seeded Customer Onboarding (Contoso Health Systems)")

        # ── 9. WEBHOOK CONFIGS ────────────────────────────────────────────────
        webhooks = [
            ("Azure Monitor Alert Webhook", "https://contoso-sentinel.azure.com/api/alerts/ct-complysphere",      ["rest_api", "kubernetes", "grpc"]),
            ("ServiceNow Ticketing",        "https://contoso.service-now.com/api/x_ct_comply/create_incident",   ["rest_api"]),
            ("Teams Security Channel",      "https://contoso-health.webhook.office.com/webhookb2/abc123/incoming",["rest_api", "kubernetes"]),
        ]
        wh_count = 0
        for name, url, protocols in webhooks:
            if not WebhookConfig.query.filter_by(name=name).first():
                db.session.add(WebhookConfig(
                    name=name, url=url, is_active=True,
                    protocols=protocols, scan_frequency=3600,
                    created_at=rnd_date(30, 5),
                ))
                wh_count += 1
        db.session.commit()
        log.warning(f"  Seeded {wh_count} Webhook Configs")

        total_agents = AIAgent.query.count()
        total_scans  = ScanResult.query.count()
        total_evals  = ComplianceEvaluation.query.count()
        log.warning(
            f"Demo data ready — {total_agents} agents | {total_scans} scans | {total_evals} compliance evals"
        )
