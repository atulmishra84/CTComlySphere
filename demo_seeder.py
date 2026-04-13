"""
CT ComplySphere — Demo Data Seeder
Simulates Contoso Health Systems, an Azure-deployed healthcare AI environment.
Each section is idempotent — checks its own table before inserting.
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
        ModelVersion, ModelDeployment, ModelLineage, ModelRegistrySync,
        DataLineageNode, DataLineageEdge,
        RemediationTemplate, RemediationExecution, RemediationWorkflowStatus,
        AIAgentInventory, InventoryStatus, AgentRegistration, RegistrationStatus,
        PlaybookExecution, ExecutionStatus,
        CloudDeployment, ComplianceRule,
    )

    with app.app_context():
        log.warning("Auto-seeding Contoso Health Systems demo data (per-section)...")

        # ── 1. AI AGENTS ──────────────────────────────────────────────────────
        created_agents = []
        if AIAgent.query.count() == 0:
            for a in AGENTS:
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
        else:
            created_agents = AIAgent.query.all()
            log.warning(f"  AI Agents already seeded ({len(created_agents)} found)")

        # ── 2. SCAN RESULTS ───────────────────────────────────────────────────
        if ScanResult.query.count() == 0:
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
        if ComplianceEvaluation.query.count() == 0:
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
        playbooks_def = [
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
        created_playbooks = []
        pb_count = 0
        for name, desc, plain in playbooks_def:
            pb = RegistrationPlaybook.query.filter_by(name=name).first()
            if not pb:
                pb = RegistrationPlaybook(
                    name=name, description=desc, plain_english_config=plain,
                    is_active=True, created_at=rnd_date(45, 10),
                )
                db.session.add(pb)
                db.session.flush()
                pb_count += 1
            created_playbooks.append(pb)
        db.session.commit()
        log.warning(f"  Seeded {pb_count} Registration Playbooks (total: {len(created_playbooks)})")

        # ── 5. REMEDIATION WORKFLOWS ──────────────────────────────────────────
        rw_defs = [
            ("PHI Exposure — Immediate Isolation",     "Isolates any Azure AI endpoint on PHI exposure detection.",          "security"),
            ("Critical Risk Agent — Escalation",       "Escalation workflow for CRITICAL risk AI agents.",                   "compliance"),
            ("Azure Policy Non-Compliance Auto-Fix",   "Applies Azure Policy remediation tasks for HIPAA control failures.", "compliance"),
            ("Shadow AI Network Block",                "Applies Azure NSG deny rules to block detected shadow AI.",         "security"),
            ("Quarterly Compliance Report Generation", "Generates quarterly HIPAA/HITRUST reports for CISO office.",        "compliance"),
        ]
        created_workflows = []
        rw_count = 0
        for name, desc, wf_type in rw_defs:
            rw = RemediationWorkflow.query.filter_by(name=name).first()
            if not rw:
                rw = RemediationWorkflow(
                    name=name, description=desc, workflow_type=wf_type,
                    trigger_type=RemediationTriggerType.SCHEDULED_MAINTENANCE,
                    created_by="system",
                    actions=[
                        {"type": "notify", "target": "ciso@contoso-health.com", "template": "compliance_alert"},
                        {"type": "ticket", "system": "ServiceNow", "priority": "P1"},
                    ],
                    created_at=rnd_date(60, 10),
                )
                db.session.add(rw)
                db.session.flush()
                rw_count += 1
            created_workflows.append(rw)
        db.session.commit()
        log.warning(f"  Seeded {rw_count} Remediation Workflows (total: {len(created_workflows)})")

        # ── 6. AUDIT TRAIL ────────────────────────────────────────────────────
        if AuditTrail.query.count() == 0:
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
                    event_type=cat, event_category=cat, action=action, user_id=user,
                    resource_type=res_type, resource_name="azure-contoso-health",
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
        if DeployedAgent.query.count() == 0:
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
                        customer_name=cust, environment_label=env,
                        api_token=secrets.token_hex(32), status="active",
                        last_heartbeat=rnd_date(1, 0), agent_version=ver,
                        hostname=host, ip_address=ip, os_info=os_info,
                        scan_interval_minutes=60,
                        enabled_scanners=["rest_api", "kubernetes", "docker", "grpc"],
                        scan_targets=["10.30.0.0/24", "10.40.0.0/24", "10.50.0.0/16"],
                        total_reports=reports, last_report_at=rnd_date(2, 0),
                        agents_discovered_total=discovered, created_at=rnd_date(90, 30),
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
                sso_enabled=True, mfa_enabled=True, api_access_enabled=True,
                steps_completed=["welcome", "basic_info", "compliance_selection", "cloud_config", "agent_deployment", "initial_scan"],
            ))
            db.session.commit()
            log.warning("  Seeded Customer Onboarding (Contoso Health Systems)")

        # ── 9. WEBHOOK CONFIGS ────────────────────────────────────────────────
        if WebhookConfig.query.count() == 0:
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

        # ── 10. MODEL VERSIONS (Model Registry) ───────────────────────────────
        if ModelVersion.query.count() == 0:
            model_defs = [
                ("patient-risk-scorer",       "v3.1.0", "Production", "XGBoost",      "classification", "Clinical Analytics",       True,  False, True,  0.924, 0.911, 0.893, 0.902, 0.961,  "https://contoso-aml.eastus.inference.ml.azure.com/score"),
                ("diagnostic-imaging-v2",     "v2.3.1", "Production", "PyTorch",      "image_class",    "Radiology",                True,  True,  True,  0.971, 0.968, 0.974, 0.971, 0.995,  "http://imaging-svc.contoso-aks.svc.cluster.local:8080"),
                ("ehr-nlp-extractor",         "v4.1.0", "Production", "HuggingFace",  "nlp",            "Health Informatics",       True,  False, True,  0.887, 0.892, 0.881, 0.886, 0.942,  "ehr-nlp.contoso-aks.svc.cluster.local:50051"),
                ("drug-dosage-optimizer",     "v3.0.0", "Production", "LightGBM",     "regression",     "Clinical Pharmacology",    True,  True,  True,  0.953, 0.947, 0.958, 0.952, 0.981,  "https://dosage-opt.eastus.inference.ml.azure.com/score"),
                ("sepsis-early-warning",      "v5.0.2", "Production", "Scikit-learn", "classification", "Intensive Care",           True,  True,  True,  0.912, 0.905, 0.918, 0.911, 0.967,  "http://sepsis-warn.contoso-aks.svc.cluster.local:9090"),
                ("ecg-arrhythmia-detector",   "v2.1.4", "Production", "TensorFlow",   "classification", "Cardiology",               True,  True,  True,  0.961, 0.955, 0.967, 0.961, 0.988,  "ecg-det.contoso-aks.svc.cluster.local:50052"),
                ("readmission-predictor",     "v3.1.0", "Production", "CatBoost",     "classification", "Population Health",        True,  False, True,  0.834, 0.821, 0.847, 0.834, 0.901,  "https://readmit-pred.eastus.inference.ml.azure.com/score"),
                ("claims-fraud-detector",     "v1.5.2", "Production", "Scikit-learn", "anomaly",        "Revenue Cycle",            False, False, False, 0.891, 0.879, 0.903, 0.891, 0.945,  "http://fraud-det.contoso-aks.svc.cluster.local:7080"),
                ("pathology-slide-analyzer",  "v2.3.0", "Production", "PyTorch",      "image_class",    "Pathology",                True,  True,  True,  0.948, 0.943, 0.952, 0.948, 0.979,  "http://pathology-ai.contoso-aks.svc.cluster.local:4000"),
                ("mental-health-assistant",   "v1.0.4", "Staging",    "OpenAI API",   "nlp",            "Behavioral Health",        True,  False, True,  0.812, 0.805, 0.819, 0.812, 0.878,  "wss://mental-health.contoso-aks.svc.cluster.local:8443"),
                ("genomics-variant-caller",   "v2.0.0", "Production", "TensorFlow",   "classification", "Genomics Lab",             True,  False, True,  0.967, 0.963, 0.971, 0.967, 0.991,  "https://adb-7788.azuredatabricks.net/model/genomics/v2/invocations"),
                ("research-summarizer",       "v1.2.0", "Staging",    "LLaMA",        "nlp",            "Research & Innovation",    False, False, False, 0.776, 0.762, 0.789, 0.775, 0.843,  "http://40.112.53.21:8080/api/summarize"),
                ("medication-reconciler",     "v1.8.3", "Production", "OpenAI API",   "nlp",            "Pharmacy",                 True,  True,  True,  0.901, 0.895, 0.907, 0.901, 0.954,  "http://med-rec-bot.contoso-aks.svc.cluster.local:3000"),
                ("clinical-coder-gpt4",       "v2.0.0", "Production", "OpenAI API",   "nlp",            "Medical Coding",           True,  False, True,  0.933, 0.928, 0.938, 0.933, 0.969,  "https://contoso-health-oai.openai.azure.com/openai/deployments/gpt-4-coder"),
                ("surgical-planning-ai",      "v1.3.1", "Staging",    "PyTorch",      "classification", "Surgery",                  True,  True,  True,  0.889, 0.882, 0.896, 0.889, 0.943,  "http://surgical-plan.contoso-aks.svc.cluster.local:8090"),
            ]
            created_mvs = []
            for (mname, ver, stage, fw, mtype, team,
                 hipaa, fda, phi, acc, prec, rec, f1, auc, endpoint) in model_defs:
                mv = ModelVersion(
                    model_name=mname, version=ver, stage=stage,
                    framework=fw, model_type=mtype, owner_team=team,
                    hipaa_compliant=hipaa, fda_cleared=fda, processes_phi=phi,
                    accuracy=acc, precision=prec, recall=rec,
                    f1_score=f1, auc_roc=auc,
                    deployed_endpoint=endpoint,
                    description=f"Contoso Health Systems — {mtype} model for {team}",
                    created_by="ml-platform@contoso-health.com",
                    created_at=rnd_date(120, 10),
                    tags={"org": "contoso-health", "env": "production" if stage == "Production" else "staging"},
                )
                db.session.add(mv)
                db.session.flush()
                created_mvs.append(mv)
            db.session.commit()
            log.warning(f"  Seeded {len(created_mvs)} Model Versions")

            # ── 11. MODEL DEPLOYMENTS ──────────────────────────────────────────
            dep_count = 0
            for mv in created_mvs:
                dep = ModelDeployment(
                    model_version_id=mv.id,
                    deployment_id=f"dep-{secrets.token_hex(8)}",
                    environment="production" if mv.stage == "Production" else "staging",
                    deployment_target=random.choice(["kubernetes", "azure_ml", "azure_openai", "databricks"]),
                    endpoint_url=mv.deployed_endpoint,
                    deployment_status="active" if mv.stage == "Production" else "pending",
                    health_status="healthy" if mv.stage == "Production" else "unknown",
                    deployed_at=rnd_date(60, 5),
                    last_health_check=rnd_date(1, 0),
                    request_count=random.randint(1000, 500000),
                    error_count=random.randint(0, 150),
                    average_response_time=round(random.uniform(45.0, 850.0), 1),
                    last_prediction_time=rnd_date(0, 0),
                    compliance_scan_status="passed" if mv.hipaa_compliant else "pending",
                    audit_logs_enabled=mv.hipaa_compliant,
                )
                db.session.add(dep)
                dep_count += 1

            # ── 12. MODEL LINEAGE ──────────────────────────────────────────────
            lin_count = 0
            parent_pairs = [
                ("patient-risk-scorer", "v2.9.0"),
                ("diagnostic-imaging-v2", "v2.2.0"),
                ("sepsis-early-warning", "v4.8.1"),
            ]
            for mv in created_mvs[:8]:
                parent = next(
                    ((p, pv) for p, pv in parent_pairs if p == mv.model_name),
                    (None, None)
                )
                lin = ModelLineage(
                    model_version_id=mv.id,
                    parent_model_name=parent[0],
                    parent_model_version=parent[1],
                    training_run_id=f"run-{secrets.token_hex(8)}",
                    experiment_name=f"exp-{mv.model_name}-contoso",
                    data_sources=[
                        {"name": "Azure Blob Storage — contoso-health-data", "type": "blob", "phi": mv.processes_phi},
                        {"name": "Azure SQL — EHR Database", "type": "sql", "phi": True},
                    ],
                    feature_dependencies=["vitals", "demographics", "labs", "medications"],
                    code_version=f"git-{secrets.token_hex(5)}",
                    framework_dependencies={"python": "3.11", "cuda": "12.2"},
                    library_dependencies={"scikit-learn": "1.4", "pandas": "2.1", "numpy": "1.26"},
                    created_by="ml-platform@contoso-health.com",
                    lineage_source="azure_ml",
                )
                db.session.add(lin)
                lin_count += 1
            db.session.commit()
            log.warning(f"  Seeded {dep_count} Model Deployments, {lin_count} Model Lineage records")

        # ── 13. MODEL REGISTRY SYNC ────────────────────────────────────────────
        if ModelRegistrySync.query.count() == 0:
            syncs = [
                ("azure_ml",    "https://contoso-aml.eastus.inference.ml.azure.com", "success", 11, 0),
                ("mlflow",      "https://mlflow.contoso-health.com",                 "success",  4, 0),
                ("databricks",  "https://adb-7788.azuredatabricks.net",              "failed",   0, 1),
            ]
            for rtype, url, status, synced, failed in syncs:
                db.session.add(ModelRegistrySync(
                    registry_type=rtype, registry_url=url,
                    sync_status=status, last_sync_at=rnd_date(3, 0),
                    models_synced=synced, models_failed=failed,
                    sync_frequency="daily", auto_sync_enabled=True,
                    connection_validated=(status == "success"),
                    last_connection_check=rnd_date(1, 0),
                ))
            db.session.commit()
            log.warning("  Seeded 3 Model Registry Syncs")

        # ── 14. DATA LINEAGE NODES & EDGES ────────────────────────────────────
        if DataLineageNode.query.count() == 0:
            nodes_def = [
                ("src-ehr-epic",        "source_system",     "Epic EHR — Contoso Health",         "PHI",         "high",   False, "eastus"),
                ("src-pacs-imaging",    "source_system",     "PACS Imaging System — Radiology",    "PHI",         "high",   False, "westeurope"),
                ("src-lab-lims",        "source_system",     "LIMS — Laboratory",                  "PHI",         "medium", False, "eastus"),
                ("src-claims-db",       "source_system",     "Claims Database — Revenue Cycle",    "Financial",   "medium", False, "eastus"),
                ("src-genomics-store",  "source_system",     "Genomics Data Lake — Azure ADLS",    "PHI",         "high",   False, "eastus"),
                ("src-iot-vitals",      "source_system",     "ICU IoT Vitals Stream",              "PHI",         "high",   False, "eastus"),
                ("ag-risk-scorer",      "ai_agent",          "Patient Risk Scorer",                "PHI",         "high",   False, "eastus"),
                ("ag-imaging-model",    "ai_agent",          "Diagnostic Imaging Model",           "PHI",         "critical", False, "westeurope"),
                ("ag-nlp-extractor",    "ai_agent",          "EHR NLP Extractor",                  "PHI",         "medium",   False, "eastus2"),
                ("ag-dosage-opt",       "ai_agent",          "Drug Dosage Optimizer",              "PHI",         "critical", False, "eastus"),
                ("ag-sepsis-warn",      "ai_agent",          "Sepsis Early Warning",               "PHI",         "critical", False, "eastus"),
                ("ag-fraud-detect",     "ai_agent",          "Claims Fraud Detector",              "Financial",   "medium", False, "eastus"),
                ("ag-genomics-ml",      "ai_agent",          "Genomics Variant Caller",            "PHI",         "high",   False, "eastus"),
                ("ext-openai-azure",    "external_provider", "Azure OpenAI Service",               "Clinical",    "high",   True,  "eastus"),
                ("ext-ms-defender",     "external_provider", "Microsoft Defender for Cloud",       "Operational", "low",    True,  "global"),
                ("ext-azure-monitor",   "external_provider", "Azure Monitor & Sentinel",           "Operational", "low",    True,  "global"),
                ("out-clinical-dash",   "output_destination","Clinical Decision Dashboard",        "PHI",         "medium",   False, "eastus"),
                ("out-ciso-report",     "output_destination","CISO Compliance Reports",            "Operational", "low",     False, "eastus"),
                ("out-ehr-feedback",    "output_destination","EHR Feedback Loop — Epic",           "PHI",         "high",    False, "eastus"),
                ("out-pharmacy-sys",    "output_destination","Pharmacy Dispensing System",         "PHI",         "critical", False, "northeurope"),
            ]
            created_nodes = {}
            for node_id, ntype, name, cls, risk, is_ext, region in nodes_def:
                n = DataLineageNode(
                    node_id=node_id, node_type=ntype, name=name,
                    data_classification=cls, risk_level=risk,
                    is_external=is_ext, region=region,
                    created_at=rnd_date(90, 30),
                )
                db.session.add(n)
                created_nodes[node_id] = n
            db.session.flush()

            edges_def = [
                ("src-ehr-epic",       "ag-risk-scorer",    ["PHI","Demographics","Labs"],          5000, True,  True,  "high",   "risk_scoring",             True),
                ("src-ehr-epic",       "ag-nlp-extractor",  ["PHI","Clinical Notes"],               8200, True,  True,  "high",   "nlp_extraction",           True),
                ("src-pacs-imaging",   "ag-imaging-model",  ["PHI","DICOM Images"],                  320, True,  True,  "critical","diagnostic_imaging",       True),
                ("src-lab-lims",       "ag-risk-scorer",    ["PHI","Lab Results"],                  3100, True,  True,  "high",   "risk_enrichment",          True),
                ("src-claims-db",      "ag-fraud-detect",   ["Financial","Claims Data"],            12000, True,  False, "medium", "fraud_detection",          False),
                ("src-genomics-store", "ag-genomics-ml",    ["PHI","Genomic Sequences"],              45, True,  True,  "high",   "variant_calling",          True),
                ("src-iot-vitals",     "ag-sepsis-warn",    ["PHI","Vitals","ICU Telemetry"],       28000, True,  True,  "critical","early_warning",           True),
                ("ag-risk-scorer",     "out-clinical-dash", ["PHI","Risk Scores"],                   5000, True,  True,  "high",   "clinical_decision_support",True),
                ("ag-risk-scorer",     "out-ehr-feedback",  ["PHI","Predictions"],                   4800, True,  True,  "high",   "ehr_feedback",             True),
                ("ag-imaging-model",   "out-clinical-dash", ["PHI","Diagnoses"],                      310, True,  True,  "critical","diagnostic_output",        True),
                ("ag-nlp-extractor",   "out-ehr-feedback",  ["PHI","ICD Codes","Entities"],          7900, True,  True,  "high",   "coding_feedback",          True),
                ("ag-dosage-opt",      "out-pharmacy-sys",  ["PHI","Dosage Recommendations"],        1200, True,  True,  "critical","medication_dispensing",    True),
                ("ag-sepsis-warn",     "out-clinical-dash", ["PHI","Alerts"],                       27000, True,  True,  "critical","clinical_alerting",        True),
                ("ag-fraud-detect",    "out-ciso-report",   ["Financial","Anomalies"],               11500, True,  False, "medium", "fraud_reporting",          False),
                ("ag-genomics-ml",     "ext-ms-defender",   ["Operational","Metrics"],                 40, True,  False, "low",    "security_monitoring",      False),
                ("ag-risk-scorer",     "ext-azure-monitor", ["Operational","Telemetry"],              5000, True,  False, "low",    "observability",            False),
                ("ext-openai-azure",   "ag-nlp-extractor",  ["Clinical","Model Outputs"],             8100, True,  True,  "high",   "inference",                True),
            ]
            edge_count = 0
            for src, tgt, dtypes, vol, enc, consent, risk, purpose, baa in edges_def:
                if src in created_nodes and tgt in created_nodes:
                    e = DataLineageEdge(
                        source_node_id=src, target_node_id=tgt,
                        data_types=dtypes, daily_volume=vol,
                        encrypted=enc, consent_obtained=consent,
                        baa_signed=baa, risk_level=risk, purpose=purpose,
                        retention_days=random.choice([365, 730, 2555]),
                        last_observed=rnd_date(1, 0),
                        created_at=rnd_date(90, 30),
                    )
                    db.session.add(e)
                    edge_count += 1
            db.session.commit()
            log.warning(f"  Seeded {len(nodes_def)} Data Lineage Nodes, {edge_count} Edges")

        # ── 15. REMEDIATION TEMPLATES ─────────────────────────────────────────
        if RemediationTemplate.query.count() == 0:
            templates_def = [
                ("HIPAA Access Control Enforcement",    "compliance", "HIPAA",
                 "Enforce HIPAA §164.312(a)(1) access control requirements on AI inference endpoints.",
                 True,  False, True,  0.93, 0.91, 0.95, 0.92, 47),
                ("PHI Encryption at Rest & Transit",    "security",   "HIPAA",
                 "Apply AES-256 encryption at rest and TLS 1.3 in transit for all PHI-processing AI systems.",
                 True,  False, True,  0.98, 0.97, 0.98, 0.97, 32),
                ("FDA SaMD Audit Trail Activation",     "compliance", "FDA_SAMD",
                 "Enable complete 21 CFR Part 11 compliant audit trail for SaMD model inference calls.",
                 True,  True,  True,  0.89, 0.88, 0.91, 0.89, 18),
                ("GDPR Article 35 DPIA Automation",     "compliance", "GDPR",
                 "Automate Data Protection Impact Assessment generation for AI systems processing EU patient data.",
                 False, False, False, 0.82, 0.80, 0.84, 0.82, 12),
                ("Shadow AI Network Isolation",         "security",   "HIPAA",
                 "Immediately isolate unregistered Shadow AI systems via Azure NSG deny rules.",
                 True,  False, True,  0.97, 0.96, 0.98, 0.97, 28),
                ("Azure Policy HITRUST Deployment",     "compliance", "HITRUST_CSF",
                 "Deploy Azure Policy HITRUST CSF initiative to enforce 150+ controls on AI workloads.",
                 True,  False, True,  0.91, 0.89, 0.93, 0.91, 23),
                ("Model Drift Alerting Setup",          "security",   "SOC2_TYPE_II",
                 "Configure Azure Monitor alerts and drift detection for all production AI models.",
                 False, False, False, 0.85, 0.83, 0.87, 0.85, 15),
                ("Zero-Trust API Gateway Enforcement",  "security",   "HIPAA",
                 "Deploy Azure API Management with zero-trust policy for all AI inference APIs.",
                 True,  False, True,  0.94, 0.92, 0.96, 0.94, 9),
            ]
            for (tname, cat, fw, desc,
                 phi, fda, hipaa, acc, prec, rec, f1, usage) in templates_def:
                db.session.add(RemediationTemplate(
                    name=tname, description=desc, category=cat, framework=fw,
                    processes_phi=phi, fda_cleared=fda, hipaa_compliant=hipaa,
                    accuracy=acc, precision=prec, recall=rec, f1_score=f1,
                    usage_count=usage, created_by="ct-complysphere-system",
                    deployment_status="deployed",
                    template_config={
                        "steps": ["assess", "configure", "apply", "verify", "report"],
                        "auto_rollback": True, "requires_approval": hipaa,
                    },
                    compliance_frameworks=[fw],
                    created_at=rnd_date(90, 20),
                ))
            db.session.commit()
            log.warning(f"  Seeded {len(templates_def)} Remediation Templates")

        # ── 16. REMEDIATION EXECUTIONS ────────────────────────────────────────
        if RemediationExecution.query.count() == 0:
            exec_count = 0
            statuses = [
                RemediationWorkflowStatus.COMPLETED,
                RemediationWorkflowStatus.COMPLETED,
                RemediationWorkflowStatus.COMPLETED,
                RemediationWorkflowStatus.PARTIALLY_COMPLETED,
                RemediationWorkflowStatus.FAILED,
            ]
            for i, wf in enumerate(created_workflows[:3]):
                for agent in random.sample(created_agents[:15], k=3):
                    st = random.choice(statuses)
                    started = rnd_date(45, 2)
                    duration = random.uniform(120.0, 3600.0)
                    completed = started + timedelta(seconds=duration) if st != RemediationWorkflowStatus.FAILED else None
                    ex = RemediationExecution(
                        workflow_id=wf.id,
                        agent_id=agent.id,
                        status=st,
                        started_at=started,
                        completed_at=completed,
                        duration_seconds=duration if completed else None,
                        trigger_data={"trigger": "compliance_violation", "framework": "HIPAA", "score": random.randint(30, 65)},
                        actions_completed=[
                            {"action": "notify_ciso", "status": "success"},
                            {"action": "apply_policy", "status": "success" if st == RemediationWorkflowStatus.COMPLETED else "failed"},
                        ],
                        actions_failed=[] if st == RemediationWorkflowStatus.COMPLETED else [{"action": "apply_policy", "error": "Azure Policy API timeout"}],
                        execution_log=f"[{started}] Workflow started\n[{started}] Notifying CISO team\n[{started}] Applying Azure Policy...",
                        approval_requested=wf.requires_approval or False,
                        approval_granted_by="sarah.chen@contoso-health.com" if st == RemediationWorkflowStatus.COMPLETED else None,
                    )
                    db.session.add(ex)
                    exec_count += 1
            db.session.commit()
            log.warning(f"  Seeded {exec_count} Remediation Executions")

        # ── 17. AI AGENT INVENTORY ────────────────────────────────────────────
        if AIAgentInventory.query.count() == 0:
            inv_count = 0
            inv_statuses = [InventoryStatus.REGISTERED, InventoryStatus.REGISTERED, InventoryStatus.ACTIVE, InventoryStatus.DISCOVERED]
            departments = ["Radiology", "Pharmacy", "Clinical Analytics", "Cardiology", "ICU", "Pathology", "Revenue Cycle", "Genomics Lab", "Behavioral Health", "Surgery"]
            owners = ["sarah.chen@contoso-health.com", "james.park@contoso-health.com", "lisa.wong@contoso-health.com", "dr.patel@contoso-health.com"]
            for agent in created_agents:
                a_data = next((a for a in AGENTS if a["name"] == agent.name), None)
                if not a_data:
                    continue
                is_shadow = "Shadow" in agent.type
                status = InventoryStatus.DISCOVERED if is_shadow else random.choice(inv_statuses)
                crit = "critical" if a_data["risk"] == "CRITICAL" else "high" if a_data["risk"] == "HIGH" else "medium" if a_data["risk"] == "MEDIUM" else "low"
                db.session.add(AIAgentInventory(
                    agent_id=agent.id,
                    inventory_status=status,
                    business_owner=random.choice(owners) if not is_shadow else None,
                    technical_owner="ml-platform@contoso-health.com" if not is_shadow else None,
                    department=a_data["owner_org"].split("—")[0].strip() if "—" in a_data["owner_org"] else random.choice(departments),
                    use_case=f"AI-powered {agent.type.lower()} for Contoso Health Systems clinical operations",
                    data_classification="restricted" if a_data["phi"] else "internal",
                    criticality_level=crit,
                    regulatory_scope=["HIPAA", "FDA_SAMD"] if a_data["phi"] else ["SOC2"],
                    deployment_environment=a_data["deploy_env"],
                    cost_center="CLIN-AI-OPS-001" if not is_shadow else None,
                    budget_allocation=random.uniform(25000, 350000) if not is_shadow else None,
                    primary_classification=agent.type,
                    classification_confidence=random.uniform(0.72, 0.98),
                    applicable_frameworks=["HIPAA", "HITRUST_CSF"] + (["FDA_SAMD"] if a_data["phi"] else []),
                    required_controls=["access_control", "audit_logging", "encryption", "phi_detection"],
                    applied_controls=[] if is_shadow else ["access_control", "audit_logging", "encryption"],
                    failed_controls=["phi_detection"] if is_shadow else [],
                    added_to_inventory=rnd_date(90, 5),
                ))
                inv_count += 1
            db.session.commit()
            log.warning(f"  Seeded {inv_count} AI Agent Inventory records")

        # ── 18. AGENT REGISTRATIONS & PLAYBOOK EXECUTIONS ────────────────────
        if AgentRegistration.query.count() == 0 and created_playbooks:
            reg_count = 0
            exec_count2 = 0
            reg_statuses = [RegistrationStatus.COMPLETED, RegistrationStatus.COMPLETED, RegistrationStatus.IN_PROGRESS, RegistrationStatus.PENDING]
            exec_statuses = [ExecutionStatus.COMPLETED, ExecutionStatus.COMPLETED, ExecutionStatus.RUNNING, ExecutionStatus.FAILED]
            for agent in random.sample([a for a in created_agents if "Shadow" not in a.type], k=min(12, len(created_agents))):
                pb = random.choice(created_playbooks)
                reg_st = random.choice(reg_statuses)
                started = rnd_date(60, 2)
                reg = AgentRegistration(
                    agent_id=agent.id,
                    playbook_id=pb.id,
                    registration_status=reg_st,
                    started_at=started,
                    completed_at=started + timedelta(hours=random.randint(1, 48)) if reg_st == RegistrationStatus.COMPLETED else None,
                    onboarding_progress={"current_step": 5 if reg_st == RegistrationStatus.COMPLETED else random.randint(1, 4), "total_steps": 5},
                    compliance_status={"hipaa": "PASS" if reg_st == RegistrationStatus.COMPLETED else "PENDING", "fda": "PASS" if reg_st == RegistrationStatus.COMPLETED else "N/A"},
                )
                db.session.add(reg)
                reg_count += 1

                exec_st = ExecutionStatus.COMPLETED if reg_st == RegistrationStatus.COMPLETED else random.choice(exec_statuses)
                ex2 = PlaybookExecution(
                    playbook_id=pb.id, agent_id=agent.id,
                    execution_status=exec_st,
                    started_at=started,
                    completed_at=started + timedelta(minutes=random.randint(5, 120)) if exec_st == ExecutionStatus.COMPLETED else None,
                    execution_time=random.uniform(300, 7200) if exec_st == ExecutionStatus.COMPLETED else None,
                    step_results={"step_1": "PASS", "step_2": "PASS", "step_3": "PASS" if exec_st == ExecutionStatus.COMPLETED else "FAIL"},
                    execution_log=f"Playbook '{pb.name}' execution started for agent '{agent.name}'",
                )
                db.session.add(ex2)
                exec_count2 += 1
            db.session.commit()
            log.warning(f"  Seeded {reg_count} Agent Registrations, {exec_count2} Playbook Executions")

        # ── 19. CLOUD DEPLOYMENTS ─────────────────────────────────────────────
        if CloudDeployment.query.count() == 0:
            cloud_deps = [
                ("azure", "eastus",       "ACTIVE"),
                ("azure", "westeurope",   "ACTIVE"),
                ("azure", "northeurope",  "ACTIVE"),
                ("azure", "uksouth",      "ACTIVE"),
                ("azure", "westus2",      "ACTIVE"),
                ("aws",   "us-east-1",    "ACTIVE"),
                ("aws",   "eu-west-1",    "INACTIVE"),
                ("gcp",   "us-central1",  "INACTIVE"),
            ]
            for provider, region, status in cloud_deps:
                db.session.add(CloudDeployment(
                    provider=provider, region=region,
                    deployment_status=status,
                    last_health_check=rnd_date(1, 0),
                    created_at=rnd_date(180, 30),
                    configuration={
                        "subscription": "sub-contoso-prod-001" if provider == "azure" else f"{provider}-account-001",
                        "vnet_integrated": provider == "azure",
                        "defender_enabled": provider == "azure" and status == "ACTIVE",
                    },
                ))
            db.session.commit()
            log.warning(f"  Seeded {len(cloud_deps)} Cloud Deployments")

        # ── 20. COMPLIANCE RULES ──────────────────────────────────────────────
        if ComplianceRule.query.count() == 0:
            rules_def = [
                ("PHI Exposure Without Encryption",     "Any AI agent processing PHI must use TLS 1.2+ in transit and AES-256 at rest.", "CRITICAL", "ALERT",   ["HIPAA", "HITRUST_CSF"], [{"field": "phi_exposure_detected", "operator": "equals", "value": True}, {"field": "protocol", "operator": "not_in", "value": ["https", "grpc", "wss"]}]),
                ("Unregistered Shadow AI Detected",     "AI agents of type Shadow AI must be quarantined immediately.", "CRITICAL", "REMEDIATE", ["HIPAA"], [{"field": "type", "operator": "contains", "value": "Shadow"}]),
                ("Missing Audit Logging on PHI Agent",  "HIPAA requires audit controls on all PHI-processing AI systems.", "HIGH",     "ALERT",   ["HIPAA"], [{"field": "audit_logging", "operator": "equals", "value": False}, {"field": "phi_exposure_detected", "operator": "equals", "value": True}]),
                ("CRITICAL Risk Score Threshold",       "Any agent with risk score ≥ 85 requires immediate review.", "HIGH",     "FLAG",    ["SOC2_TYPE_II", "HITRUST_CSF"], [{"field": "risk_score", "operator": "gte", "value": 85}]),
                ("FDA SaMD Missing Classification",     "SaMD AI models must be classified per 21 CFR Part 11.", "HIGH",     "FLAG",    ["FDA_SAMD"], [{"field": "fda_cleared", "operator": "equals", "value": False}, {"field": "processes_phi", "operator": "equals", "value": True}]),
                ("Autonomous Agent PHI Access",         "Fully autonomous agents with PHI access require additional human oversight controls.", "HIGH", "ALERT", ["HIPAA", "GDPR"], [{"field": "autonomy_level", "operator": "in", "value": ["high", "full"]}, {"field": "phi_exposure_detected", "operator": "equals", "value": True}]),
                ("GDPR Automated Decision-Making",      "AI systems making automated decisions on EU patients must comply with GDPR Art. 22.", "MEDIUM", "FLAG", ["GDPR"], [{"field": "planning_capability", "operator": "equals", "value": True}]),
                ("Outdated Model Version in Production","Production models older than 6 months require re-validation.", "MEDIUM",   "ALERT",   ["FDA_SAMD", "SOC2_TYPE_II"], [{"field": "deployment_environment", "operator": "equals", "value": "production"}, {"field": "version", "operator": "contains", "value": "2023"}]),
                ("Missing BAA for External AI Provider","External AI providers processing PHI require a Business Associate Agreement.", "HIGH", "BLOCK", ["HIPAA"], [{"field": "cloud_provider", "operator": "equals", "value": "azure"}, {"field": "phi_exposure_detected", "operator": "equals", "value": True}]),
                ("Low-Risk Agent Auto-Approval",        "AI agents with risk score < 25 and no PHI may be auto-approved.", "INFO",    "FLAG",    ["SOC2_TYPE_II"], [{"field": "risk_score", "operator": "lt", "value": 25}, {"field": "phi_exposure_detected", "operator": "equals", "value": False}]),
            ]
            for (rname, desc, sev, action, fws, conditions) in rules_def:
                db.session.add(ComplianceRule(
                    name=rname, description=desc, severity=sev, action_type=action,
                    frameworks=fws, conditions=conditions,
                    is_active=True,
                    match_count=random.randint(0, 18),
                    last_run_at=rnd_date(2, 0),
                    created_at=rnd_date(60, 10),
                    condition_logic="AND",
                    action_message=f"Automated compliance action triggered: {rname}",
                ))
            db.session.commit()
            log.warning(f"  Seeded {len(rules_def)} Compliance Rules")

        total_agents = AIAgent.query.count()
        total_scans  = ScanResult.query.count()
        total_evals  = ComplianceEvaluation.query.count()
        total_mvs    = ModelVersion.query.count()
        total_nodes  = DataLineageNode.query.count()
        total_rules  = ComplianceRule.query.count()
        log.warning(
            f"Demo data ready — {total_agents} agents | {total_scans} scans | "
            f"{total_evals} evals | {total_mvs} models | "
            f"{total_nodes} lineage nodes | {total_rules} compliance rules"
        )
