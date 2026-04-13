"""
Security Inspection Engine
==========================
Performs a deep, structured security inspection of a single AI agent
across 15 security domains. Each domain returns:

  {
    'domain':        str,          # domain key
    'label':         str,          # human-readable name
    'icon':          str,          # Font Awesome class
    'status':        str,          # PASS | WARN | FAIL | UNKNOWN
    'severity':      str,          # critical | high | medium | low | info
    'score':         int,          # 0-100 domain score
    'summary':       str,          # one-line verdict
    'findings':      list[dict],   # [{text, level}]  level = ok|warn|fail
    'evidence':      dict,         # raw extracted evidence
    'remediation':   list[str],    # ordered remediation steps
  }
"""

from datetime import datetime, timedelta
import re

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_STRONG_IAM = {'oauth2', 'oidc', 'saml', 'saml2', 'mtls', 'mutual tls',
               'certificate', 'kerberos', 'azure ad', 'okta', 'aws iam',
               'google iam', 'jwt+oidc', 'ldap+mfa'}

_WEAK_IAM   = {'api key', 'api_key', 'apikey', 'basic auth', 'basic authentication',
               'http basic', 'static token', 'bearer token', 'token', 'jwt'}

_NONE_IAM   = {'none', 'unknown', '', 'n/a', 'not configured', 'not set', 'null'}

_STRONG_ENC = {'aes-256', 'aes256', 'tls 1.3', 'tls1.3', 'tls_1.3', 'strong',
               'enabled', 'full', 'e2e', 'end-to-end'}

_MEDIUM_ENC = {'tls', 'tls 1.2', 'tls1.2', 'ssl', 'aes-128', 'aes128', 'partial'}

_WEAK_ENC   = {'none', 'disabled', 'unknown', '', 'weak', 'plaintext', 'http'}


def _auth_class(method):
    if not method:
        return 'none'
    m = method.lower().strip()
    if any(k in m for k in _STRONG_IAM):
        return 'strong'
    if any(k in m for k in _WEAK_IAM):
        return 'weak'
    if m in _NONE_IAM:
        return 'none'
    return 'unknown'


def _enc_class(status):
    if not status:
        return 'none'
    s = status.lower().strip()
    if any(k in s for k in _STRONG_ENC):
        return 'strong'
    if any(k in s for k in _MEDIUM_ENC):
        return 'medium'
    if s in _WEAK_ENC:
        return 'none'
    return 'unknown'


def _controls_has(controls, *keywords):
    if not controls:
        return False
    text = str(controls).lower()
    return any(kw in text for kw in keywords)


def _measures_has(measures, *keywords):
    if not measures:
        return False
    text = str(measures).lower()
    return any(kw in text for kw in keywords)


# ---------------------------------------------------------------------------
# Domain 1 — IAM Authentication
# ---------------------------------------------------------------------------
def _inspect_iam(agent, scan, scans):
    method = agent.authentication_method or ''
    cls    = _auth_class(method)

    findings = []
    remediation = []
    score = 0

    # Detected IAM system
    findings.append({'text': f'Authentication method detected: {method or "NONE"}',
                     'level': 'ok' if cls == 'strong' else 'fail' if cls == 'none' else 'warn'})

    # Is any IAM enforced?
    if cls == 'strong':
        findings.append({'text': f'Strong IAM system in use — meets HIPAA §164.312(d)', 'level': 'ok'})
        score += 40
    elif cls == 'weak':
        findings.append({'text': 'Weak credential mechanism (API Key / Basic Auth) — no federated identity', 'level': 'warn'})
        findings.append({'text': 'API keys do not support MFA, RBAC, or automatic rotation by default', 'level': 'warn'})
        score += 20
        remediation.append('Upgrade from API Key / Basic Auth to OAuth 2.0, OIDC, or SAML 2.0')
        remediation.append('Integrate with a corporate IdP (Okta, Azure AD, AWS IAM Identity Center)')
    else:
        findings.append({'text': 'NO authentication method recorded — agent is potentially unauthenticated', 'level': 'fail'})
        score += 0
        remediation.append('Immediately enforce authentication via an IAM system (OAuth2 / OIDC recommended)')
        remediation.append('Block all unauthenticated access at the API gateway or network layer')

    # Authorization scope
    if agent.authorization_scope:
        findings.append({'text': f'Authorization scope defined: {str(agent.authorization_scope)[:80]}', 'level': 'ok'})
        score += 20
    else:
        findings.append({'text': 'No authorization scope defined — cannot verify least-privilege principle', 'level': 'fail'})
        remediation.append('Define explicit authorization scopes (OAuth scopes or IAM policies with least-privilege)')
        score += 0

    # Data access permissions
    if agent.data_access_permissions:
        perms = agent.data_access_permissions
        count = len(perms) if isinstance(perms, (list, dict)) else 1
        findings.append({'text': f'{count} data access permission(s) recorded', 'level': 'ok' if count < 6 else 'warn'})
        score += 15
    else:
        findings.append({'text': 'No data access permissions recorded in registry', 'level': 'warn'})
        remediation.append('Document all data access permissions in the agent registry (read/write/admin per resource)')
        score += 5

    # Protocol-specific notes
    proto = (agent.protocol or '').lower()
    if proto in ('kubernetes', 'k8s'):
        findings.append({'text': 'Kubernetes — verify ServiceAccount tokens are short-lived and RBAC-bound', 'level': 'warn'})
        remediation.append('Set automountServiceAccountToken: false unless required; bind RBAC policies to SA')
    elif proto in ('docker',):
        findings.append({'text': 'Docker — verify daemon is not exposed without TLS client auth', 'level': 'warn'})
    elif proto in ('rest', 'graphql', 'grpc'):
        if cls != 'strong':
            remediation.append('Enforce authentication at the API Gateway level (AWS API GW, Kong, Nginx) in addition to application code')

    status = 'PASS' if score >= 70 else 'WARN' if score >= 40 else 'FAIL'
    severity = 'critical' if cls == 'none' else 'high' if cls == 'weak' else 'low'

    return {
        'domain': 'iam_auth', 'label': 'IAM & Authentication', 'icon': 'fas fa-id-badge',
        'status': status, 'severity': severity, 'score': min(score, 100),
        'summary': f'{method or "No auth method"} — {cls.upper()} IAM posture',
        'findings': findings,
        'evidence': {'authentication_method': method, 'iam_class': cls,
                     'authorization_scope': str(agent.authorization_scope)[:120] if agent.authorization_scope else None,
                     'data_access_permissions_count': len(agent.data_access_permissions) if isinstance(agent.data_access_permissions, (list, dict)) else 0},
        'remediation': remediation,
    }


# ---------------------------------------------------------------------------
# Domain 2 — Multi-Factor Authentication
# ---------------------------------------------------------------------------
def _inspect_mfa(agent, scan, scans):
    controls = agent.compliance_controls or {}
    measures = agent.safety_measures or []

    has_mfa = (
        _controls_has(controls, 'mfa', 'multi-factor', 'two-factor', '2fa', 'totp', 'authenticator') or
        _measures_has(measures, 'mfa', 'multi-factor', 'two-factor', '2fa')
    )
    strong_auth = _auth_class(agent.authentication_method or '') == 'strong'

    findings = []
    remediation = []
    score = 0

    if has_mfa:
        findings.append({'text': 'MFA evidence found in compliance controls or safety measures', 'level': 'ok'})
        score = 90
    elif strong_auth:
        findings.append({'text': 'Strong IAM method detected but explicit MFA not confirmed', 'level': 'warn'})
        score = 50
        remediation.append('Verify MFA is enforced at the IdP level for all human users accessing this agent')
        remediation.append('Enable TOTP / FIDO2 hardware keys for privileged agent administrators')
    else:
        findings.append({'text': 'No MFA evidence found — high risk for credential compromise', 'level': 'fail'})
        score = 0
        remediation.append('Enforce MFA for all accounts that can configure, access, or modify this agent')
        remediation.append('Use TOTP apps (Google Authenticator, Authy) or hardware keys (YubiKey) minimum')
        remediation.append('Implement adaptive MFA for high-risk sessions (new device, unusual location)')

    if agent.authentication_method and 'saml' in (agent.authentication_method or '').lower():
        findings.append({'text': 'SAML SSO detected — MFA delegated to IdP (verify IdP policy)', 'level': 'ok'})
        score = max(score, 70)

    status = 'PASS' if score >= 80 else 'WARN' if score >= 40 else 'FAIL'
    return {
        'domain': 'mfa', 'label': 'Multi-Factor Authentication', 'icon': 'fas fa-mobile-alt',
        'status': status, 'severity': 'high' if score < 40 else 'medium' if score < 80 else 'low',
        'score': score,
        'summary': 'MFA confirmed' if has_mfa else ('Strong SSO (verify MFA at IdP)' if strong_auth else 'MFA NOT enforced'),
        'findings': findings,
        'evidence': {'mfa_in_controls': has_mfa, 'auth_class': _auth_class(agent.authentication_method or '')},
        'remediation': remediation,
    }


# ---------------------------------------------------------------------------
# Domain 3 — Authorization & RBAC
# ---------------------------------------------------------------------------
def _inspect_rbac(agent, scan, scans):
    controls = agent.compliance_controls or {}
    measures = agent.safety_measures or []

    has_rbac = _controls_has(controls, 'rbac', 'role-based', 'role based', 'authorization policy',
                              'abac', 'attribute-based', 'policy', 'least privilege')
    has_scope = bool(agent.authorization_scope)

    findings = []
    remediation = []
    score = 0

    if has_rbac:
        findings.append({'text': 'RBAC / authorization policy evidence found', 'level': 'ok'})
        score += 50
    else:
        findings.append({'text': 'No RBAC or authorization policy configured', 'level': 'fail'})
        remediation.append('Implement Role-Based Access Control (RBAC) — define roles: viewer, operator, admin')
        remediation.append('Enforce least-privilege: agents should only access data required for their function')

    if has_scope:
        findings.append({'text': f'Authorization scope set: {str(agent.authorization_scope)[:80]}', 'level': 'ok'})
        score += 30
    else:
        findings.append({'text': 'Authorization scope is undefined — over-permissioned access possible', 'level': 'fail'})
        remediation.append('Define explicit OAuth scopes or IAM policy documents limiting resource access')

    if agent.data_access_permissions:
        findings.append({'text': 'Data access permissions documented in registry', 'level': 'ok'})
        score += 20
    else:
        findings.append({'text': 'Data access permissions not documented', 'level': 'warn'})
        score += 5
        remediation.append('Audit and document all database, API, and file system permissions granted to this agent')

    status = 'PASS' if score >= 70 else 'WARN' if score >= 35 else 'FAIL'
    return {
        'domain': 'rbac', 'label': 'Authorization & RBAC', 'icon': 'fas fa-user-shield',
        'status': status, 'severity': 'high' if score < 35 else 'medium' if score < 70 else 'low',
        'score': min(score, 100),
        'summary': 'RBAC configured' if (has_rbac and has_scope) else 'Partial authorization controls' if (has_rbac or has_scope) else 'No authorization model',
        'findings': findings,
        'evidence': {'rbac_in_controls': has_rbac, 'scope_defined': has_scope},
        'remediation': remediation,
    }


# ---------------------------------------------------------------------------
# Domain 4 — Credential & Secret Management
# ---------------------------------------------------------------------------
def _inspect_secrets(agent, scan, scans):
    controls = agent.compliance_controls or {}
    measures = agent.safety_measures or []

    has_vault   = _controls_has(controls, 'vault', 'secret', 'key management', 'hsm', 'aws secrets', 'azure key vault', 'kms')
    has_rotation = _controls_has(controls, 'rotation', 'rotate', 'key rotation', 'token rotation', 'expiry')
    has_hardcoded_risk = not has_vault and _auth_class(agent.authentication_method or '') == 'weak'

    findings = []
    remediation = []
    score = 0

    if has_vault:
        findings.append({'text': 'Secret management / key vault integration detected', 'level': 'ok'})
        score += 40
    else:
        findings.append({'text': 'No secrets vault integration recorded — credentials may be hardcoded or in env vars', 'level': 'fail'})
        remediation.append('Integrate with HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault')
        remediation.append('Never store credentials in environment variables, config files, or source code')
        score += 0

    if has_rotation:
        findings.append({'text': 'Credential / token rotation policy documented', 'level': 'ok'})
        score += 30
    else:
        findings.append({'text': 'No credential rotation policy — stale secrets increase breach risk', 'level': 'warn'})
        remediation.append('Rotate API keys and tokens every 90 days minimum (30 days for PHI-handling agents)')
        remediation.append('Implement automatic rotation via your secrets manager or IAM lifecycle policies')
        score += 0

    if has_hardcoded_risk:
        findings.append({'text': 'API Key auth + no vault = HIGH RISK of hardcoded credentials', 'level': 'fail'})
        remediation.append('Run a secrets scanning tool (truffleHog, git-secrets) to detect hardcoded credentials in code')
        score -= 10
    else:
        score += 20

    # Check if scan found any credential-related vulnerabilities
    if scan:
        vuln_text = str(scan.vulnerabilities_found or 0)
        if scan.vulnerabilities_found and scan.vulnerabilities_found > 0:
            findings.append({'text': f'{scan.vulnerabilities_found} vulnerability/ies found in last scan — may include credential issues', 'level': 'warn'})

    score = max(0, min(score, 100))
    status = 'PASS' if score >= 70 else 'WARN' if score >= 35 else 'FAIL'
    return {
        'domain': 'secrets', 'label': 'Credential & Secret Management', 'icon': 'fas fa-key',
        'status': status, 'severity': 'critical' if score < 20 else 'high' if score < 50 else 'medium' if score < 70 else 'low',
        'score': score,
        'summary': 'Vault + rotation configured' if (has_vault and has_rotation) else 'Partial secret controls' if (has_vault or has_rotation) else 'No secret management',
        'findings': findings,
        'evidence': {'vault_detected': has_vault, 'rotation_policy': has_rotation, 'api_key_risk': has_hardcoded_risk},
        'remediation': remediation,
    }


# ---------------------------------------------------------------------------
# Domain 5 — Encryption at Rest
# ---------------------------------------------------------------------------
def _inspect_enc_rest(agent, scan, scans):
    enc = getattr(agent, 'encryption_status', None) or ''
    cls = _enc_class(enc)
    controls = agent.compliance_controls or {}

    has_enc_control = _controls_has(controls, 'encrypt', 'aes', 'at rest', 'storage encryption')

    findings = []
    remediation = []
    score = 0

    if cls == 'strong':
        findings.append({'text': f'Strong encryption at rest detected: {enc}', 'level': 'ok'})
        score = 90
    elif cls == 'medium':
        findings.append({'text': f'Moderate encryption at rest: {enc} — upgrade to AES-256 recommended', 'level': 'warn'})
        score = 60
        remediation.append('Upgrade encryption at rest to AES-256-GCM standard (HIPAA ePHI requirement)')
    elif has_enc_control:
        findings.append({'text': 'Encryption mentioned in compliance controls but encryption_status field not set', 'level': 'warn'})
        score = 40
        remediation.append('Set the encryption_status field on the agent record after verifying AES-256 at-rest encryption')
    else:
        findings.append({'text': 'No encryption at rest detected — ePHI / sensitive data is unprotected at rest', 'level': 'fail'})
        score = 0
        remediation.append('Enable AES-256 encryption for all data stores used by this agent')
        remediation.append('For databases: enable Transparent Data Encryption (TDE) on PostgreSQL/MySQL/MSSQL')
        remediation.append('For object storage: enable server-side encryption (S3-SSE-KMS, Azure Blob Encryption)')

    proto = (agent.protocol or '').lower()
    if 'kubernetes' in proto:
        findings.append({'text': 'Kubernetes: verify etcd encryption at rest is enabled for Secrets objects', 'level': 'warn'})
        remediation.append('Enable Kubernetes etcd encryption-at-rest for Secret resources (EncryptionConfiguration)')

    status = 'PASS' if score >= 80 else 'WARN' if score >= 40 else 'FAIL'
    return {
        'domain': 'enc_rest', 'label': 'Encryption at Rest', 'icon': 'fas fa-database',
        'status': status, 'severity': 'critical' if score == 0 else 'high' if score < 50 else 'medium' if score < 80 else 'low',
        'score': score,
        'summary': f'{enc or "Not configured"} — {cls.upper()}',
        'findings': findings,
        'evidence': {'encryption_status': enc, 'enc_class': cls, 'in_compliance_controls': has_enc_control},
        'remediation': remediation,
    }


# ---------------------------------------------------------------------------
# Domain 6 — Encryption in Transit
# ---------------------------------------------------------------------------
def _inspect_enc_transit(agent, scan, scans):
    enc = getattr(agent, 'encryption_status', None) or ''
    proto = (agent.protocol or '').lower()
    controls = agent.compliance_controls or {}

    tls_strong  = any(k in enc.lower() for k in ('tls 1.3', 'tls1.3', 'strong'))
    tls_ok      = any(k in enc.lower() for k in ('tls', 'ssl', 'https'))
    tls_in_ctl  = _controls_has(controls, 'tls', 'ssl', 'transit', 'https', 'mtls', 'mutual tls')

    # Protocol-specific defaults
    proto_secure = proto in ('grpc', 'webrtc', 'mqtt')  # typically use TLS by default

    findings = []
    remediation = []
    score = 0

    if tls_strong:
        findings.append({'text': 'TLS 1.3 in use — strong in-transit encryption', 'level': 'ok'})
        score = 95
    elif tls_ok or tls_in_ctl:
        findings.append({'text': 'TLS detected but version not confirmed as 1.2+ — verify cipher suites', 'level': 'warn'})
        score = 65
        remediation.append('Verify minimum TLS 1.2 (prefer TLS 1.3); disable SSLv3, TLS 1.0, TLS 1.1')
        remediation.append('Disable weak cipher suites (RC4, DES, 3DES, export ciphers)')
    elif proto_secure:
        findings.append({'text': f'{proto.upper()} protocol typically enforces TLS — verify configuration', 'level': 'warn'})
        score = 50
        remediation.append(f'Verify {proto.upper()} channel is using TLS 1.2+ and certificate validation is enabled')
    else:
        findings.append({'text': 'No TLS / in-transit encryption evidence found', 'level': 'fail'})
        score = 0
        remediation.append('Enable TLS 1.3 on all network communications for this agent')
        remediation.append('Use certificate pinning for agent-to-agent communications')
        remediation.append('Configure HSTS headers if agent serves an HTTP interface')

    # Certificate validity
    if tls_ok or tls_strong:
        findings.append({'text': 'Verify TLS certificates are from a trusted CA and are not expiring within 30 days', 'level': 'warn'})
        remediation.append('Automate certificate renewal with Let\'s Encrypt / ACM / ACME protocol')

    if proto in ('grpc',):
        findings.append({'text': 'gRPC: verify channel credentials (grpc.ssl_channel_credentials) are set — not insecure channel', 'level': 'warn'})

    status = 'PASS' if score >= 80 else 'WARN' if score >= 40 else 'FAIL'
    return {
        'domain': 'enc_transit', 'label': 'Encryption in Transit', 'icon': 'fas fa-lock',
        'status': status, 'severity': 'critical' if score == 0 else 'high' if score < 50 else 'medium' if score < 80 else 'low',
        'score': score,
        'summary': 'TLS 1.3' if tls_strong else ('TLS detected' if (tls_ok or tls_in_ctl) else 'No TLS detected'),
        'findings': findings,
        'evidence': {'tls_strong': tls_strong, 'tls_detected': tls_ok or tls_in_ctl, 'protocol': proto},
        'remediation': remediation,
    }


# ---------------------------------------------------------------------------
# Domain 7 — Network Security & Segmentation
# ---------------------------------------------------------------------------
def _inspect_network(agent, scan, scans):
    controls = agent.compliance_controls or {}
    has_network = bool(agent.network_access)
    has_firewall = _controls_has(controls, 'firewall', 'network policy', 'ingress', 'egress',
                                  'network segmentation', 'vpc', 'subnet', 'security group', 'zero trust')
    has_zt = _controls_has(controls, 'zero trust', 'zero-trust', 'ztna')

    findings = []
    remediation = []
    score = 0

    if has_zt:
        findings.append({'text': 'Zero Trust Network Access (ZTNA) posture detected', 'level': 'ok'})
        score += 40

    if has_firewall:
        findings.append({'text': 'Firewall / network policy rules documented', 'level': 'ok'})
        score += 30
    else:
        findings.append({'text': 'No firewall or network segmentation policy recorded', 'level': 'fail'})
        remediation.append('Define and enforce network policies: allow only required inbound/outbound connections')
        remediation.append('Use Kubernetes NetworkPolicy or AWS Security Groups to isolate agent traffic')

    if has_network:
        findings.append({'text': f'Network access configuration present: {str(agent.network_access)[:80]}', 'level': 'ok'})
        score += 20
    else:
        findings.append({'text': 'Network access rules not documented in agent registry', 'level': 'warn'})
        remediation.append('Document all network interfaces, ingress rules, and egress endpoints in the agent registry')
        score += 5

    proto = (agent.protocol or '').lower()
    if proto == 'kubernetes':
        findings.append({'text': 'Kubernetes: apply NetworkPolicy to restrict pod-to-pod communication', 'level': 'warn'})
        remediation.append('Apply Kubernetes NetworkPolicy with default-deny and explicit allow rules per namespace')
    elif proto == 'docker':
        findings.append({'text': 'Docker: verify custom bridge network is used (not default bridge — avoids inter-container discovery)', 'level': 'warn'})
    elif proto in ('rest', 'graphql'):
        findings.append({'text': 'REST/GraphQL: confirm API is behind a WAF (Web Application Firewall)', 'level': 'warn'})
        remediation.append('Deploy WAF rules (AWS WAF, Cloudflare, ModSecurity) to filter malicious HTTP traffic')

    score = min(score, 100)
    status = 'PASS' if score >= 70 else 'WARN' if score >= 30 else 'FAIL'
    return {
        'domain': 'network', 'label': 'Network Security & Segmentation', 'icon': 'fas fa-network-wired',
        'status': status, 'severity': 'high' if score < 30 else 'medium' if score < 70 else 'low',
        'score': score,
        'summary': 'Zero Trust + Firewall' if (has_zt and has_firewall) else 'Firewall rules present' if has_firewall else 'No network controls documented',
        'findings': findings,
        'evidence': {'network_access_defined': has_network, 'firewall_in_controls': has_firewall, 'zero_trust': has_zt},
        'remediation': remediation,
    }


# ---------------------------------------------------------------------------
# Domain 8 — Rate Limiting & Throttling
# ---------------------------------------------------------------------------
def _inspect_rate_limiting(agent, scan, scans):
    controls = agent.compliance_controls or {}
    resource_limits = agent.resource_limits or {}
    has_rate_limit = bool(resource_limits) or _controls_has(controls, 'rate limit', 'throttl', 'quota', 'request limit', 'rate-limit')

    findings = []
    remediation = []
    score = 0

    if has_rate_limit:
        findings.append({'text': 'Rate limiting / throttling controls documented', 'level': 'ok'})
        score = 80
        if isinstance(resource_limits, dict):
            for k, v in list(resource_limits.items())[:5]:
                findings.append({'text': f'Resource limit — {k}: {v}', 'level': 'ok'})
    else:
        findings.append({'text': 'No rate limiting controls found — agent is vulnerable to abuse / DDoS', 'level': 'fail'})
        score = 0
        remediation.append('Implement API rate limiting: e.g., 100 requests/min per client token')
        remediation.append('Use API Gateway rate limiting (AWS API GW, Kong, Nginx limit_req_zone)')
        remediation.append('Set per-user token bucket limits to prevent resource exhaustion attacks')

    proto = (agent.protocol or '').lower()
    if proto == 'graphql':
        findings.append({'text': 'GraphQL: verify query complexity limits and depth limiting are configured', 'level': 'warn'})
        remediation.append('Set GraphQL query depth limit (max 10) and complexity limit to prevent DoS via nested queries')
    elif proto == 'grpc':
        findings.append({'text': 'gRPC: verify max_concurrent_streams and keepalive timeout are set', 'level': 'warn'})

    if scan and scan.vulnerabilities_found and scan.vulnerabilities_found > 5:
        findings.append({'text': f'High vulnerability count ({scan.vulnerabilities_found}) may indicate uncontrolled access', 'level': 'warn'})

    status = 'PASS' if score >= 70 else 'WARN' if score >= 35 else 'FAIL'
    return {
        'domain': 'rate_limit', 'label': 'Rate Limiting & Throttling', 'icon': 'fas fa-tachometer-alt',
        'status': status, 'severity': 'high' if score < 35 else 'medium' if score < 70 else 'low',
        'score': score,
        'summary': 'Rate limits configured' if has_rate_limit else 'No rate limiting',
        'findings': findings,
        'evidence': {'rate_limit_in_controls': has_rate_limit, 'resource_limits': resource_limits},
        'remediation': remediation,
    }


# ---------------------------------------------------------------------------
# Domain 9 — Input Validation & Injection Protection
# ---------------------------------------------------------------------------
def _inspect_input_validation(agent, scan, scans):
    controls = agent.compliance_controls or {}
    measures = agent.safety_measures or []

    has_input_val = _controls_has(controls, 'input validation', 'sanitiz', 'injection', 'xss', 'sql injection',
                                   'prompt injection', 'input filter', 'schema validation')
    has_guardrails = _measures_has(measures, 'guardrail', 'prompt', 'injection', 'filter', 'sanitiz', 'validation')

    findings = []
    remediation = []
    score = 0

    if has_input_val:
        findings.append({'text': 'Input validation / injection protection controls present', 'level': 'ok'})
        score += 50
    else:
        findings.append({'text': 'No input validation controls recorded', 'level': 'fail'})
        remediation.append('Implement strict input schema validation (JSON Schema / Pydantic) on all API inputs')
        remediation.append('Validate and sanitize all user inputs to prevent SQL injection, XSS, and command injection')

    if has_guardrails:
        findings.append({'text': 'AI guardrails / prompt injection protection safety measures present', 'level': 'ok'})
        score += 30
    else:
        findings.append({'text': 'No prompt injection protection — AI agents are vulnerable to adversarial inputs', 'level': 'fail'})
        remediation.append('Implement prompt injection guardrails (system prompt isolation, input length limits, sensitive keyword filtering)')
        remediation.append('Use OWASP LLM Top 10 controls — specifically LLM01 (Prompt Injection) mitigations')

    # Check PHI-handling agents
    if scan and scan.phi_exposure_detected:
        findings.append({'text': 'PHI exposure detected in scan — injection risk is critical if PHI data is in query path', 'level': 'fail'})
        remediation.append('Audit all code paths where PHI data flows through user-controlled inputs')

    score = min(score, 100)
    status = 'PASS' if score >= 70 else 'WARN' if score >= 35 else 'FAIL'
    return {
        'domain': 'input_val', 'label': 'Input Validation & Injection', 'icon': 'fas fa-shield-alt',
        'status': status, 'severity': 'critical' if score < 20 else 'high' if score < 50 else 'medium' if score < 70 else 'low',
        'score': score,
        'summary': 'Validation + guardrails' if (has_input_val and has_guardrails) else 'Partial protection' if (has_input_val or has_guardrails) else 'No injection protection',
        'findings': findings,
        'evidence': {'input_validation_in_controls': has_input_val, 'guardrails_in_measures': has_guardrails},
        'remediation': remediation,
    }


# ---------------------------------------------------------------------------
# Domain 10 — Output Filtering & Data Masking
# ---------------------------------------------------------------------------
def _inspect_output_filtering(agent, scan, scans):
    controls = agent.compliance_controls or {}
    measures = agent.safety_measures or []

    has_masking  = _controls_has(controls, 'mask', 'redact', 'anonymi', 'de-identif', 'output filter',
                                  'data loss', 'dlp', 'pii filter', 'phi mask')
    has_phi_scan = scan and scan.phi_exposure_detected is not None

    findings = []
    remediation = []
    score = 0

    if has_masking:
        findings.append({'text': 'Data masking / redaction / DLP controls documented', 'level': 'ok'})
        score += 60
    else:
        findings.append({'text': 'No output masking or DLP controls found', 'level': 'fail'})
        remediation.append('Implement PII/PHI detection and masking in all API responses (use Presidio, AWS Macie, or regex-based filters)')
        remediation.append('Configure a Data Loss Prevention (DLP) policy to block PHI from appearing in logs or API responses')

    if scan:
        if scan.phi_exposure_detected:
            findings.append({'text': 'PHI EXPOSURE DETECTED in latest scan — immediate masking required', 'level': 'fail'})
            remediation.insert(0, 'URGENT: PHI detected in scan output — enable output masking immediately')
            score = max(0, score - 30)
        else:
            findings.append({'text': 'No PHI exposure detected in latest scan', 'level': 'ok'})
            score += 30
    else:
        findings.append({'text': 'No scan available to verify PHI exposure status', 'level': 'warn'})
        score += 10

    score = max(0, min(score, 100))
    status = 'PASS' if score >= 70 else 'WARN' if score >= 35 else 'FAIL'
    severity = 'critical' if (scan and scan.phi_exposure_detected) else 'high' if score < 35 else 'medium' if score < 70 else 'low'
    return {
        'domain': 'output_filter', 'label': 'Output Filtering & Data Masking', 'icon': 'fas fa-eye-slash',
        'status': status, 'severity': severity, 'score': score,
        'summary': 'DLP + masking configured' if has_masking else 'PHI EXPOSED' if (scan and scan.phi_exposure_detected) else 'No output filtering',
        'findings': findings,
        'evidence': {'masking_in_controls': has_masking, 'phi_exposure': scan.phi_exposure_detected if scan else None},
        'remediation': remediation,
    }


# ---------------------------------------------------------------------------
# Domain 11 — Audit Logging & Monitoring
# ---------------------------------------------------------------------------
def _inspect_audit_logging(agent, scan, scans):
    controls = agent.compliance_controls or {}
    thirty_ago = datetime.utcnow() - timedelta(days=30)
    recent_scans = [s for s in scans if s.created_at and s.created_at >= thirty_ago]

    has_audit_field    = bool(agent.audit_logging)
    has_audit_controls = _controls_has(controls, 'audit', 'log', 'monitoring', 'siem', 'splunk', 'cloudwatch', 'elk')
    has_recent_scans   = len(recent_scans) >= 3

    findings = []
    remediation = []
    score = 0

    if has_audit_field:
        findings.append({'text': 'Audit logging enabled on agent record', 'level': 'ok'})
        score += 35
    else:
        findings.append({'text': 'Audit logging NOT enabled on agent — access events not being recorded', 'level': 'fail'})
        remediation.append('Enable audit_logging on this agent and configure log shipping to a SIEM (Splunk, CloudWatch, ELK)')
        remediation.append('Log must capture: user ID, timestamp, action, resource accessed, source IP, success/failure')

    if has_audit_controls:
        findings.append({'text': 'Audit / logging system referenced in compliance controls', 'level': 'ok'})
        score += 25

    if has_recent_scans:
        findings.append({'text': f'{len(recent_scans)} scans in last 30 days — continuous monitoring active', 'level': 'ok'})
        score += 25
    elif recent_scans:
        findings.append({'text': f'Only {len(recent_scans)} scan(s) in last 30 days — increase frequency', 'level': 'warn'})
        score += 10
        remediation.append('Schedule automated scans at minimum weekly (daily for PHI-handling agents)')
    else:
        findings.append({'text': 'No scans in last 30 days — monitoring gap detected', 'level': 'fail'})
        score += 0
        remediation.append('Enable continuous monitoring: schedule automated security scans every 7 days minimum')

    findings.append({'text': 'Verify log retention policy meets requirements: HIPAA = 6 years, SOC2 = 1 year', 'level': 'warn'})
    remediation.append('Set log retention: 6 years for HIPAA, 1 year for SOC 2 — configure lifecycle policies on log storage')

    score = min(score, 100)
    status = 'PASS' if score >= 70 else 'WARN' if score >= 35 else 'FAIL'
    return {
        'domain': 'audit', 'label': 'Audit Logging & Monitoring', 'icon': 'fas fa-clipboard-list',
        'status': status, 'severity': 'high' if score < 35 else 'medium' if score < 70 else 'low',
        'score': score,
        'summary': f'Logging enabled — {len(recent_scans)} scans/30d' if has_audit_field else 'Audit logging DISABLED',
        'findings': findings,
        'evidence': {'audit_logging_field': has_audit_field, 'scans_last_30d': len(recent_scans), 'total_scans': len(scans)},
        'remediation': remediation,
    }


# ---------------------------------------------------------------------------
# Domain 12 — Vulnerability Management
# ---------------------------------------------------------------------------
def _inspect_vulns(agent, scan, scans):
    findings = []
    remediation = []
    score = 0

    if not scan:
        findings.append({'text': 'No scan results found — vulnerability status unknown', 'level': 'fail'})
        remediation.append('Run a security scan on this agent to identify vulnerabilities')
        return {
            'domain': 'vulns', 'label': 'Vulnerability Management', 'icon': 'fas fa-bug',
            'status': 'FAIL', 'severity': 'critical', 'score': 0,
            'summary': 'No scan data available',
            'findings': findings, 'evidence': {}, 'remediation': remediation,
        }

    vuln_count = scan.vulnerabilities_found or 0
    risk_score = round(scan.risk_score or 0, 1)

    findings.append({'text': f'Latest scan risk score: {risk_score}/100', 'level': 'ok' if risk_score < 40 else 'warn' if risk_score < 70 else 'fail'})
    findings.append({'text': f'Vulnerabilities found: {vuln_count}', 'level': 'ok' if vuln_count == 0 else 'warn' if vuln_count <= 3 else 'fail'})

    if vuln_count == 0:
        score = 95
        findings.append({'text': 'No vulnerabilities detected in latest scan', 'level': 'ok'})
    elif vuln_count <= 3:
        score = 70
        findings.append({'text': f'{vuln_count} low-severity vulnerability/ies — schedule remediation', 'level': 'warn'})
        remediation.append(f'Remediate {vuln_count} open vulnerability/ies identified in latest scan')
    else:
        score = max(0, 60 - (vuln_count - 3) * 5)
        findings.append({'text': f'{vuln_count} vulnerabilities open — critical remediation required', 'level': 'fail'})
        remediation.append(f'URGENT: {vuln_count} vulnerabilities — triage by CVSS score and patch within SLA')
        remediation.append('Block agent from processing PHI until critical CVEs are resolved')

    # Scan age
    if scan.created_at:
        age_days = (datetime.utcnow() - scan.created_at).days
        findings.append({'text': f'Last scanned {age_days} day(s) ago', 'level': 'ok' if age_days < 7 else 'warn' if age_days < 30 else 'fail'})
        if age_days > 30:
            remediation.append('Scan data is stale (>30 days) — run a new vulnerability scan immediately')

    status = 'PASS' if score >= 80 else 'WARN' if score >= 40 else 'FAIL'
    return {
        'domain': 'vulns', 'label': 'Vulnerability Management', 'icon': 'fas fa-bug',
        'status': status, 'severity': 'critical' if score < 20 else 'high' if score < 50 else 'medium' if score < 80 else 'low',
        'score': score,
        'summary': f'{vuln_count} vulnerabilities | Risk score {risk_score}',
        'findings': findings,
        'evidence': {'vulnerabilities_found': vuln_count, 'risk_score': risk_score,
                     'scan_date': str(scan.created_at.date()) if scan.created_at else None},
        'remediation': remediation,
    }


# ---------------------------------------------------------------------------
# Domain 13 — PHI / PII Data Protection (HIPAA)
# ---------------------------------------------------------------------------
def _inspect_phi(agent, scan, scans):
    controls = agent.compliance_controls or {}
    phi_scans = [s for s in scans if s.phi_exposure_detected]

    has_phi_control = _controls_has(controls, 'phi', 'protected health', 'pii', 'hipaa', 'de-identif', 'anonymi')

    findings = []
    remediation = []
    score = 0

    if phi_scans:
        findings.append({'text': f'PHI EXPOSURE detected in {len(phi_scans)} of {len(scans)} scan(s)', 'level': 'fail'})
        remediation.insert(0, 'CRITICAL: PHI exposure detected — initiate HIPAA breach assessment within 60 days')
        remediation.append('Identify all PHI data fields exposed and implement field-level encryption or masking')
        remediation.append('Review BAA (Business Associate Agreement) with all downstream parties')
        score = 0
    else:
        findings.append({'text': f'No PHI exposure detected across {len(scans)} scan(s)', 'level': 'ok'})
        score = 60

    if has_phi_control:
        findings.append({'text': 'PHI / HIPAA controls documented in compliance configuration', 'level': 'ok'})
        score += 30
    else:
        findings.append({'text': 'No explicit PHI/HIPAA compliance controls configured', 'level': 'warn'})
        remediation.append('Configure HIPAA compliance controls in the framework settings for this agent')

    if not scan:
        findings.append({'text': 'No scan available to assess PHI exposure — status unknown', 'level': 'warn'})
        score = 20

    score = min(score, 100)
    status = 'PASS' if score >= 80 else 'WARN' if score >= 40 else 'FAIL'
    severity = 'critical' if phi_scans else 'high' if score < 40 else 'medium' if score < 80 else 'low'
    return {
        'domain': 'phi', 'label': 'PHI / PII Data Protection', 'icon': 'fas fa-heartbeat',
        'status': status, 'severity': severity, 'score': score,
        'summary': f'PHI exposed in {len(phi_scans)} scan(s)' if phi_scans else 'No PHI exposure detected',
        'findings': findings,
        'evidence': {'phi_scans': len(phi_scans), 'total_scans': len(scans), 'hipaa_in_controls': has_phi_control},
        'remediation': remediation,
    }


# ---------------------------------------------------------------------------
# Domain 14 — Incident Response & Alerting
# ---------------------------------------------------------------------------
def _inspect_incident_response(agent, scan, scans):
    controls = agent.compliance_controls or {}
    measures = agent.safety_measures or []

    has_ir       = (_controls_has(controls, 'incident', 'response plan', 'breach', 'alert', 'notify', 'escalat') or
                    _measures_has(measures, 'incident', 'response', 'alert', 'notify', 'escalat', 'oncall'))
    has_runbook  = _controls_has(controls, 'runbook', 'playbook', 'procedure', 'sop')
    has_sla      = _controls_has(controls, 'sla', 'rto', 'rpo', 'recovery time', 'recovery point')

    findings = []
    remediation = []
    score = 0

    if has_ir:
        findings.append({'text': 'Incident response procedures found in controls or safety measures', 'level': 'ok'})
        score += 40
    else:
        findings.append({'text': 'No incident response plan documented for this agent', 'level': 'fail'})
        remediation.append('Create an Incident Response Plan: define detection, containment, eradication, recovery, and lessons-learned steps')
        remediation.append('Assign an incident owner and define escalation path (L1 → L2 → CISO)')

    if has_runbook:
        findings.append({'text': 'Runbook / operational playbook referenced', 'level': 'ok'})
        score += 25
    else:
        findings.append({'text': 'No runbook / playbook documented', 'level': 'warn'})
        remediation.append('Create operational runbooks for common failure scenarios (agent crash, PHI leak, auth bypass)')

    if has_sla:
        findings.append({'text': 'SLA / RTO / RPO targets defined', 'level': 'ok'})
        score += 20
    else:
        findings.append({'text': 'No SLA, RTO, or RPO targets defined', 'level': 'warn'})
        remediation.append('Define RTO (Recovery Time Objective) and RPO (Recovery Point Objective) for this agent')

    score = min(score, 100)
    status = 'PASS' if score >= 70 else 'WARN' if score >= 35 else 'FAIL'
    return {
        'domain': 'incident', 'label': 'Incident Response & Alerting', 'icon': 'fas fa-bell',
        'status': status, 'severity': 'high' if score < 35 else 'medium' if score < 70 else 'low',
        'score': score,
        'summary': 'IR plan + runbook defined' if (has_ir and has_runbook) else 'Partial IR controls' if has_ir else 'No incident response plan',
        'findings': findings,
        'evidence': {'ir_in_controls': has_ir, 'runbook_present': has_runbook, 'sla_defined': has_sla},
        'remediation': remediation,
    }


# ---------------------------------------------------------------------------
# Domain 15 — Resource & Privilege Management
# ---------------------------------------------------------------------------
def _inspect_privilege(agent, scan, scans):
    controls = agent.compliance_controls or {}
    measures = agent.safety_measures or []

    has_limits    = bool(agent.resource_limits)
    has_pam       = _controls_has(controls, 'privileged access', 'pam', 'just-in-time', 'jit access',
                                   'privilege escalation', 'sudo', 'root', 'admin access')
    has_safety    = bool(agent.safety_measures)

    findings = []
    remediation = []
    score = 0

    if has_limits:
        limits = agent.resource_limits
        findings.append({'text': f'Resource limits defined: {str(limits)[:100]}', 'level': 'ok'})
        score += 35
    else:
        findings.append({'text': 'No CPU, memory, or rate limits set — agent can consume unbounded resources', 'level': 'fail'})
        remediation.append('Set resource requests and limits (CPU: 500m, Memory: 512Mi) in Kubernetes manifests or Docker Compose')
        remediation.append('Implement rate limits to prevent resource exhaustion attacks')

    if has_pam:
        findings.append({'text': 'Privileged access management (PAM) controls present', 'level': 'ok'})
        score += 35
    else:
        findings.append({'text': 'No privileged access management controls documented', 'level': 'warn'})
        remediation.append('Implement Just-In-Time (JIT) privileged access — no standing admin access')
        remediation.append('Use CyberArk, BeyondTrust, or AWS IAM Roles for temporary elevated permissions')

    if has_safety:
        measures = agent.safety_measures if isinstance(agent.safety_measures, list) else list(agent.safety_measures)
        findings.append({'text': f'{len(measures)} safety measure(s) configured', 'level': 'ok'})
        score += 20
    else:
        findings.append({'text': 'No safety measures configured', 'level': 'warn'})
        remediation.append('Configure safety guardrails: output filters, kill switches, and human-in-the-loop checkpoints')

    proto = (agent.protocol or '').lower()
    if proto == 'kubernetes':
        findings.append({'text': 'Kubernetes: verify Pod Security Standards (PSS) — use "restricted" profile, not "privileged"', 'level': 'warn'})
        remediation.append('Apply PodSecurityAdmission with "restricted" enforcement and disable privilege escalation: allowPrivilegeEscalation: false')
    elif proto == 'docker':
        findings.append({'text': 'Docker: verify container does not run as root (USER directive in Dockerfile)', 'level': 'warn'})
        remediation.append('Add "USER nonroot" in Dockerfile and use --read-only filesystem flag')

    score = min(score, 100)
    status = 'PASS' if score >= 70 else 'WARN' if score >= 35 else 'FAIL'
    return {
        'domain': 'privilege', 'label': 'Resource & Privilege Management', 'icon': 'fas fa-user-lock',
        'status': status, 'severity': 'high' if score < 35 else 'medium' if score < 70 else 'low',
        'score': score,
        'summary': 'Resource limits + PAM configured' if (has_limits and has_pam) else 'Partial controls' if (has_limits or has_pam) else 'No resource / privilege controls',
        'findings': findings,
        'evidence': {'resource_limits_set': has_limits, 'pam_in_controls': has_pam, 'safety_measures_count': len(agent.safety_measures) if isinstance(agent.safety_measures, (list, set)) else 0},
        'remediation': remediation,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_DOMAIN_CHECKERS = [
    _inspect_iam,
    _inspect_mfa,
    _inspect_rbac,
    _inspect_secrets,
    _inspect_enc_rest,
    _inspect_enc_transit,
    _inspect_network,
    _inspect_rate_limiting,
    _inspect_input_validation,
    _inspect_output_filtering,
    _inspect_audit_logging,
    _inspect_vulns,
    _inspect_phi,
    _inspect_incident_response,
    _inspect_privilege,
]

_SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
_STATUS_SCORE   = {'PASS': 100, 'WARN': 50, 'FAIL': 0, 'UNKNOWN': 0}


def run_security_inspection(agent, ScanResult):
    """
    Run all 15 security domain checks for a given agent.
    Returns a structured report dict.
    """
    scans = ScanResult.query.filter_by(ai_agent_id=agent.id).order_by(ScanResult.created_at).all()
    latest_scan = scans[-1] if scans else None

    domains = []
    for checker in _DOMAIN_CHECKERS:
        try:
            result = checker(agent, latest_scan, scans)
        except Exception as exc:
            result = {
                'domain': checker.__name__, 'label': checker.__name__,
                'icon': 'fas fa-exclamation-triangle',
                'status': 'UNKNOWN', 'severity': 'info', 'score': 0,
                'summary': f'Check error: {exc}',
                'findings': [{'text': str(exc), 'level': 'warn'}],
                'evidence': {}, 'remediation': [],
            }
        domains.append(result)

    # Sort: FAIL first, then WARN, then PASS; within same status by severity
    domains.sort(key=lambda d: (_STATUS_SCORE.get(d['status'], 0),
                                 _SEVERITY_ORDER.get(d['severity'], 4)))

    total_score   = round(sum(d['score'] for d in domains) / len(domains)) if domains else 0
    fail_count    = sum(1 for d in domains if d['status'] == 'FAIL')
    warn_count    = sum(1 for d in domains if d['status'] == 'WARN')
    pass_count    = sum(1 for d in domains if d['status'] == 'PASS')
    critical_count = sum(1 for d in domains if d['severity'] == 'critical')

    # All critical-severity findings across all domains
    all_criticals = []
    for d in domains:
        if d['severity'] in ('critical', 'high'):
            for f in d['findings']:
                if f['level'] == 'fail':
                    all_criticals.append({'domain': d['label'], 'text': f['text']})

    posture = 'Critical' if total_score < 30 else 'Poor' if total_score < 50 else 'Fair' if total_score < 70 else 'Good' if total_score < 85 else 'Excellent'

    return {
        'agent': agent,
        'domains': domains,
        'total_score': total_score,
        'posture': posture,
        'fail_count': fail_count,
        'warn_count': warn_count,
        'pass_count': pass_count,
        'critical_count': critical_count,
        'all_criticals': all_criticals,
        'generated_at': datetime.utcnow(),
        'scan_count': len(scans),
        'latest_scan': latest_scan,
    }
