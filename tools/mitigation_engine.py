"""
Mitigation Engine for Left<<Shift Threat Modeling System.

This module generates structured mitigation strategies based on
CVE data, CWE types, and NIST 800-53 controls.
"""

import logging
import re
from typing import Dict, List, Optional

from tools.models import ThreatRecord, MitigationStrategy

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# CWE to Mitigation Mapping
# =============================================================================

CWE_MITIGATION_MAP: Dict[str, Dict[str, List[str]]] = {
    # Injection Vulnerabilities
    "CWE-89": {  # SQL Injection
        "config_changes": [
            "Use parameterized queries or prepared statements",
            "Enable WAF SQL injection rules",
            "Disable verbose SQL error messages",
            "Use ORM with proper escaping"
        ],
        "access_controls": [
            "Apply least privilege to database accounts",
            "Restrict direct database access from web tier",
            "Implement database activity monitoring"
        ],
        "monitoring": [
            "Enable SQL query logging",
            "Alert on unusual query patterns",
            "Monitor for SQL injection signatures in logs"
        ],
        "nist_controls": ["SI-10", "SA-11", "SC-18"]
    },
    "CWE-78": {  # OS Command Injection
        "config_changes": [
            "Avoid shell command execution where possible",
            "Use allowlists for command arguments",
            "Sanitize all user input before command execution",
            "Use language-specific safe APIs"
        ],
        "access_controls": [
            "Run application with minimal OS privileges",
            "Use sandboxing/containers",
            "Implement command execution whitelist"
        ],
        "monitoring": [
            "Monitor process execution logs",
            "Alert on unusual command patterns",
            "Enable shell command auditing"
        ],
        "nist_controls": ["SI-10", "CM-7", "AC-6"]
    },
    "CWE-79": {  # Cross-Site Scripting (XSS)
        "config_changes": [
            "Enable Content Security Policy (CSP) headers",
            "Sanitize and encode all output",
            "Use HTTP-only and Secure flags for cookies",
            "Implement input validation on client and server"
        ],
        "access_controls": [
            "Implement CORS restrictions",
            "Use SameSite cookie attribute",
            "Enable X-XSS-Protection header"
        ],
        "monitoring": [
            "Monitor for XSS payloads in request logs",
            "Enable CSP violation reporting",
            "Alert on suspicious JavaScript execution"
        ],
        "nist_controls": ["SI-10", "SC-18", "SC-28"]
    },
    
    # Authentication/Authorization
    "CWE-287": {  # Improper Authentication
        "config_changes": [
            "Implement multi-factor authentication",
            "Use secure password hashing (bcrypt, Argon2)",
            "Enforce strong password policies",
            "Implement account lockout after failed attempts"
        ],
        "access_controls": [
            "Implement session management best practices",
            "Use secure token generation",
            "Enforce re-authentication for sensitive operations"
        ],
        "monitoring": [
            "Monitor failed authentication attempts",
            "Alert on brute force patterns",
            "Track session anomalies"
        ],
        "nist_controls": ["IA-2", "IA-5", "IA-8", "AC-7"]
    },
    "CWE-306": {  # Missing Authentication
        "config_changes": [
            "Implement authentication for all sensitive endpoints",
            "Use authentication middleware/interceptors",
            "Enforce authentication by default"
        ],
        "access_controls": [
            "Implement role-based access control",
            "Review and secure all API endpoints",
            "Use API gateway for authentication"
        ],
        "monitoring": [
            "Monitor for unauthenticated access to sensitive resources",
            "Alert on authentication bypass attempts"
        ],
        "nist_controls": ["IA-2", "AC-3", "AC-17"]
    },
    "CWE-269": {  # Improper Privilege Management
        "config_changes": [
            "Implement principle of least privilege",
            "Use role-based access control (RBAC)",
            "Regularly review privilege assignments"
        ],
        "access_controls": [
            "Implement privilege separation",
            "Use just-in-time privilege escalation",
            "Enforce separation of duties"
        ],
        "monitoring": [
            "Monitor privilege escalation events",
            "Alert on unauthorized privilege changes",
            "Track administrative actions"
        ],
        "nist_controls": ["AC-6", "AC-2", "CM-5"]
    },
    "CWE-639": {  # IDOR (Insecure Direct Object Reference)
        "config_changes": [
            "Implement authorization checks for all object access",
            "Use indirect object references",
            "Validate user ownership of requested resources"
        ],
        "access_controls": [
            "Implement object-level permissions",
            "Use UUIDs instead of sequential IDs",
            "Add authorization middleware"
        ],
        "monitoring": [
            "Monitor for sequential ID enumeration",
            "Alert on unauthorized object access attempts",
            "Track access patterns per user"
        ],
        "nist_controls": ["AC-3", "AC-4", "AC-6"]
    },
    
    # Data Protection
    "CWE-200": {  # Information Exposure
        "config_changes": [
            "Disable verbose error messages in production",
            "Remove sensitive data from logs",
            "Implement proper error handling",
            "Configure secure HTTP headers"
        ],
        "access_controls": [
            "Classify and protect sensitive data",
            "Implement data masking",
            "Restrict access to sensitive information"
        ],
        "monitoring": [
            "Monitor for data leakage patterns",
            "Alert on sensitive data exposure",
            "Enable DLP monitoring"
        ],
        "nist_controls": ["SC-28", "AC-3", "SI-11"]
    },
    "CWE-311": {  # Missing Encryption
        "config_changes": [
            "Enable TLS 1.2+ for all communications",
            "Encrypt sensitive data at rest",
            "Use strong encryption algorithms (AES-256)",
            "Implement proper key management"
        ],
        "access_controls": [
            "Restrict access to encryption keys",
            "Implement key rotation",
            "Use hardware security modules (HSM) for key storage"
        ],
        "monitoring": [
            "Monitor for unencrypted data transmission",
            "Alert on certificate issues",
            "Track encryption key usage"
        ],
        "nist_controls": ["SC-8", "SC-12", "SC-13", "SC-28"]
    },
    "CWE-502": {  # Insecure Deserialization
        "config_changes": [
            "Avoid deserializing untrusted data",
            "Use safe serialization formats (JSON)",
            "Implement integrity checks on serialized data",
            "Use allowlists for deserialization classes"
        ],
        "access_controls": [
            "Isolate deserialization processes",
            "Run deserialization in sandboxed environment",
            "Validate serialized data structure"
        ],
        "monitoring": [
            "Monitor for deserialization attacks",
            "Alert on unusual object creation patterns",
            "Track serialization errors"
        ],
        "nist_controls": ["SI-10", "SC-18", "SA-11"]
    },
    
    # Server-Side Vulnerabilities
    "CWE-918": {  # Server-Side Request Forgery (SSRF)
        "config_changes": [
            "Validate and sanitize all URLs",
            "Use allowlists for permitted destinations",
            "Block requests to internal/private IP ranges",
            "Disable unnecessary URL schemes"
        ],
        "access_controls": [
            "Implement network segmentation",
            "Use egress filtering",
            "Block metadata endpoints (169.254.169.254)"
        ],
        "monitoring": [
            "Monitor for internal network requests",
            "Alert on requests to blocked destinations",
            "Track outbound request patterns"
        ],
        "nist_controls": ["SC-7", "AC-4", "SI-10"]
    },
    "CWE-611": {  # XXE (XML External Entity)
        "config_changes": [
            "Disable XML external entity processing",
            "Disable DTD processing",
            "Use less complex data formats (JSON)",
            "Update XML parsers to latest versions"
        ],
        "access_controls": [
            "Restrict file system access from XML parser",
            "Implement input size limits"
        ],
        "monitoring": [
            "Monitor for XXE attack patterns",
            "Alert on XML parsing errors",
            "Track file access from web processes"
        ],
        "nist_controls": ["SI-10", "CM-7", "SC-18"]
    },
    
    # Path Traversal
    "CWE-22": {  # Path Traversal
        "config_changes": [
            "Use canonical path validation",
            "Implement allowlist for accessible directories",
            "Sanitize path separators and special characters",
            "Use chroot or containers for isolation"
        ],
        "access_controls": [
            "Restrict file system permissions",
            "Use separate user for file operations",
            "Implement jail directories"
        ],
        "monitoring": [
            "Monitor for path traversal sequences",
            "Alert on access outside allowed directories",
            "Track file access patterns"
        ],
        "nist_controls": ["AC-6", "CM-7", "SI-10"]
    },
    
    # Denial of Service
    "CWE-400": {  # Resource Exhaustion
        "config_changes": [
            "Implement request rate limiting",
            "Set resource limits (memory, CPU, connections)",
            "Configure timeouts for all operations",
            "Enable connection pooling"
        ],
        "access_controls": [
            "Use DDoS protection services",
            "Implement API quotas",
            "Enable auto-scaling"
        ],
        "monitoring": [
            "Monitor resource usage metrics",
            "Alert on resource exhaustion",
            "Track request rates and patterns"
        ],
        "nist_controls": ["SC-5", "SC-6", "CP-10"]
    },
    
    # Memory Safety
    "CWE-120": {  # Buffer Overflow
        "config_changes": [
            "Use memory-safe programming languages",
            "Enable compiler security features (ASLR, stack canaries)",
            "Use safe string functions",
            "Implement bounds checking"
        ],
        "access_controls": [
            "Enable DEP/NX bit",
            "Use sandboxing",
            "Implement process isolation"
        ],
        "monitoring": [
            "Enable crash reporting",
            "Monitor for exploitation attempts",
            "Track memory allocation patterns"
        ],
        "nist_controls": ["SI-16", "SA-11", "SC-3"]
    },
}

# Default mitigation for unknown CWEs
DEFAULT_MITIGATION = {
    "config_changes": [
        "Review and apply security patches",
        "Follow vendor security guidelines",
        "Implement defense in depth"
    ],
    "access_controls": [
        "Apply principle of least privilege",
        "Implement network segmentation",
        "Enable security monitoring"
    ],
    "monitoring": [
        "Enable comprehensive logging",
        "Implement security alerting",
        "Conduct regular security assessments"
    ],
    "nist_controls": ["CA-7", "SI-4", "RA-5"]
}

# =============================================================================
# NIST Control Descriptions
# =============================================================================

NIST_CONTROL_MAP = {
    "AC-2": "Account Management",
    "AC-3": "Access Enforcement",
    "AC-4": "Information Flow Enforcement",
    "AC-6": "Least Privilege",
    "AC-7": "Unsuccessful Logon Attempts",
    "AC-17": "Remote Access",
    "CA-7": "Continuous Monitoring",
    "CM-5": "Access Restrictions for Change",
    "CM-7": "Least Functionality",
    "CP-10": "System Recovery and Reconstitution",
    "IA-2": "Identification and Authentication",
    "IA-5": "Authenticator Management",
    "IA-8": "Identification and Authentication (Non-Organizational Users)",
    "RA-5": "Vulnerability Monitoring and Scanning",
    "SA-11": "Developer Testing and Evaluation",
    "SC-3": "Security Function Isolation",
    "SC-5": "Denial-of-Service Protection",
    "SC-6": "Resource Availability",
    "SC-7": "Boundary Protection",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-12": "Cryptographic Key Establishment and Management",
    "SC-13": "Cryptographic Protection",
    "SC-18": "Mobile Code",
    "SC-28": "Protection of Information at Rest",
    "SI-4": "System Monitoring",
    "SI-10": "Information Input Validation",
    "SI-11": "Error Handling",
    "SI-16": "Memory Protection",
}


# =============================================================================
# Mitigation Generation
# =============================================================================

def _extract_product_from_cve(threat: ThreatRecord) -> str:
    """Extract product name from CVE data."""
    # Try to extract from affected products
    affected = threat.affected_products.lower()
    
    # Common product patterns
    products = [
        "nginx", "apache", "postgresql", "mysql", "redis", "mongodb",
        "django", "flask", "spring", "express", "node.js", "docker",
        "kubernetes", "jenkins", "elasticsearch", "rabbitmq", "kafka"
    ]
    
    for product in products:
        if product in affected or product in threat.summary.lower():
            return product.title()
    
    # Fallback: try to extract from CVE description
    summary_lower = threat.summary.lower()
    for product in products:
        if product in summary_lower:
            return product.title()
    
    return "the affected software"


def _determine_attack_vector(threat: ThreatRecord) -> str:
    """Determine if the attack is remote or local based on CVSS."""
    if threat.cvss_vector:
        if "AV:N" in threat.cvss_vector:
            return "remote"
        elif "AV:L" in threat.cvss_vector:
            return "local"
        elif "AV:A" in threat.cvss_vector:
            return "adjacent_network"
    
    # Fallback: check summary for indicators
    summary_lower = threat.summary.lower()
    if any(word in summary_lower for word in ["remote", "network", "unauthenticated"]):
        return "remote"
    
    return "remote"  # Default to remote for safety


def generate_mitigation(threat: ThreatRecord) -> MitigationStrategy:
    """
    Generate a structured mitigation strategy for a CVE.
    
    Args:
        threat: ThreatRecord containing CVE information
        
    Returns:
        MitigationStrategy with detailed remediation steps
    """
    logger.debug(f"Generating mitigation for {threat.cve_id}")
    
    # Extract relevant information
    product = _extract_product_from_cve(threat)
    attack_vector = _determine_attack_vector(threat)
    cwe_id = threat.cwe_id or "UNKNOWN"
    
    # Get CWE-specific mitigations
    cwe_mitigations = CWE_MITIGATION_MAP.get(cwe_id, DEFAULT_MITIGATION)
    
    # Build primary fix
    if threat.cvss_score and threat.cvss_score >= 9.0:
        urgency = "CRITICAL: Immediate patching required. "
    elif threat.cvss_score and threat.cvss_score >= 7.0:
        urgency = "HIGH PRIORITY: "
    else:
        urgency = ""
    
    primary_fix = f"{urgency}Upgrade {product} to the latest patched version or apply vendor security patch for {threat.cve_id}"
    
    # Build configuration changes
    config_changes = list(cwe_mitigations.get("config_changes", DEFAULT_MITIGATION["config_changes"]))
    
    # Build access control changes based on attack vector
    access_controls = list(cwe_mitigations.get("access_controls", DEFAULT_MITIGATION["access_controls"]))
    
    if attack_vector == "remote":
        access_controls.extend([
            "Restrict network access to the service",
            "Implement firewall rules to limit exposure",
            "Consider placing behind VPN or internal network"
        ])
    elif attack_vector == "local":
        access_controls.extend([
            "Limit user privileges on the system",
            "Enable audit logging for local access",
            "Implement endpoint protection"
        ])
    
    # Remove duplicates while preserving order
    access_controls = list(dict.fromkeys(access_controls))
    
    # Build monitoring actions
    monitoring_actions = list(cwe_mitigations.get("monitoring", DEFAULT_MITIGATION["monitoring"]))
    monitoring_actions.append(f"Enable logging for {product}")
    monitoring_actions.append(f"Set up alerts for {threat.cve_id} exploitation attempts")
    
    # Remove duplicates
    monitoring_actions = list(dict.fromkeys(monitoring_actions))
    
    # Get NIST controls
    nist_controls = list(cwe_mitigations.get("nist_controls", DEFAULT_MITIGATION["nist_controls"]))
    
    # Build additional notes
    additional_notes = []
    
    if threat.is_actively_exploited:
        additional_notes.append(
            "WARNING: This vulnerability is in CISA's Known Exploited Vulnerabilities (KEV) catalog - "
            "active exploitation has been observed in the wild. Prioritize immediate remediation."
        )
    
    if threat.cvss_score and threat.cvss_score >= 9.0:
        additional_notes.append(
            f"CVSS Score: {threat.cvss_score} (CRITICAL) - This vulnerability poses severe risk."
        )
    
    if threat.references:
        additional_notes.append(f"Reference: {threat.references[0]}")
    
    return MitigationStrategy(
        primary_fix=primary_fix,
        configuration_changes=config_changes[:5],  # Limit to top 5
        access_control_changes=access_controls[:5],
        monitoring_actions=monitoring_actions[:4],
        nist_controls=nist_controls,
        additional_notes=additional_notes
    )


def enrich_threat_with_mitigation(threat: ThreatRecord) -> ThreatRecord:
    """
    Enrich a ThreatRecord with a generated mitigation strategy.
    
    Args:
        threat: ThreatRecord to enrich
        
    Returns:
        ThreatRecord with mitigation field populated
    """
    mitigation = generate_mitigation(threat)
    threat.mitigation = mitigation
    return threat


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "generate_mitigation",
    "enrich_threat_with_mitigation",
    "CWE_MITIGATION_MAP",
    "NIST_CONTROL_MAP",
]
