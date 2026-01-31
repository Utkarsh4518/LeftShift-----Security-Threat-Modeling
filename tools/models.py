"""
Core Architecture Models for Left<<Shift Threat Modeling System.

This module defines Pydantic models for representing software architecture
components, data flows, trust boundaries, threats, and attack paths used in threat analysis.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


# =============================================================================
# Architecture Models
# =============================================================================

class Component(BaseModel):
    """
    Represents an architecture component in the system.
    
    Components are the building blocks of a software architecture,
    such as databases, web servers, APIs, or microservices.
    """
    
    name: str = Field(
        ...,
        description="Unique identifier for the component (e.g., 'Primary Database', 'Auth Service')"
    )
    type: str = Field(
        ...,
        description="Category of the component (e.g., 'Database', 'Web Server', 'API Gateway', 'Microservice')"
    )


class DataFlow(BaseModel):
    """
    Represents a data flow between components in the architecture.
    
    Data flows describe how information moves between components,
    including the communication protocol used.
    """
    
    source: str = Field(
        ...,
        description="Name of the source component where data originates"
    )
    destination: str = Field(
        ...,
        description="Name of the destination component where data is sent"
    )
    protocol: str = Field(
        ...,
        description="Communication protocol used (e.g., 'HTTPS', 'TCP/5432', 'gRPC', 'AMQP')"
    )


class ArchitectureSchema(BaseModel):
    """
    Generalized schema representing a complete software architecture.
    
    This model aggregates components, data flows, and trust boundaries
    to provide a comprehensive view of the system for threat modeling.
    """
    
    project_name: str = Field(
        default="Untitled Project",
        description="Name of the project or system being modeled"
    )
    description: str = Field(
        ...,
        description="Brief description of the architecture and its purpose"
    )
    components: List[Component] = Field(
        default_factory=list,
        description="List of architecture components in the system"
    )
    data_flows: List[DataFlow] = Field(
        default_factory=list,
        description="List of data flows between components"
    )
    trust_boundaries: List[str] = Field(
        default_factory=list,
        description="List of trust boundary names (e.g., 'Internet', 'DMZ', 'Internal Network', 'Database Zone')"
    )


# =============================================================================
# Threat Models (CVE Data)
# =============================================================================

class MitigationStrategy(BaseModel):
    """
    Represents a comprehensive mitigation strategy for a threat or vulnerability.
    
    Includes primary fixes, configuration changes, access controls,
    monitoring actions, and relevant NIST controls.
    """
    
    primary_fix: str = Field(
        ...,
        description="Primary remediation action to address the vulnerability"
    )
    configuration_changes: List[str] = Field(
        default_factory=list,
        description="List of configuration changes required"
    )
    access_control_changes: List[str] = Field(
        default_factory=list,
        description="List of access control modifications needed"
    )
    monitoring_actions: List[str] = Field(
        default_factory=list,
        description="List of monitoring and detection actions to implement"
    )
    nist_controls: List[str] = Field(
        default_factory=list,
        description="Relevant NIST security controls (e.g., ['SI-2', 'AC-3', 'CM-6'])"
    )
    additional_notes: List[str] = Field(
        default_factory=list,
        description="Additional notes or recommendations"
    )


class ThreatRecord(BaseModel):
    """
    Represents a threat record, typically sourced from CVE databases.
    
    Contains vulnerability information including severity, affected products,
    exploitation status, and mitigation strategies.
    """
    
    cve_id: str = Field(
        ...,
        description="CVE identifier (e.g., 'CVE-2024-12345')"
    )
    summary: str = Field(
        ...,
        description="Brief description of the vulnerability"
    )
    severity: str = Field(
        ...,
        description="Severity level: CRITICAL, HIGH, MEDIUM, or LOW"
    )
    affected_products: str = Field(
        ...,
        description="Products or software affected by this vulnerability"
    )
    is_actively_exploited: bool = Field(
        default=False,
        description="Whether the vulnerability is known to be actively exploited in the wild"
    )
    source: str = Field(
        ...,
        description="Data source (e.g., 'NVD', 'CISA KEV')"
    )
    cvss_vector: Optional[str] = Field(
        default=None,
        description="CVSS vector string (e.g., 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')"
    )
    cvss_score: Optional[float] = Field(
        default=None,
        description="CVSS base score (0.0 - 10.0)"
    )
    cwe_id: Optional[str] = Field(
        default=None,
        description="Associated CWE identifier (e.g., 'CWE-79')"
    )
    references: List[str] = Field(
        default_factory=list,
        description="List of reference URLs for additional information"
    )
    mitigation: Optional[MitigationStrategy] = Field(
        default=None,
        description="Detailed mitigation strategy for this threat"
    )
    relevance_status: Optional[str] = Field(
        default=None,
        description="Relevance to the target architecture (e.g., 'Relevant', 'Not Applicable')"
    )
    prerequisites: Optional[str] = Field(
        default=None,
        description="Prerequisites required for exploitation"
    )
    exploitability: Optional[str] = Field(
        default=None,
        description="Ease of exploitation (e.g., 'Easy', 'Moderate', 'Difficult')"
    )
    likelihood: Optional[str] = Field(
        default=None,
        description="Likelihood of exploitation (e.g., 'High', 'Medium', 'Low')"
    )
    justification: Optional[str] = Field(
        default=None,
        description="Justification for relevance or risk assessment"
    )


# Alias for convenience
CVE = ThreatRecord


# =============================================================================
# STRIDE Threat Models
# =============================================================================

class ArchitecturalThreat(BaseModel):
    """
    Represents a threat identified through STRIDE analysis.
    
    STRIDE categories: Spoofing, Tampering, Repudiation, Information Disclosure,
    Denial of Service, Elevation of Privilege.
    """
    
    threat_id: str = Field(
        ...,
        description="Unique threat identifier (e.g., 'T-001')"
    )
    category: str = Field(
        ...,
        description="STRIDE category: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, or Elevation of Privilege"
    )
    description: str = Field(
        ...,
        description="Detailed description of the threat scenario"
    )
    affected_component: str = Field(
        ...,
        description="Name of the component affected by this threat"
    )
    affected_asset: Optional[str] = Field(
        default=None,
        description="Specific asset within the component that is affected"
    )
    trust_boundary: Optional[str] = Field(
        default=None,
        description="Trust boundary where this threat is relevant"
    )
    severity: str = Field(
        ...,
        description="Severity level: Critical, High, Medium, or Low"
    )
    mitigation_steps: List[str] = Field(
        default_factory=list,
        description="List of recommended mitigation steps"
    )
    preconditions: List[str] = Field(
        default_factory=list,
        description="Conditions that must be met for the threat to be exploitable"
    )
    impact: Optional[str] = Field(
        default=None,
        description="Potential impact if the threat is realized"
    )
    example: Optional[str] = Field(
        default=None,
        description="Example attack scenario"
    )
    cwe_id: Optional[str] = Field(
        default=None,
        description="Associated CWE identifier"
    )
    related_cve_id: Optional[str] = Field(
        default=None,
        description="Related CVE identifier if applicable"
    )


class ArchitecturalWeakness(BaseModel):
    """
    Represents an architectural weakness identified in the system.
    
    Weaknesses are design or implementation flaws that could be
    exploited by threats.
    """
    
    weakness_id: str = Field(
        ...,
        description="Unique weakness identifier (e.g., 'W-001')"
    )
    title: str = Field(
        ...,
        description="Brief title of the weakness"
    )
    description: str = Field(
        ...,
        description="Detailed description of the weakness"
    )
    impact: str = Field(
        ...,
        description="Potential impact of exploiting this weakness"
    )
    mitigation: str = Field(
        ...,
        description="Recommended mitigation for this weakness"
    )


# =============================================================================
# Attack Path Models
# =============================================================================

class AttackPathStep(BaseModel):
    """
    Represents a single step in an attack path.
    
    Each step describes an action taken by an attacker to progress
    through the system toward their objective.
    """
    
    step_number: int = Field(
        ...,
        description="Sequential step number in the attack path"
    )
    action: str = Field(
        ...,
        description="Description of the attacker's action"
    )
    target_component: str = Field(
        ...,
        description="Component targeted in this step"
    )
    technique: str = Field(
        ...,
        description="Attack technique used (MITRE ATT&CK technique if applicable)"
    )
    outcome: str = Field(
        ...,
        description="Result or outcome of this step"
    )


class AttackPath(BaseModel):
    """
    Represents a complete attack path through the system.
    
    An attack path is a sequence of steps an attacker might take
    to achieve a malicious objective.
    """
    
    path_id: str = Field(
        ...,
        description="Unique attack path identifier (e.g., 'AP-01')"
    )
    name: str = Field(
        ...,
        description="Descriptive name for the attack path"
    )
    description: str = Field(
        ...,
        description="Detailed description of the attack scenario"
    )
    impact: str = Field(
        ...,
        description="Potential impact if the attack is successful"
    )
    likelihood: str = Field(
        ...,
        description="Likelihood of this attack: High, Medium, or Low"
    )
    steps: List[AttackPathStep] = Field(
        default_factory=list,
        description="Ordered list of attack steps"
    )
    referenced_threats: List[str] = Field(
        default_factory=list,
        description="List of threat IDs referenced in this attack path"
    )
    referenced_cves: List[str] = Field(
        default_factory=list,
        description="List of CVE IDs that enable this attack path"
    )


# =============================================================================
# Container Models
# =============================================================================

class ThreatSearchResults(BaseModel):
    """
    Container for threat search results.
    
    Used to aggregate multiple threat records from vulnerability searches.
    """
    
    threats: List[ThreatRecord] = Field(
        default_factory=list,
        description="List of threat records matching the search criteria"
    )


class AttackPathList(BaseModel):
    """
    Container for attack paths.
    
    Used to aggregate multiple attack paths for a system.
    """
    
    paths: List[AttackPath] = Field(
        default_factory=list,
        description="List of identified attack paths"
    )
