"""
Threat Knowledge Agent for Left<<Shift Threat Modeling System.

This agent performs STRIDE-based threat analysis on architecture components,
generates detailed threats with CWE mappings, and identifies architectural weaknesses.

Uses Google Gemini for STRIDE analysis and threat generation.
"""

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

from tools.models import (
    ArchitectureSchema,
    ArchitecturalThreat,
    ArchitecturalWeakness,
)

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# Configuration Constants
# =============================================================================

MAX_RETRIES = 3
BASE_DELAY = 2.0
PRIMARY_MODEL = "gemini-3-pro-preview"
FALLBACK_MODEL = "gemini-2.5-pro"

# =============================================================================
# STRIDE Analysis System Instruction
# =============================================================================

STRIDE_SYSTEM_INSTRUCTION = """You are an expert penetration tester and security architect performing STRIDE threat modeling.

## YOUR APPROACH: Quality Over Quantity

DO NOT generate generic, copy-paste threats. Each threat must be:
- UNIQUE to the specific component and its role in the architecture
- CONTEXTUALIZED based on data flows, trust boundaries, and neighboring components
- PRIORITIZED based on realistic attack feasibility

## SEVERITY CALIBRATION (STRICT CRITERIA):

**CRITICAL** (use sparingly - max 10% of threats):
- Remote code execution from untrusted network without authentication
- Full database compromise with data exfiltration
- Authentication bypass affecting all users
- Container/VM escape to host

**HIGH** (20-30% of threats):
- SQL injection with data modification capability
- Privilege escalation from user to admin
- Sensitive data exposure (PII, credentials, secrets)
- Denial of service affecting core business functions

**MEDIUM** (40-50% of threats):
- Requires authentication + specific conditions
- Information disclosure of non-critical data
- Local-only exploits with limited impact
- DoS affecting non-critical services

**LOW** (20-30% of threats):
- Requires physical access or insider position
- Theoretical attacks with no known exploitation
- Minor information leakage
- Attacks mitigated by common configurations

## ANTI-PATTERNS TO AVOID:

1. **DO NOT** copy the same threat for every database (SQL injection everywhere)
2. **DO NOT** mark everything as High/Critical
3. **DO NOT** use generic descriptions like "Attacker could compromise the system"
4. **DO NOT** ignore the actual data flows - threats should follow data paths
5. **DO NOT** generate threats for components that don't apply (e.g., SQL injection on Redis)

## COMPONENT-SPECIFIC GUIDANCE:

- **Databases**: Focus on the SPECIFIC database technology (MySQL vs PostgreSQL vs MongoDB have different threats)
- **Caches (Redis/Memcached)**: Focus on protocol-specific attacks, not generic injection
- **Message Queues**: Focus on message tampering, unauthorized subscription, poison messages
- **API Gateways**: Focus on routing bypass, rate limit evasion, header injection
- **Auth Services**: Focus on token handling, session management, credential storage
- **Frontend Services**: Focus on client-side attacks, CORS, CSP bypass

## THREAT GENERATION RULES:

1. Generate 2-4 HIGH-QUALITY threats per component (not 6-10 generic ones)
2. Each threat description must be at least 2 sentences with specific technical detail
3. Preconditions must list ACTUAL requirements (network access, auth level, specific config)
4. Mitigations must be ACTIONABLE (not "implement security controls")

## OUTPUT FORMAT:

Return JSON with "threats" and "weaknesses" arrays.

Each threat:
- threat_id: T-001, T-002, etc.
- category: One of [Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege]
- description: 2-3 sentences with technical specifics
- affected_component: Exact component name from input
- severity: Use calibration above - distribute realistically
- mitigation_steps: Array of 2-4 SPECIFIC, ACTIONABLE steps
- preconditions: Array of SPECIFIC requirements for this attack
- impact: Concrete business/technical impact
- cwe_id: SPECIFIC CWE (not generic CWE-20, CWE-693)
- example: One concrete attack scenario

**DO NOT set related_cve_id** - CVE mapping happens separately.

Each weakness:
- weakness_id: W-001, etc.
- title: Brief title
- description: Specific architectural concern
- impact: Concrete consequences
- mitigation: Actionable fix
"""

# =============================================================================
# CWE Validation System Instruction
# =============================================================================

CWE_VALIDATION_INSTRUCTION = """You are a CWE (Common Weakness Enumeration) expert.

Your task is to review and validate CWE mappings in threat assessments.

## Validation Rules:

1. **Reject Generic CWEs** - These are too broad:
   - CWE-20 (Improper Input Validation) → Find specific weakness
   - CWE-693 (Protection Mechanism Failure) → Find specific mechanism
   - CWE-284 (Improper Access Control) → Find specific access control issue
   - CWE-707 (Improper Neutralization) → Find specific neutralization failure
   - CWE-664 (Improper Control of Resource) → Find specific resource issue

2. **Prefer Specific CWEs**:
   - SQL Injection → CWE-89
   - XSS → CWE-79 (Reflected), CWE-80 (Basic), CWE-87 (Improper Neutralization)
   - Authentication Bypass → CWE-287, CWE-306
   - Path Traversal → CWE-22
   - Command Injection → CWE-78
   - XXE → CWE-611
   - SSRF → CWE-918
   - Insecure Deserialization → CWE-502
   - Broken Access Control → CWE-639 (IDOR), CWE-285, CWE-862

3. **Context Matters**:
   - Consider the technology stack
   - Consider the threat description
   - Match CWE to the specific vulnerability pattern

## For Each Threat:
- Determine if the CWE is accurate and specific
- If not, provide the corrected CWE with reasoning
- Only flag items that need correction

## Output Format:
Return a JSON object with "corrections" list containing only threats that need CWE updates.
"""

# =============================================================================
# Pydantic Models for Agent Output
# =============================================================================

class CWEValidationItem(BaseModel):
    """Result of validating a single threat's CWE mapping."""
    
    threat_id: str = Field(
        ...,
        description="ID of the threat being validated"
    )
    is_accurate: bool = Field(
        ...,
        description="Whether the original CWE mapping is accurate"
    )
    corrected_cwe_id: Optional[str] = Field(
        default=None,
        description="Corrected CWE ID if original was inaccurate"
    )
    reason: str = Field(
        ...,
        description="Explanation for the validation result"
    )


class CWEValidationOutput(BaseModel):
    """Output from CWE validation pass."""
    
    corrections: List[CWEValidationItem] = Field(
        default_factory=list,
        description="List of CWE corrections needed"
    )


class ThreatKnowledgeOutput(BaseModel):
    """Complete output from threat knowledge generation."""
    
    threats: List[ArchitecturalThreat] = Field(
        default_factory=list,
        description="List of identified STRIDE threats"
    )
    weaknesses: List[ArchitecturalWeakness] = Field(
        default_factory=list,
        description="List of architectural weaknesses"
    )


# =============================================================================
# Schema Definitions for Structured Output
# =============================================================================

def _create_threat_output_schema() -> dict:
    """Create JSON schema for threat knowledge output."""
    return {
        "type": "object",
        "properties": {
            "threats": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "threat_id": {"type": "string"},
                        "category": {"type": "string"},
                        "description": {"type": "string"},
                        "affected_component": {"type": "string"},
                        "affected_asset": {"type": "string"},
                        "trust_boundary": {"type": "string"},
                        "severity": {"type": "string"},
                        "mitigation_steps": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "preconditions": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "impact": {"type": "string"},
                        "example": {"type": "string"},
                        "cwe_id": {"type": "string"},
                        "related_cve_id": {"type": "string"}
                    },
                    "required": ["threat_id", "category", "description", 
                                "affected_component", "severity", "cwe_id"]
                }
            },
            "weaknesses": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "weakness_id": {"type": "string"},
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "impact": {"type": "string"},
                        "mitigation": {"type": "string"}
                    },
                    "required": ["weakness_id", "title", "description", 
                                "impact", "mitigation"]
                }
            }
        },
        "required": ["threats", "weaknesses"]
    }


def _create_cwe_validation_schema() -> dict:
    """Create JSON schema for CWE validation output."""
    return {
        "type": "object",
        "properties": {
            "corrections": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "threat_id": {"type": "string"},
                        "is_accurate": {"type": "boolean"},
                        "corrected_cwe_id": {"type": "string"},
                        "reason": {"type": "string"}
                    },
                    "required": ["threat_id", "is_accurate", "reason"]
                }
            }
        },
        "required": ["corrections"]
    }


# =============================================================================
# Threat Knowledge Agent
# =============================================================================

class ThreatKnowledgeAgent:
    """
    Agent for generating STRIDE-based threat knowledge from architecture analysis.
    
    This agent:
    1. Analyzes architecture components using STRIDE methodology
    2. Generates detailed, technology-specific threats
    3. Validates and corrects CWE mappings
    4. Identifies architectural weaknesses
    
    Uses Google Gemini for threat generation.
    """
    
    def __init__(self, model_name: str = PRIMARY_MODEL):
        """
        Initialize the Threat Knowledge Agent.
        
        Args:
            model_name: Gemini model to use for generation
        """
        self.model_name = model_name
        self.client: Optional[genai.Client] = None
        self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize Gemini client if API key is available."""
        api_key = os.getenv("GEMINI_API_KEY")
        if api_key and api_key != "your_gemini_api_key_here":
            try:
                self.client = genai.Client(api_key=api_key)
                logger.info(f"Gemini client initialized with model: {self.model_name}")
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini client: {e}")
                self.client = None
        else:
            logger.warning("GEMINI_API_KEY not configured - threat generation disabled")
            self.client = None
    
    def _call_llm_with_retry(
        self,
        prompt: str,
        system_instruction: str,
        response_schema: dict,
        model: str = None,
        attempt: int = 1
    ) -> Optional[str]:
        """
        Call LLM with retry logic and fallback.
        
        Args:
            prompt: User prompt
            system_instruction: System instruction
            response_schema: JSON schema for structured output (used for guidance)
            model: Model to use (defaults to self.model_name)
            attempt: Current attempt number
            
        Returns:
            Response text or None if all attempts fail
        """
        if not self.client:
            logger.warning("No LLM client available")
            return None
        
        model = model or self.model_name
        
        try:
            logger.info(f"LLM call attempt {attempt}/{MAX_RETRIES} using {model}")
            
            # Add schema guidance to system instruction
            schema_guidance = f"\n\nYou MUST respond with valid JSON matching this schema:\n{json.dumps(response_schema, indent=2)}"
            full_prompt = f"{system_instruction}{schema_guidance}\n\n{prompt}"
            
            response = self.client.models.generate_content(
                model=model,
                contents=full_prompt,
                config=types.GenerateContentConfig(
                    temperature=0.3,
                    response_mime_type="application/json"
                )
            )
            
            return response.text
            
        except Exception as e:
            logger.warning(f"LLM call failed (attempt {attempt}): {e}")
            
            if attempt < MAX_RETRIES:
                delay = BASE_DELAY * (2 ** (attempt - 1))
                logger.info(f"Retrying in {delay}s...")
                time.sleep(delay)
                
                next_model = FALLBACK_MODEL if attempt == MAX_RETRIES - 1 else model
                return self._call_llm_with_retry(
                    prompt, system_instruction, response_schema, next_model, attempt + 1
                )
            
            return None
    
    def _build_analysis_prompt(
        self,
        inferred_components: List[Dict[str, Any]],
        architecture: ArchitectureSchema
    ) -> str:
        """
        Build the prompt for STRIDE threat analysis.
        
        Args:
            inferred_components: Component list with inferred products
            architecture: Full architecture schema
            
        Returns:
            Formatted prompt string
        """
        # Build component summary
        component_details = []
        for comp in inferred_components:
            name = comp.get("component_name", "Unknown")
            products = comp.get("inferred_product_categories", ["Generic"])
            confidence = comp.get("confidence", 0.0)
            comp_type = comp.get("type", "Unknown")
            
            component_details.append(
                f"- {name} (Type: {comp_type}, Likely Tech: {products[0]}, Confidence: {confidence:.0%})"
            )
        
        # Build data flow summary
        flow_details = []
        for flow in architecture.data_flows:
            flow_details.append(
                f"- {flow.source} → {flow.destination} [{flow.protocol}]"
            )
        
        # Build trust boundary summary
        boundaries = architecture.trust_boundaries or ["Not specified"]
        
        prompt = f"""Perform STRIDE threat analysis on the following architecture:

## Project: {architecture.project_name}

## Description:
{architecture.description}

## Components ({len(inferred_components)} total):
{chr(10).join(component_details)}

## Data Flows ({len(architecture.data_flows)} total):
{chr(10).join(flow_details) if flow_details else "No data flows specified"}

## Trust Boundaries:
{chr(10).join(f"- {b}" for b in boundaries)}

## Analysis Requirements:

1. Generate 6-10 STRIDE threats for EACH component
2. Ensure ALL 6 STRIDE categories are covered across the analysis
3. Use technology-specific attack descriptions
4. Provide specific CWE IDs (not generic ones like CWE-20)
5. Include actionable mitigation steps
6. Identify 5-10 architectural weaknesses

Focus on:
- Component-specific vulnerabilities based on inferred technologies
- Data flow security (encryption, authentication, integrity)
- Trust boundary violations
- Protocol-specific attacks
- Real-world attack patterns and CVE references

Return your analysis as a JSON object with "threats" and "weaknesses" arrays."""

        return prompt
    
    def _validate_cwe_mappings(
        self,
        threats: List[ArchitecturalThreat]
    ) -> List[ArchitecturalThreat]:
        """
        Validate and correct CWE mappings for generated threats.
        
        Args:
            threats: List of threats to validate
            
        Returns:
            List of threats with corrected CWE mappings
        """
        if not threats or not self.client:
            return threats
        
        logger.info(f"Validating CWE mappings for {len(threats)} threats")
        
        # Build validation prompt
        threat_summary = []
        for t in threats:
            threat_summary.append({
                "threat_id": t.threat_id,
                "category": t.category,
                "description": t.description[:200],
                "cwe_id": t.cwe_id
            })
        
        prompt = f"""Review the following threat assessments and validate their CWE mappings:

{json.dumps(threat_summary, indent=2)}

For each threat:
1. Check if the CWE is specific enough
2. If the CWE is too generic (CWE-20, CWE-693, etc.), provide a more specific CWE
3. Only include threats that need correction in your response

Return a JSON object with "corrections" array containing only items that need updates."""

        # Call validation
        response_text = self._call_llm_with_retry(
            prompt=prompt,
            system_instruction=CWE_VALIDATION_INSTRUCTION,
            response_schema=_create_cwe_validation_schema()
        )
        
        if not response_text:
            logger.warning("CWE validation failed - keeping original mappings")
            return threats
        
        # Parse and apply corrections
        try:
            data = json.loads(response_text)
            validation = CWEValidationOutput.model_validate(data)
            
            # Build correction map
            corrections = {c.threat_id: c for c in validation.corrections if not c.is_accurate}
            
            if corrections:
                logger.info(f"Applying {len(corrections)} CWE corrections")
                
                # Apply corrections
                for threat in threats:
                    if threat.threat_id in corrections:
                        correction = corrections[threat.threat_id]
                        if correction.corrected_cwe_id:
                            old_cwe = threat.cwe_id
                            threat.cwe_id = correction.corrected_cwe_id
                            logger.debug(
                                f"Corrected {threat.threat_id}: {old_cwe} → {threat.cwe_id} "
                                f"({correction.reason})"
                            )
            else:
                logger.info("All CWE mappings validated - no corrections needed")
                
        except Exception as e:
            logger.error(f"Failed to parse CWE validation response: {e}")
        
        return threats
    
    def generate_threats(
        self,
        inferred_components: List[Dict[str, Any]],
        architecture: ArchitectureSchema
    ) -> Dict[str, List]:
        """
        Generate STRIDE threats and architectural weaknesses.
        
        Args:
            inferred_components: List of components with inferred product info
            architecture: Full architecture schema
            
        Returns:
            Dict with 'threats' and 'weaknesses' lists
        """
        if not self.client:
            logger.error("LLM client not available - cannot generate threats")
            return self._generate_fallback_threats(inferred_components, architecture)
        
        # Build prompt
        prompt = self._build_analysis_prompt(inferred_components, architecture)
        
        # Call LLM for threat generation
        logger.info("Generating STRIDE threats...")
        response_text = self._call_llm_with_retry(
            prompt=prompt,
            system_instruction=STRIDE_SYSTEM_INSTRUCTION,
            response_schema=_create_threat_output_schema()
        )
        
        if not response_text:
            logger.error("Threat generation failed - using fallback")
            return self._generate_fallback_threats(inferred_components, architecture)
        
        # Parse response
        try:
            data = json.loads(response_text)
            output = ThreatKnowledgeOutput.model_validate(data)
            
            logger.info(
                f"Generated {len(output.threats)} threats and "
                f"{len(output.weaknesses)} weaknesses"
            )
            
            # Validate CWE mappings
            validated_threats = self._validate_cwe_mappings(output.threats)
            
            # Log STRIDE coverage
            categories = {}
            for t in validated_threats:
                cat = t.category
                categories[cat] = categories.get(cat, 0) + 1
            
            logger.info(f"STRIDE coverage: {categories}")
            
            return {
                "threats": validated_threats,
                "weaknesses": output.weaknesses
            }
            
        except Exception as e:
            logger.error(f"Failed to parse threat generation response: {e}")
            return self._generate_fallback_threats(inferred_components, architecture)
    
    def _generate_fallback_threats(
        self,
        inferred_components: List[Dict[str, Any]],
        architecture: ArchitectureSchema
    ) -> Dict[str, List]:
        """
        Generate basic fallback threats when LLM is unavailable.
        
        Args:
            inferred_components: Component list
            architecture: Architecture schema
            
        Returns:
            Dict with basic threats and weaknesses
        """
        logger.info("Generating fallback threats (heuristic-based)")
        
        threats = []
        threat_id = 1
        
        # Generate basic STRIDE threats for each component
        stride_templates = [
            ("Spoofing", "Authentication bypass or identity spoofing", "CWE-287"),
            ("Tampering", "Unauthorized data modification", "CWE-345"),
            ("Repudiation", "Insufficient logging and monitoring", "CWE-778"),
            ("Information Disclosure", "Sensitive data exposure", "CWE-200"),
            ("Denial of Service", "Resource exhaustion attack", "CWE-400"),
            ("Elevation of Privilege", "Unauthorized privilege escalation", "CWE-269"),
        ]
        
        for comp in inferred_components[:5]:  # Limit to first 5 components
            comp_name = comp.get("component_name", "Unknown")
            
            for category, desc, cwe in stride_templates:
                threats.append(ArchitecturalThreat(
                    threat_id=f"T-{threat_id:03d}",
                    category=category,
                    description=f"{desc} affecting {comp_name}",
                    affected_component=comp_name,
                    severity="Medium",
                    mitigation_steps=[
                        "Implement security controls",
                        "Follow security best practices",
                        "Regular security assessments"
                    ],
                    preconditions=["Attacker has network access"],
                    impact=f"Potential {category.lower()} impact on {comp_name}",
                    cwe_id=cwe
                ))
                threat_id += 1
        
        # Generate basic weaknesses
        weaknesses = [
            ArchitecturalWeakness(
                weakness_id="W-001",
                title="Insufficient Security Controls",
                description="Architecture may lack comprehensive security controls",
                impact="Increased attack surface",
                mitigation="Implement defense-in-depth security controls"
            ),
            ArchitecturalWeakness(
                weakness_id="W-002",
                title="Missing Network Segmentation",
                description="Components may not be properly segmented",
                impact="Lateral movement risk",
                mitigation="Implement network segmentation and micro-segmentation"
            ),
        ]
        
        return {
            "threats": threats,
            "weaknesses": weaknesses
        }
    
    def analyze_component(
        self,
        component_name: str,
        component_type: str,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ArchitecturalThreat]:
        """
        Analyze a single component for STRIDE threats.
        
        Args:
            component_name: Name of the component
            component_type: Type/category of the component
            context: Optional context (other components, data flows)
            
        Returns:
            List of threats for this component
        """
        # Create minimal architecture for single component analysis
        from tools.models import Component
        
        architecture = ArchitectureSchema(
            project_name="Single Component Analysis",
            description=f"Analysis of {component_name}",
            components=[Component(name=component_name, type=component_type)],
            data_flows=[],
            trust_boundaries=[]
        )
        
        inferred = [{
            "component_name": component_name,
            "type": component_type,
            "inferred_product_categories": [component_name],
            "confidence": 0.9
        }]
        
        result = self.generate_threats(inferred, architecture)
        return result.get("threats", [])


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "ThreatKnowledgeAgent",
    "ThreatKnowledgeOutput",
    "CWEValidationItem",
    "CWEValidationOutput",
    "STRIDE_SYSTEM_INSTRUCTION",
    "CWE_VALIDATION_INSTRUCTION",
]
