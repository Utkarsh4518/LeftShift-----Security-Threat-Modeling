"""
Threat Relevance Agent for Left<<Shift Threat Modeling System.

This agent analyzes discovered CVEs and STRIDE threats for relevance
to the specific architecture, filtering out irrelevant findings and
enriching relevant ones with context-specific information.

IMPORTANT: This agent does NOT generate or hallucinate CVEs.
It only analyzes CVEs that were discovered from real vulnerability databases.

Uses Google Gemini for relevance analysis.
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
    ArchitecturalThreat,
    ArchitecturalWeakness,
    ThreatRecord,
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
# Relevance Analysis System Instruction
# =============================================================================

RELEVANCE_SYSTEM_INSTRUCTION = """You are a senior security analyst performing CVE triage for a specific architecture.

## YOUR JOB: Be conservative, not alarmist.

Most CVEs do NOT apply to most systems. Your job is to filter noise, not amplify it.

## CRITICAL RULES:
1. ONLY analyze CVEs provided in the input - NEVER invent CVE IDs
2. When in doubt, mark as LOW or IRRELEVANT, not HIGH
3. Prerequisites MUST factor into likelihood scoring
4. Group similar CVEs into vulnerability classes - only keep 1-2 representative CVEs per class

## VULNERABILITY CLASSIFICATION (Group similar CVEs):

Assign each CVE to a vulnerability_class. Common classes:
- "Input Parsing DoS" - ReDoS, multipart parser abuse, Accept-Language parsing, etc.
- "Template Engine Disclosure" - Template filter misuse, dictsort, variable resolution
- "Serialization RCE" - Unsafe deserialization, pickle, YAML attacks
- "SQL Injection" - Any SQL injection variant
- "Authentication Bypass" - Auth bypass, session issues
- "Path Traversal" - Directory traversal, LFI
- "SSRF" - Server-side request forgery
- "XSS" - Cross-site scripting variants
- "Privilege Escalation" - Priv esc, permission issues
- "Memory Corruption" - Buffer overflows, use-after-free

When you see multiple CVEs in the same class (e.g., 5 Django DoS CVEs):
- Mark ONE as is_representative=true (the most severe or most exploitable)
- Mark others as is_representative=false
- They will be grouped in the report as "X additional CVEs in this class"

## IMPACT CATEGORIZATION (Distinguish severity types):

Assign each CVE an impact_category:

1. "Server Compromise" (MOST SEVERE):
   - Remote Code Execution
   - Container/VM escape
   - Full system takeover
   - Example: Deserialization leading to RCE

2. "Data Compromise" (SEVERE):
   - Data exfiltration
   - Database access
   - PII exposure
   - Credential theft
   - Example: SQL injection, path traversal to sensitive files

3. "Availability Impact" (MODERATE):
   - Denial of Service
   - Resource exhaustion
   - Service disruption
   - Example: ReDoS, infinite loops, memory exhaustion

4. "User-Level Impact" (LOWER):
   - Session hijacking
   - Cookie theft
   - CSRF
   - Client-side attacks
   - Example: XSS, clickjacking

## EXPLICIT ASSUMPTIONS:

For each CVE, provide assumptions array with conditions that must be true:
- "File uploads enabled" / "File uploads disabled"
- "DEBUG=True in production settings"
- "User input passed directly to [function/filter]"
- "Internationalized URLs (i18n_patterns) enabled"
- "Windows deployment" / "Linux deployment"
- "Internal network traffic unencrypted"
- "No WAF/rate limiting in place"
- "Vulnerable component version deployed"
- "Feature X enabled (non-default)"

## RELEVANCE SCORING (Be strict):

### HIGH Relevance (rare - max 15% of CVEs):
ALL of these must be true:
- Product EXACTLY matches architecture component
- Exploitable remotely WITHOUT authentication
- Works in DEFAULT configuration
- CVSS >= 8.0 or CISA KEV listed
- No unusual prerequisites

### MEDIUM Relevance (common - 30-40% of CVEs):
- Product matches but requires ONE of:
  - Authentication (reduces to Medium even if RCE)
  - Specific non-default configuration
  - Network-adjacent access (not remote)
  - Specific version that may not be deployed

### LOW Relevance (common - 30-40% of CVEs):
ANY of these drops to LOW:
- Requires local access
- Requires admin/root privileges already
- Requires specific plugin/module not commonly used
- Requires unusual configuration
- Old CVE (pre-2020) likely already patched
- Requires chained exploitation

### IRRELEVANT (Discard - 20-30% of CVEs):
- Product not in architecture
- Wrong OS/platform
- Feature clearly not in use
- Requires physical access
- CVE is disputed or rejected

## OUTPUT:
JSON with "assessments" array. Each assessment:
- cve_id: EXACT ID from input
- relevance_status: High/Medium/Low (no Irrelevant - just omit those)
- vulnerability_class: Class name from list above
- impact_category: One of Server Compromise/Data Compromise/Availability Impact/User-Level Impact
- is_representative: true if this is the best example of its class, false otherwise
- assumptions: Array of EXPLICIT conditions required for exploitation
- prerequisites: Condensed requirements string
- exploitability: RCE/DoS/Info Disclosure/Privilege Escalation/etc.
- likelihood: High/Medium/Low with justification
- justification: 2-3 sentences explaining relevance IN CONTEXT
- mitigation_suggestion: Specific action
- configuration_fixes: Array of config changes

OMIT irrelevant CVEs entirely from output.
"""


# =============================================================================
# Pydantic Models for Relevance Assessment
# =============================================================================

class CVERelevanceAssessment(BaseModel):
    """Assessment of a CVE's relevance to the architecture."""
    
    cve_id: str = Field(
        ...,
        description="The CVE identifier being assessed"
    )
    relevance_status: str = Field(
        ...,
        description="Relevance level: High, Medium, or Low"
    )
    justification: str = Field(
        ...,
        description="Why this CVE is relevant to the specific architecture"
    )
    prerequisites: str = Field(
        default="",
        description="Conditions required for exploitation"
    )
    exploitability: str = Field(
        default="",
        description="Type of exploitation: RCE, DoS, Info Disclosure, etc."
    )
    likelihood: str = Field(
        default="Medium",
        description="Likelihood of exploitation: High, Medium, or Low"
    )
    mitigation_suggestion: str = Field(
        default="",
        description="Specific remediation recommendation"
    )
    configuration_fixes: List[str] = Field(
        default_factory=list,
        description="Configuration changes to mitigate the vulnerability"
    )
    # New fields for improved CVE classification
    vulnerability_class: str = Field(
        default="Unclassified",
        description="Vulnerability class grouping (e.g., 'Input Parsing DoS', 'Serialization RCE')"
    )
    impact_category: str = Field(
        default="Availability Impact",
        description="Impact category: Server Compromise, Data Compromise, Availability Impact, User-Level Impact"
    )
    is_representative: bool = Field(
        default=False,
        description="Whether this CVE is the representative example for its vulnerability class"
    )
    assumptions: List[str] = Field(
        default_factory=list,
        description="Explicit assumptions required for this CVE to be exploitable"
    )


class ThreatRelevanceOutput(BaseModel):
    """Output from relevance analysis."""
    
    assessments: List[CVERelevanceAssessment] = Field(
        default_factory=list,
        description="List of relevance assessments for CVEs"
    )


# =============================================================================
# Schema for Structured Output
# =============================================================================

def _create_relevance_schema() -> dict:
    """Create JSON schema for relevance assessment output."""
    return {
        "type": "object",
        "properties": {
            "assessments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "cve_id": {"type": "string"},
                        "relevance_status": {"type": "string"},
                        "justification": {"type": "string"},
                        "prerequisites": {"type": "string"},
                        "exploitability": {"type": "string"},
                        "likelihood": {"type": "string"},
                        "mitigation_suggestion": {"type": "string"},
                        "configuration_fixes": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "vulnerability_class": {"type": "string"},
                        "impact_category": {"type": "string"},
                        "is_representative": {"type": "boolean"},
                        "assumptions": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    },
                    "required": ["cve_id", "relevance_status", "justification", "vulnerability_class", "impact_category"]
                }
            }
        },
        "required": ["assessments"]
    }


# =============================================================================
# Threat Relevance Agent
# =============================================================================

class ThreatRelevanceAgent:
    """
    Agent for assessing threat relevance to specific architectures.
    
    This agent:
    1. Analyzes CVEs for relevance to the target architecture
    2. Filters out irrelevant vulnerabilities
    3. Enriches relevant CVEs with context-specific information
    4. Promotes critical CVEs to architectural threats
    
    IMPORTANT: This agent does NOT generate CVEs - it only analyzes
    CVEs that were discovered from real vulnerability databases.
    
    Uses Google Gemini for relevance analysis.
    """
    
    def __init__(self, model_name: str = PRIMARY_MODEL):
        """
        Initialize the Threat Relevance Agent.
        
        Args:
            model_name: Gemini model to use for analysis
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
                logger.info(f"Gemini client initialized for relevance analysis")
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini client: {e}")
                self.client = None
        else:
            logger.warning("GEMINI_API_KEY not configured")
            self.client = None
    
    def _call_llm_with_retry(
        self,
        prompt: str,
        attempt: int = 1,
        model: Optional[str] = None
    ) -> Optional[str]:
        """Call LLM with retry logic and fallback model support."""
        if not self.client:
            return None
        
        model = model or self.model_name
        
        try:
            logger.info(f"LLM call attempt {attempt}/{MAX_RETRIES} using {model}")
            
            # Add schema guidance to system instruction
            schema = _create_relevance_schema()
            schema_guidance = f"\n\nYou MUST respond with valid JSON matching this schema:\n{json.dumps(schema, indent=2)}"
            full_prompt = f"{RELEVANCE_SYSTEM_INSTRUCTION}{schema_guidance}\n\n{prompt}"
            
            response = self.client.models.generate_content(
                model=model,
                contents=full_prompt,
                config=types.GenerateContentConfig(
                    temperature=0.2,
                    response_mime_type="application/json"
                )
            )
            
            return response.text
            
        except Exception as e:
            logger.warning(f"LLM call failed (attempt {attempt}): {e}")
            
            if attempt < MAX_RETRIES:
                delay = BASE_DELAY * (2 ** (attempt - 1))
                time.sleep(delay)
                # Use fallback model on last retry attempt
                next_model = FALLBACK_MODEL if attempt == MAX_RETRIES - 1 else model
                return self._call_llm_with_retry(prompt, attempt + 1, next_model)
            
            return None
    
    def _simplify_cve_for_prompt(self, cve: ThreatRecord) -> Dict[str, Any]:
        """
        Simplify CVE data to save tokens in prompt.
        
        Args:
            cve: ThreatRecord to simplify
            
        Returns:
            Simplified dict with essential fields
        """
        return {
            "cve_id": cve.cve_id,
            "summary": cve.summary[:300] if cve.summary else "",
            "severity": cve.severity,
            "cvss_score": cve.cvss_score,
            "affected_products": cve.affected_products[:200] if cve.affected_products else "",
            "cwe_id": cve.cwe_id,
            "is_actively_exploited": cve.is_actively_exploited,
        }
    
    def _build_relevance_prompt(
        self,
        inferred_components: List[Dict[str, Any]],
        cve_threats: List[ThreatRecord]
    ) -> str:
        """Build the prompt for relevance analysis."""
        # Build component summary
        component_summary = []
        for comp in inferred_components:
            name = comp.get("component_name", "Unknown")
            products = comp.get("inferred_product_categories", [])
            comp_type = comp.get("type", "Unknown")
            component_summary.append(f"- {name} (Type: {comp_type}, Tech: {products[0] if products else 'Unknown'})")
        
        # Simplify CVEs
        simplified_cves = [self._simplify_cve_for_prompt(cve) for cve in cve_threats]
        
        prompt = f"""Analyze the following CVEs for relevance to this specific architecture.

## Architecture Components:
{chr(10).join(component_summary)}

## CVEs to Analyze ({len(simplified_cves)} total):
{json.dumps(simplified_cves, indent=2)}

## Instructions:
1. For each CVE, determine if it's RELEVANT (High/Medium/Low) or IRRELEVANT
2. DISCARD irrelevant CVEs - do not include them in output
3. For relevant CVEs, provide:
   - prerequisites: What's needed to exploit
   - exploitability: RCE, DoS, Info Disclosure, etc.
   - likelihood: High/Medium/Low based on architecture
   - justification: Why this matters to THIS system
   - mitigation_suggestion: Specific fix
   - configuration_fixes: Config changes needed

IMPORTANT: Only analyze the CVEs provided above. Do not invent new CVE IDs.

Return only RELEVANT CVEs in the assessments array."""

        return prompt
    
    def _apply_assessments_to_cves(
        self,
        cve_threats: List[ThreatRecord],
        assessments: List[CVERelevanceAssessment]
    ) -> List[ThreatRecord]:
        """
        Apply assessment data to original CVE objects.
        
        Args:
            cve_threats: Original CVE list
            assessments: Relevance assessments
            
        Returns:
            List of relevant CVEs with enriched data
        """
        # Build assessment lookup
        assessment_map = {a.cve_id: a for a in assessments}
        
        relevant_cves = []
        for cve in cve_threats:
            if cve.cve_id in assessment_map:
                assessment = assessment_map[cve.cve_id]
                
                # Enrich CVE with assessment data
                cve.relevance_status = assessment.relevance_status
                cve.prerequisites = assessment.prerequisites
                cve.exploitability = assessment.exploitability
                cve.likelihood = assessment.likelihood
                cve.justification = assessment.justification
                
                # Apply new classification fields
                cve.vulnerability_class = assessment.vulnerability_class
                cve.impact_category = assessment.impact_category
                cve.is_representative = assessment.is_representative
                cve.assumptions = assessment.assumptions
                
                relevant_cves.append(cve)
        
        return relevant_cves
    
    def _promote_critical_cves_to_threats(
        self,
        relevant_cves: List[ThreatRecord],
        existing_threats: List[ArchitecturalThreat]
    ) -> List[ArchitecturalThreat]:
        """
        Promote critical/high-relevance CVEs to architectural threats.
        
        Args:
            relevant_cves: CVEs assessed as relevant
            existing_threats: Existing threat list
            
        Returns:
            Updated threats list with promoted CVEs
        """
        # Find next available threat ID
        existing_ids = set()
        for threat in existing_threats:
            if threat.threat_id.startswith("T-"):
                try:
                    num = int(threat.threat_id[2:])
                    existing_ids.add(num)
                except ValueError:
                    pass
        
        next_id = max(existing_ids, default=0) + 1
        
        # Map exploitability to STRIDE category
        exploitability_to_stride = {
            "rce": "Elevation of Privilege",
            "remote code execution": "Elevation of Privilege",
            "privilege escalation": "Elevation of Privilege",
            "dos": "Denial of Service",
            "denial of service": "Denial of Service",
            "information disclosure": "Information Disclosure",
            "info disclosure": "Information Disclosure",
            "data leak": "Information Disclosure",
            "authentication bypass": "Spoofing",
            "auth bypass": "Spoofing",
            "data tampering": "Tampering",
            "tampering": "Tampering",
            "injection": "Tampering",
        }
        
        promoted_threats = list(existing_threats)
        
        for cve in relevant_cves:
            # Only promote HIGH/CRITICAL severity or High relevance
            should_promote = (
                cve.severity in ["CRITICAL", "HIGH"] or
                (hasattr(cve, 'relevance_status') and cve.relevance_status == "High") or
                cve.is_actively_exploited
            )
            
            if not should_promote:
                continue
            
            # Check if already promoted (avoid duplicates)
            already_promoted = any(
                t.related_cve_id == cve.cve_id for t in promoted_threats
            )
            if already_promoted:
                continue
            
            # Determine STRIDE category from exploitability
            category = "Elevation of Privilege"  # Default
            if hasattr(cve, 'exploitability') and cve.exploitability:
                exploitability_lower = cve.exploitability.lower()
                for key, stride_cat in exploitability_to_stride.items():
                    if key in exploitability_lower:
                        category = stride_cat
                        break
            
            # Extract affected component
            affected_component = cve.affected_products.split(",")[0] if cve.affected_products else "Unknown"
            if len(affected_component) > 50:
                affected_component = affected_component[:50] + "..."
            
            # Build mitigation steps
            mitigation_steps = []
            if cve.mitigation:
                mitigation_steps.append(cve.mitigation.primary_fix)
                mitigation_steps.extend(cve.mitigation.configuration_changes[:2])
            else:
                mitigation_steps = [
                    f"Apply security patch for {cve.cve_id}",
                    "Review vendor security advisory",
                    "Implement compensating controls"
                ]
            
            # Build preconditions
            preconditions = []
            if hasattr(cve, 'prerequisites') and cve.prerequisites:
                preconditions.append(cve.prerequisites)
            else:
                preconditions.append("Network access to vulnerable component")
            
            # Get assumptions from CVE
            threat_assumptions = []
            if hasattr(cve, 'assumptions') and cve.assumptions:
                threat_assumptions = cve.assumptions
            
            # Get impact category from CVE
            impact_cat = getattr(cve, 'impact_category', None) or "Server Compromise"
            
            # Determine attack complexity
            attack_complexity = "Low"
            if hasattr(cve, 'prerequisites') and cve.prerequisites:
                prereq_lower = cve.prerequisites.lower()
                if "authenticated" in prereq_lower or "admin" in prereq_lower:
                    attack_complexity = "Medium"
                if "chain" in prereq_lower or "multiple" in prereq_lower:
                    attack_complexity = "High"
            
            # Create threat
            threat = ArchitecturalThreat(
                threat_id=f"T-{next_id:03d}",
                category=category,
                description=f"Exploitation of {cve.cve_id}: {cve.summary[:200]}",
                affected_component=affected_component,
                severity=cve.severity.title(),
                mitigation_steps=mitigation_steps,
                preconditions=preconditions,
                impact=f"Successful exploitation could lead to {cve.exploitability if hasattr(cve, 'exploitability') and cve.exploitability else 'system compromise'}",
                cwe_id=cve.cwe_id,
                related_cve_id=cve.cve_id,
                impact_category=impact_cat,
                assumptions=threat_assumptions,
                attack_complexity=attack_complexity
            )
            
            promoted_threats.append(threat)
            next_id += 1
            
            logger.info(f"Promoted {cve.cve_id} to threat {threat.threat_id}")
        
        return promoted_threats
    
    def match_relevant_threats(
        self,
        inferred_components: List[Dict[str, Any]],
        generic_threats: List[ArchitecturalThreat],
        cve_threats: List[ThreatRecord]
    ) -> Dict[str, List]:
        """
        Analyze and filter threats for relevance to the architecture.
        
        Args:
            inferred_components: Component inference results
            generic_threats: STRIDE-based architectural threats
            cve_threats: CVEs discovered from vulnerability databases
            
        Returns:
            Dict with:
            - relevant_threats: Filtered and enriched architectural threats
            - relevant_weaknesses: Architecture-specific weaknesses
            - relevant_cves: CVEs relevant to this architecture
        """
        logger.info(f"Analyzing relevance for {len(cve_threats)} CVEs")
        
        if not cve_threats:
            logger.info("No CVEs to analyze")
            return {
                "relevant_threats": generic_threats,
                "relevant_weaknesses": [],
                "relevant_cves": []
            }
        
        # If no LLM client, use heuristic filtering
        if not self.client:
            logger.warning("LLM unavailable - using heuristic relevance filtering")
            return self._heuristic_relevance_filter(
                inferred_components, generic_threats, cve_threats
            )
        
        # Build and execute LLM prompt
        prompt = self._build_relevance_prompt(inferred_components, cve_threats)
        response_text = self._call_llm_with_retry(prompt)
        
        if not response_text:
            logger.warning("LLM analysis failed - using heuristic filtering")
            return self._heuristic_relevance_filter(
                inferred_components, generic_threats, cve_threats
            )
        
        # Parse response
        try:
            data = json.loads(response_text)
            output = ThreatRelevanceOutput.model_validate(data)
            
            logger.info(f"Received {len(output.assessments)} relevant CVE assessments")
            
            # Apply assessments to CVEs
            relevant_cves = self._apply_assessments_to_cves(
                cve_threats, output.assessments
            )
            
            # Promote critical CVEs to threats
            enriched_threats = self._promote_critical_cves_to_threats(
                relevant_cves, generic_threats
            )
            
            # Count stats
            filtered_count = len(cve_threats) - len(relevant_cves)
            promoted_count = len(enriched_threats) - len(generic_threats)
            
            logger.info(
                f"Relevance analysis complete: "
                f"{len(relevant_cves)} relevant CVEs, "
                f"{filtered_count} filtered out, "
                f"{promoted_count} promoted to threats"
            )
            
            return {
                "relevant_threats": enriched_threats,
                "relevant_weaknesses": [],  # Could be enriched in future
                "relevant_cves": relevant_cves
            }
            
        except Exception as e:
            logger.error(f"Failed to parse relevance response: {e}")
            return self._heuristic_relevance_filter(
                inferred_components, generic_threats, cve_threats
            )
    
    def _classify_cve_heuristic(self, cve: ThreatRecord) -> tuple:
        """
        Heuristically classify a CVE into vulnerability class and impact category.
        
        Returns:
            Tuple of (vulnerability_class, impact_category)
        """
        summary_lower = cve.summary.lower() if cve.summary else ""
        cwe = cve.cwe_id or ""
        
        # Determine vulnerability class based on summary and CWE
        vulnerability_class = "Unclassified"
        impact_category = "Availability Impact"  # Default
        
        # RCE / Serialization
        if any(x in summary_lower for x in ["remote code execution", "deserialization", "pickle", "yaml", "arbitrary code"]):
            vulnerability_class = "Serialization RCE"
            impact_category = "Server Compromise"
        elif "rce" in summary_lower or cwe in ["CWE-502", "CWE-94"]:
            vulnerability_class = "Code Execution"
            impact_category = "Server Compromise"
        # DoS patterns
        elif any(x in summary_lower for x in ["denial of service", "redos", "regular expression", "infinite loop", "memory exhaustion", "resource exhaustion"]):
            vulnerability_class = "Input Parsing DoS"
            impact_category = "Availability Impact"
        elif any(x in summary_lower for x in ["multipart", "accept-language", "parsing"]) and "dos" in summary_lower:
            vulnerability_class = "Input Parsing DoS"
            impact_category = "Availability Impact"
        # SQL Injection
        elif "sql injection" in summary_lower or cwe == "CWE-89":
            vulnerability_class = "SQL Injection"
            impact_category = "Data Compromise"
        # Path Traversal
        elif any(x in summary_lower for x in ["path traversal", "directory traversal", "lfi", "local file"]) or cwe == "CWE-22":
            vulnerability_class = "Path Traversal"
            impact_category = "Data Compromise"
        # XSS
        elif "cross-site scripting" in summary_lower or "xss" in summary_lower or cwe == "CWE-79":
            vulnerability_class = "XSS"
            impact_category = "User-Level Impact"
        # SSRF
        elif "ssrf" in summary_lower or "server-side request" in summary_lower or cwe == "CWE-918":
            vulnerability_class = "SSRF"
            impact_category = "Data Compromise"
        # Auth bypass
        elif any(x in summary_lower for x in ["authentication bypass", "access control", "authorization"]) or cwe in ["CWE-287", "CWE-306"]:
            vulnerability_class = "Authentication Bypass"
            impact_category = "Data Compromise"
        # Privilege escalation
        elif any(x in summary_lower for x in ["privilege escalation", "privilege elevation"]):
            vulnerability_class = "Privilege Escalation"
            impact_category = "Server Compromise"
        # Information disclosure
        elif "information disclosure" in summary_lower or cwe in ["CWE-200", "CWE-209"]:
            vulnerability_class = "Information Disclosure"
            impact_category = "Data Compromise"
        # Template issues
        elif any(x in summary_lower for x in ["template", "dictsort", "variable resolution"]):
            vulnerability_class = "Template Engine Disclosure"
            impact_category = "Data Compromise"
        # Memory corruption
        elif any(x in summary_lower for x in ["buffer overflow", "memory corruption", "heap", "stack"]):
            vulnerability_class = "Memory Corruption"
            impact_category = "Server Compromise"
        
        return vulnerability_class, impact_category
    
    def _generate_assumptions_heuristic(self, cve: ThreatRecord) -> List[str]:
        """Generate assumptions based on CVE content."""
        assumptions = []
        summary_lower = cve.summary.lower() if cve.summary else ""
        
        # File upload related
        if any(x in summary_lower for x in ["upload", "multipart", "file"]):
            assumptions.append("File uploads enabled on the application")
        
        # Template related
        if any(x in summary_lower for x in ["template", "dictsort"]):
            assumptions.append("User input passed to template filters")
        
        # i18n related
        if any(x in summary_lower for x in ["i18n", "locale", "language", "internationalized"]):
            assumptions.append("Internationalized URLs (i18n_patterns) enabled")
        
        # Windows specific
        if "windows" in summary_lower:
            assumptions.append("Windows deployment environment")
        
        # Version specific
        if "before" in summary_lower:
            assumptions.append("Vulnerable version of component deployed (check version)")
        
        # Auth required - QUALIFY STRONG ASSUMPTIONS
        if any(x in summary_lower for x in ["authenticated", "authentication required"]):
            assumptions.append("Attacker has valid user credentials (via phishing, credential stuffing, or prior compromise)")
        
        # Database privilege requirements - ALWAYS QUALIFY THESE
        if any(x in summary_lower for x in ["sql", "database", "postgresql", "mysql", "query"]):
            if any(x in summary_lower for x in ["authenticated", "privilege", "permission", "admin", "create"]):
                # Qualify the assumption - don't assume god-mode
                assumptions.append("Attacker can gain database access via application-layer vulnerabilities (e.g., SQL Injection, compromised app credentials, or misconfigured connection pooling)")
        
        # Privilege escalation context - qualify how privileges were obtained
        if any(x in summary_lower for x in ["privilege escalation", "elevation of privilege"]):
            assumptions.append("Initial access obtained via separate vulnerability or compromised credentials")
        
        # Network access assumptions
        if any(x in summary_lower for x in ["remote", "network", "http"]):
            assumptions.append("Target service is network-accessible to the attacker")
        
        # Add a default if no specific assumptions
        if not assumptions:
            assumptions.append("Component is exposed and reachable")
            assumptions.append("Default configuration in use")
        
        return assumptions
    
    def _qualify_dangerous_assumptions(self, assumptions: List[str]) -> List[str]:
        """
        Review assumptions and qualify any that are too strong without justification.
        
        This prevents credibility issues where assumptions imply god-mode access.
        """
        qualified = []
        
        # Patterns that need qualification
        dangerous_patterns = {
            # Original assumption pattern -> Qualified version
            "attacker has sql": "Attacker can gain SQL execution privileges via application-layer vulnerabilities (e.g., SQL Injection or compromised application credentials)",
            "attacker has database": "Attacker can access the database via application-layer vulnerabilities or misconfigured access controls",
            "attacker has admin": "Attacker can obtain admin privileges via privilege escalation or compromised admin credentials",
            "attacker has root": "Attacker can obtain root access via privilege escalation from initial foothold",
            "attacker has shell": "Attacker can obtain shell access via RCE vulnerability or compromised credentials",
            "attacker can execute": "Attacker can achieve code execution via identified vulnerabilities in the application layer",
        }
        
        for assumption in assumptions:
            assumption_lower = assumption.lower()
            was_qualified = False
            
            for pattern, qualified_version in dangerous_patterns.items():
                if pattern in assumption_lower:
                    # Check if already qualified (contains "via" or "through")
                    if " via " not in assumption_lower and " through " not in assumption_lower:
                        qualified.append(qualified_version)
                        was_qualified = True
                        break
            
            if not was_qualified:
                qualified.append(assumption)
        
        return qualified
    
    def _heuristic_relevance_filter(
        self,
        inferred_components: List[Dict[str, Any]],
        generic_threats: List[ArchitecturalThreat],
        cve_threats: List[ThreatRecord]
    ) -> Dict[str, List]:
        """
        Fallback heuristic-based relevance filtering.
        
        Args:
            inferred_components: Component inference results
            generic_threats: STRIDE-based architectural threats
            cve_threats: CVEs discovered from vulnerability databases
            
        Returns:
            Filtered results using heuristics
        """
        logger.info("Using heuristic relevance filtering")
        
        # Extract product keywords from components
        product_keywords = set()
        for comp in inferred_components:
            name = comp.get("component_name", "").lower()
            products = comp.get("inferred_product_categories", [])
            
            # Add component name words
            for word in name.split():
                if len(word) > 3:
                    product_keywords.add(word)
            
            # Add inferred products
            for product in products:
                if product.lower() != "generic":
                    product_keywords.add(product.lower())
        
        # Filter CVEs by keyword matching
        relevant_cves = []
        class_counts: Dict[str, int] = {}  # Track CVEs per class
        class_representatives: Dict[str, ThreatRecord] = {}  # Best CVE per class
        
        for cve in cve_threats:
            # Check if CVE matches any component
            cve_text = f"{cve.affected_products} {cve.summary}".lower()
            
            is_relevant = False
            for keyword in product_keywords:
                if keyword in cve_text:
                    is_relevant = True
                    break
            
            # Also keep HIGH/CRITICAL severity and actively exploited
            if cve.severity in ["CRITICAL", "HIGH"] or cve.is_actively_exploited:
                is_relevant = True
            
            if is_relevant:
                # Classify CVE
                vuln_class, impact_cat = self._classify_cve_heuristic(cve)
                assumptions = self._generate_assumptions_heuristic(cve)
                # Qualify any dangerous assumptions that imply god-mode
                assumptions = self._qualify_dangerous_assumptions(assumptions)
                
                # Add heuristic assessment
                cve.relevance_status = "Medium"  # Default for heuristic
                cve.prerequisites = "Network access to vulnerable component"
                cve.exploitability = "See CVE description"
                cve.likelihood = "Medium"
                cve.justification = f"Matches architecture component keyword"
                cve.vulnerability_class = vuln_class
                cve.impact_category = impact_cat
                cve.assumptions = assumptions
                
                # Track for representative selection
                class_counts[vuln_class] = class_counts.get(vuln_class, 0) + 1
                
                # Select representative (highest CVSS or actively exploited)
                current_rep = class_representatives.get(vuln_class)
                if current_rep is None:
                    class_representatives[vuln_class] = cve
                    cve.is_representative = True
                else:
                    # Compare - prefer KEV, then higher CVSS
                    current_score = current_rep.cvss_score or 0
                    new_score = cve.cvss_score or 0
                    if cve.is_actively_exploited and not current_rep.is_actively_exploited:
                        current_rep.is_representative = False
                        cve.is_representative = True
                        class_representatives[vuln_class] = cve
                    elif new_score > current_score and not current_rep.is_actively_exploited:
                        current_rep.is_representative = False
                        cve.is_representative = True
                        class_representatives[vuln_class] = cve
                    else:
                        cve.is_representative = False
                
                relevant_cves.append(cve)
        
        # Log class distribution
        logger.info(f"CVE vulnerability classes: {class_counts}")
        
        # Promote critical CVEs
        enriched_threats = self._promote_critical_cves_to_threats(
            relevant_cves, generic_threats
        )
        
        filtered_count = len(cve_threats) - len(relevant_cves)
        logger.info(f"Heuristic filter: {len(relevant_cves)} relevant, {filtered_count} filtered")
        
        return {
            "relevant_threats": enriched_threats,
            "relevant_weaknesses": [],
            "relevant_cves": relevant_cves
        }


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "ThreatRelevanceAgent",
    "CVERelevanceAssessment",
    "ThreatRelevanceOutput",
    "RELEVANCE_SYSTEM_INSTRUCTION",
]
