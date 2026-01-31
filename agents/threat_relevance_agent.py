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

## LIKELIHOOD CALIBRATION:

**High likelihood**: 
- No authentication needed
- Default ports exposed
- No special configuration
- Public exploit available

**Medium likelihood** (most CVEs should be here):
- Requires valid credentials
- Requires specific query patterns
- Requires enabled but non-default feature

**Low likelihood**:
- Requires admin credentials
- Requires unusual configuration
- Requires chained vulnerabilities
- Theoretical with no public exploit

## IMPORTANT: Prerequisites affect likelihood!

Example: MariaDB CVE requiring specific storage engine + authenticated user + specific SQL query
- Even if CVSS is 7.5, likelihood is LOW because prerequisites are significant
- justification MUST explain why likelihood is low despite high CVSS

## OUTPUT:
JSON with "assessments" array. Each assessment:
- cve_id: EXACT ID from input
- relevance_status: High/Medium/Low (no Irrelevant - just omit those)
- prerequisites: Array of SPECIFIC requirements
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
                        }
                    },
                    "required": ["cve_id", "relevance_status", "justification"]
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
                related_cve_id=cve.cve_id
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
                # Add heuristic assessment
                cve.relevance_status = "Medium"  # Default for heuristic
                cve.prerequisites = "Network access to vulnerable component"
                cve.exploitability = "See CVE description"
                cve.likelihood = "Medium"
                cve.justification = f"Matches architecture component keyword"
                
                relevant_cves.append(cve)
        
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
