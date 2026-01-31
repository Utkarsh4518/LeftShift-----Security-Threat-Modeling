"""
Report Synthesizer Agent for Left<<Shift Threat Modeling System.

This agent generates comprehensive threat modeling reports in Markdown format.
It synthesizes all analysis results into a structured, actionable report.

CRITICAL: This agent NEVER invents or hallucinates content.
All data in the report comes directly from the input analysis results.
"""

import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from google import genai
from google.genai import types
from pydantic import BaseModel

from tools.models import (
    ArchitectureSchema,
    ArchitecturalThreat,
    ArchitecturalWeakness,
    ThreatRecord,
    AttackPath,
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
# Report Structure System Instruction
# =============================================================================

REPORT_SYSTEM_INSTRUCTION = """You are a Security Report Synthesizer generating threat modeling reports.

## CRITICAL RULES - READ CAREFULLY (VIOLATION = REPORT FAILURE):

1. **NEVER INVENT OR HALLUCINATE CONTENT**
   - Only use data provided in the input JSON
   - If data is missing, state "No data provided" or "N/A"
   - Never create fake CVE IDs, threat IDs, or component names
   - Every ID, name, and value must come from the input data

2. **DATA INTEGRITY FOR CVEs**
   - CVE IDs must EXACTLY match those in the input "cves" array
   - You may ONLY reference CVE IDs that appear in the input
   - If a threat has no related_cve_id field, DO NOT associate it with any CVE
   - STRIDE threats (T-001 to T-015 typically) are theoretical - they have NO CVE mappings unless explicitly set
   - Only threats PROMOTED from CVEs (which have related_cve_id set) should appear in Threat-CVE matrix

3. **DATA INTEGRITY FOR THREATS**
   - Threat IDs must exactly match those in the input
   - Do not add or remove any threats
   - Do not modify threat descriptions or severities

4. **CONSISTENCY**
   - Use the exact same IDs throughout the report
   - No contradictions between sections
   - Counts must match the actual input data
   - If input has 28 CVEs, report must reference exactly 28 CVEs (no more, no less)

## REPORT STRUCTURE (12 Sections):

Generate a Markdown report with these sections:

### 1. EXECUTIVE SUMMARY
- Project name and description
- Total threats, CVEs, and weaknesses found
- Overall risk assessment (based on severity counts)
- Top 3 priority actions

### 2. ARCHITECTURE EXTRACTION
- **Components List**: Table of all components with type
- **Data Flows**: Table showing source, destination, protocol
- **Trust Boundaries**: List of identified trust boundaries

### 3. COMPONENT INVENTORY TABLE
| Component | Type | Inferred Technology | Criticality | Notes |

Criticality based on:
- High: Database, Auth service, API Gateway
- Medium: Application servers, caches
- Low: CDN, static content

### 4. STRIDE THREAT ENUMERATION
| Threat ID | STRIDE Category | CWE ID | Affected Component | Description | Severity | Mitigation Steps |

Include ALL threats from input - do not add or remove any.

### 5. ARCHITECTURAL WEAKNESSES
| Weakness ID | Title | Description | Impact | Recommended Mitigation |

Include ALL weaknesses from input.

### 6. CVE DISCOVERY RESULTS
For each CVE from the input "cves" array:
- CVE ID (MUST be from input), Severity, CVSS Score
- Affected Products (from input data)
- Summary (from input data - do not rewrite)
- Is Actively Exploited (CISA KEV status from input)
- Relevance assessment and prerequisites (from input)

**IF NO CVEs IN INPUT:**
If the "cves" array is empty or not provided, write:
"No specific CVEs were identified for this architecture. This is expected for architecture-level threat modeling where:
- Components are identified by service type (e.g., 'EC2 Instance') rather than specific software versions
- The analysis focuses on architectural risks (STRIDE) rather than software vulnerabilities
- CVE discovery requires specific product names and versions (e.g., 'nginx 1.18.0')

To enable CVE discovery, provide specific software versions deployed on each component."

**ABSOLUTE RULES:**
- List ONLY CVEs that exist in the input "cves" array
- Do not add any CVE IDs not in the input
- Do not remove any CVEs from the input
- The CVE count in this section must match input exactly

### 7. THREAT ↔ CVE CORRELATION MATRIX
| Threat ID | Related CVE | Relationship Type | Notes |

**ABSOLUTE RULES FOR THIS SECTION - VIOLATION = FAILURE:**
- ONLY include rows where the threat object has a non-null, non-empty "related_cve_id" field
- The CVE ID in this table MUST exactly match a CVE ID from the input CVE list
- If threat.related_cve_id is null, empty, or missing → DO NOT create a row for that threat
- NEVER infer, guess, or conceptually map CVEs to threats based on descriptions
- NEVER use CVE IDs that do not appear in the input data
- If zero valid mappings exist, write: "No direct Threat-CVE correlations exist. STRIDE threats are architecture-derived, not CVE-derived."
- Relationship Type must be: "CVE Promoted to Threat" for threats created from CVEs

### 8. ATTACK PATH SIMULATIONS
For each attack path in input:
- Path ID and Name
- Description
- Impact and Likelihood
- Step-by-step attack sequence
- Referenced threats and CVEs

Only include attack paths from input data.

### 9. COMPONENT SECURITY PROFILES
For each component:
- Threat count affecting this component
- CVE count affecting this component
- Risk level (Critical/High/Medium/Low)
- Key vulnerabilities
- Priority mitigations

### 10. NIST 800-53 CONTROL MAPPING
| Risk Area | Threat ID(s) | Recommended NIST Control | Control Family | Rationale |

Map threats to appropriate NIST 800-53 controls:
- AC (Access Control)
- AU (Audit and Accountability)
- CA (Assessment, Authorization)
- CM (Configuration Management)
- IA (Identification and Authentication)
- SC (System and Communications Protection)
- SI (System and Information Integrity)

### 11. HARDENING PLAN
Organize mitigations by timeline:

**Quick Wins (< 1 day)**
- Immediate configuration changes
- Enable existing security features

**Short-Term (1-4 weeks)**
- Patching and updates
- Access control improvements
- Monitoring enhancements

**Long-Term (1-3 months)**
- Architecture changes
- Major security implementations
- Process improvements

### 12. APPENDIX
- Report generation timestamp
- Data sources used
- Methodology notes

## OUTPUT FORMAT:
- Clean, valid Markdown
- Proper headers (# ## ###)
- Well-formatted tables
- Code blocks for technical details
- No HTML tags
"""


# =============================================================================
# JSON Serialization Helper
# =============================================================================

def json_serial(obj: Any) -> Any:
    """
    JSON serializer for objects not serializable by default json code.
    
    Handles:
    - datetime objects
    - Pydantic models
    - Other custom types
    """
    # Handle datetime
    if isinstance(obj, datetime):
        return obj.isoformat()
    
    # Handle Pydantic models
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    
    # Handle objects with __dict__
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    
    raise TypeError(f"Type {type(obj)} not serializable")


def serialize_for_report(data: Any) -> str:
    """Serialize data structure for report generation."""
    return json.dumps(data, indent=2, default=json_serial)


# =============================================================================
# Report Synthesizer Agent
# =============================================================================

class ReportSynthesizerAgent:
    """
    Agent for synthesizing comprehensive threat modeling reports.
    
    This agent:
    1. Collects all analysis results (threats, CVEs, weaknesses, attack paths)
    2. Generates a structured Markdown report
    3. Ensures data integrity - NEVER invents content
    
    Uses Google Gemini for report generation.
    """
    
    def __init__(self, model_name: str = PRIMARY_MODEL):
        """
        Initialize the Report Synthesizer Agent.
        
        Args:
            model_name: Gemini model to use for report generation
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
                logger.info(f"Gemini client initialized for report synthesis")
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini client: {e}")
                self.client = None
        else:
            logger.warning("GEMINI_API_KEY not configured")
            self.client = None
    
    def _call_llm_with_retry(
        self,
        prompt: str,
        model: str = None,
        attempt: int = 1
    ) -> Optional[str]:
        """Call LLM with retry logic."""
        if not self.client:
            return None
        
        model = model or self.model_name
        
        try:
            logger.info(f"Report generation attempt {attempt}/{MAX_RETRIES} using {model}")
            
            full_prompt = f"{REPORT_SYSTEM_INSTRUCTION}\n\n{prompt}"
            
            response = self.client.models.generate_content(
                model=model,
                contents=full_prompt,
                config=types.GenerateContentConfig(
                    temperature=0.3,
                    max_output_tokens=16000  # Allow long reports
                )
            )
            
            return response.text
            
        except Exception as e:
            logger.warning(f"LLM call failed (attempt {attempt}): {e}")
            
            if attempt < MAX_RETRIES:
                delay = BASE_DELAY * (2 ** (attempt - 1))
                time.sleep(delay)
                next_model = FALLBACK_MODEL if attempt == MAX_RETRIES - 1 else model
                return self._call_llm_with_retry(prompt, next_model, attempt + 1)
            
            return None
    
    def synthesize_report_data(
        self,
        architecture: ArchitectureSchema,
        inferred_components: List[Dict[str, Any]],
        threats: List[ArchitecturalThreat],
        weaknesses: List[ArchitecturalWeakness],
        cves: List[ThreatRecord],
        attack_paths: List[AttackPath] = None
    ) -> Dict[str, Any]:
        """
        Prepare all data for report generation.
        
        Args:
            architecture: The analyzed architecture
            inferred_components: Component inference results
            threats: STRIDE threats identified
            weaknesses: Architectural weaknesses
            cves: Relevant CVEs
            attack_paths: Attack path simulations
            
        Returns:
            Structured data dictionary for report generation
        """
        return {
            "project_name": architecture.project_name,
            "project_description": architecture.description,
            "architecture": {
                "components": [c.model_dump() if hasattr(c, "model_dump") else c 
                              for c in architecture.components],
                "data_flows": [f.model_dump() if hasattr(f, "model_dump") else f 
                              for f in architecture.data_flows],
                "trust_boundaries": architecture.trust_boundaries
            },
            "inferred_components": inferred_components,
            "threats": [t.model_dump() if hasattr(t, "model_dump") else t 
                       for t in threats],
            "weaknesses": [w.model_dump() if hasattr(w, "model_dump") else w 
                          for w in weaknesses],
            "cves": [c.model_dump() if hasattr(c, "model_dump") else c 
                    for c in cves],
            "attack_paths": [p.model_dump() if hasattr(p, "model_dump") else p 
                            for p in (attack_paths or [])],
            "summary_stats": {
                "total_components": len(architecture.components),
                "total_threats": len(threats),
                "total_weaknesses": len(weaknesses),
                "total_cves": len(cves),
                "total_attack_paths": len(attack_paths or []),
                "critical_cves": sum(1 for c in cves if c.severity == "CRITICAL"),
                "high_cves": sum(1 for c in cves if c.severity == "HIGH"),
                "actively_exploited": sum(1 for c in cves if c.is_actively_exploited),
            },
            "generation_timestamp": datetime.now().isoformat()
        }
    
    def _build_report_prompt(self, report_data: Dict[str, Any]) -> str:
        """Build the prompt for report generation."""
        # Serialize data
        data_json = serialize_for_report(report_data)
        
        # Extract valid CVE IDs from input
        valid_cve_ids = []
        for cve in report_data.get("cves", []):
            if isinstance(cve, dict):
                cve_id = cve.get("cve_id", "")
            elif hasattr(cve, "cve_id"):
                cve_id = cve.cve_id
            else:
                continue
            if cve_id:
                valid_cve_ids.append(cve_id)
        
        # Extract valid threat-CVE mappings
        threat_cve_mappings = []
        for threat in report_data.get("threats", []):
            if isinstance(threat, dict):
                threat_id = threat.get("threat_id", "")
                related_cve = threat.get("related_cve_id")
            elif hasattr(threat, "threat_id"):
                threat_id = threat.threat_id
                related_cve = getattr(threat, "related_cve_id", None)
            else:
                continue
            
            if threat_id and related_cve and related_cve in valid_cve_ids:
                threat_cve_mappings.append(f"{threat_id} -> {related_cve}")
        
        prompt = f"""Generate a comprehensive threat modeling report for the following analysis data.

## CRITICAL DATA INTEGRITY RULES:

### VALID CVE IDs (ONLY these may appear in your report):
{json.dumps(valid_cve_ids, indent=2) if valid_cve_ids else '[]  (No CVEs in input)'}

### VALID THREAT-CVE MAPPINGS (ONLY these may appear in Section 7):
{chr(10).join(threat_cve_mappings) if threat_cve_mappings else 'NONE - No threats have related_cve_id set. Section 7 should state: "No direct Threat-CVE correlations exist."'}

### RULES:
- You may ONLY use CVE IDs from the list above
- You may ONLY create Threat-CVE rows for the mappings listed above
- STRIDE threats WITHOUT related_cve_id must NOT appear in Section 7
- DO NOT invent conceptual or illustrative CVE mappings
- If a threat description mentions a vulnerability type, do NOT map it to a random CVE

## ANALYSIS DATA:

```json
{data_json}
```

## STATISTICS SUMMARY:
- Project: {report_data['project_name']}
- Components: {report_data['summary_stats']['total_components']}
- Threats: {report_data['summary_stats']['total_threats']}
- Weaknesses: {report_data['summary_stats']['total_weaknesses']}
- CVEs: {report_data['summary_stats']['total_cves']}
- Attack Paths: {report_data['summary_stats']['total_attack_paths']}
- Critical CVEs: {report_data['summary_stats']['critical_cves']}
- Actively Exploited: {report_data['summary_stats']['actively_exploited']}

Generate the complete 12-section Markdown report now. 

FINAL REMINDER: 
- Section 7 (Threat-CVE Matrix) must ONLY contain the {len(threat_cve_mappings)} valid mappings listed above
- If zero valid mappings, state "No direct Threat-CVE correlations exist"
- NEVER guess or infer CVE relationships"""

        return prompt
    
    def generate_markdown_report(
        self,
        report_data: Dict[str, Any]
    ) -> str:
        """
        Generate the final Markdown report.
        
        Args:
            report_data: Prepared report data from synthesize_report_data()
            
        Returns:
            Complete Markdown report string
        """
        if not self.client:
            logger.warning("No LLM client - generating basic report")
            return self._generate_fallback_report(report_data)
        
        prompt = self._build_report_prompt(report_data)
        
        logger.info("Generating comprehensive report...")
        report = self._call_llm_with_retry(prompt)
        
        if not report:
            logger.warning("LLM report generation failed - using fallback")
            return self._generate_fallback_report(report_data)
        
        logger.info(f"Report generated: {len(report)} characters")
        return report
    
    def _generate_fallback_report(self, report_data: Dict[str, Any]) -> str:
        """Generate a basic report without LLM."""
        stats = report_data["summary_stats"]
        
        report = f"""# Threat Modeling Report: {report_data['project_name']}

**Generated:** {report_data['generation_timestamp']}

---

## 1. Executive Summary

This report summarizes the threat modeling analysis for **{report_data['project_name']}**.

### Key Findings:
- **Components Analyzed:** {stats['total_components']}
- **Threats Identified:** {stats['total_threats']}
- **Weaknesses Found:** {stats['total_weaknesses']}
- **CVEs Discovered:** {stats['total_cves']}
- **Attack Paths Simulated:** {stats['total_attack_paths']}

### Risk Overview:
- Critical CVEs: {stats['critical_cves']}
- High Severity CVEs: {stats['high_cves']}
- Actively Exploited (CISA KEV): {stats['actively_exploited']}

---

## 2. Architecture Extraction

### Components
| Name | Type |
|------|------|
"""
        for comp in report_data["architecture"]["components"]:
            name = comp.get("name", "Unknown")
            ctype = comp.get("type", "Unknown")
            report += f"| {name} | {ctype} |\n"
        
        report += """
### Data Flows
| Source | Destination | Protocol |
|--------|-------------|----------|
"""
        for flow in report_data["architecture"]["data_flows"]:
            src = flow.get("source", "Unknown")
            dst = flow.get("destination", "Unknown")
            proto = flow.get("protocol", "Unknown")
            report += f"| {src} | {dst} | {proto} |\n"
        
        report += f"""
### Trust Boundaries
"""
        for boundary in report_data["architecture"]["trust_boundaries"]:
            report += f"- {boundary}\n"
        
        report += """
---

## 3. Component Inventory

| Component | Type | Inferred Technology | Confidence |
|-----------|------|---------------------|------------|
"""
        for comp in report_data.get("inferred_components", []):
            name = comp.get("component_name", "Unknown")
            ctype = comp.get("type", "Unknown")
            cats = comp.get("inferred_product_categories", ["Unknown"])
            conf = comp.get("confidence", 0)
            report += f"| {name} | {ctype} | {cats[0] if cats else 'Unknown'} | {conf:.0%} |\n"
        
        report += """
---

## 4. STRIDE Threat Enumeration

| ID | Category | CWE | Component | Description | Severity |
|----|----------|-----|-----------|-------------|----------|
"""
        for threat in report_data.get("threats", []):
            tid = threat.get("threat_id", "N/A")
            cat = threat.get("category", "Unknown")
            cwe = threat.get("cwe_id", "N/A")
            comp = threat.get("affected_component", "Unknown")
            desc = threat.get("description", "")[:50] + "..."
            sev = threat.get("severity", "Unknown")
            report += f"| {tid} | {cat} | {cwe} | {comp} | {desc} | {sev} |\n"
        
        report += """
---

## 5. Architectural Weaknesses

| ID | Title | Impact |
|----|-------|--------|
"""
        for weakness in report_data.get("weaknesses", []):
            wid = weakness.get("weakness_id", "N/A")
            title = weakness.get("title", "Unknown")
            impact = weakness.get("impact", "Unknown")[:50] + "..."
            report += f"| {wid} | {title} | {impact} |\n"
        
        report += """
---

## 6. CVE Discovery Results

| CVE ID | Severity | CVSS | Actively Exploited | Affected Products |
|--------|----------|------|-------------------|-------------------|
"""
        for cve in report_data.get("cves", []):
            cid = cve.get("cve_id", "N/A")
            sev = cve.get("severity", "Unknown")
            cvss = cve.get("cvss_score", "N/A")
            kev = "Yes" if cve.get("is_actively_exploited") else "No"
            products = cve.get("affected_products", "Unknown")[:30]
            report += f"| {cid} | {sev} | {cvss} | {kev} | {products} |\n"
        
        report += """
---

## 7-12. Additional Sections

*Full report requires LLM generation for detailed analysis.*

---

**Note:** This is a fallback report generated without LLM assistance.
For the complete 12-section report, ensure the OpenAI API is configured.
"""
        
        return report
    
    def generate_full_report(
        self,
        architecture: ArchitectureSchema,
        inferred_components: List[Dict[str, Any]],
        threats: List[ArchitecturalThreat],
        weaknesses: List[ArchitecturalWeakness],
        cves: List[ThreatRecord],
        attack_paths: List[AttackPath] = None,
        output_path: str = None
    ) -> str:
        """
        Generate a complete threat modeling report.
        
        This is the main entry point that combines data synthesis and report generation.
        
        Args:
            architecture: The analyzed architecture
            inferred_components: Component inference results
            threats: STRIDE threats identified
            weaknesses: Architectural weaknesses
            cves: Relevant CVEs
            attack_paths: Attack path simulations
            output_path: Optional path to save the report
            
        Returns:
            Complete Markdown report string
        """
        # Synthesize data
        report_data = self.synthesize_report_data(
            architecture=architecture,
            inferred_components=inferred_components,
            threats=threats,
            weaknesses=weaknesses,
            cves=cves,
            attack_paths=attack_paths
        )
        
        # Generate report
        report = self.generate_markdown_report(report_data)
        
        # Save if path provided
        if output_path:
            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(report)
                logger.info(f"Report saved to: {output_path}")
            except Exception as e:
                logger.error(f"Failed to save report: {e}")
        
        return report


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "ReportSynthesizerAgent",
    "REPORT_SYSTEM_INSTRUCTION",
    "json_serial",
    "serialize_for_report",
]
