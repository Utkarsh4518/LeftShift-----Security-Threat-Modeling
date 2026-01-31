"""
Threat Intelligence API Integration for Left<<Shift.

This module provides integration with:
- NVD (National Vulnerability Database) for CVE data
- CISA KEV (Known Exploited Vulnerabilities) catalog
"""

import logging
import os
import re
import time
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set

import requests
from dotenv import load_dotenv

# Import nvdlib for NVD API queries
try:
    import nvdlib
    NVDLIB_AVAILABLE = True
except ImportError:
    NVDLIB_AVAILABLE = False
    logging.warning("nvdlib not available - NVD queries will be disabled")

from tools.models import ThreatRecord, ThreatSearchResults

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# Configuration Constants
# =============================================================================

# NVD API key (optional but recommended for higher rate limits)
NVD_API_KEY = os.getenv("NVD_API_KEY")

# CISA KEV catalog URL
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Rate limiting - delay between NVD API calls (seconds)
NVD_RATE_LIMIT_DELAY = 1.0 if NVD_API_KEY else 6.0  # 6 seconds without API key

# CVE recency filter - only fetch CVEs from last N years
CVE_RECENCY_YEARS = 5

# Severity filter - minimum CVSS score
MIN_CVSS_SCORE = 7.0  # HIGH and CRITICAL only

# =============================================================================
# Product Mapping for Accurate CPE Matching
# =============================================================================

PRODUCT_MAPPING: Dict[str, Dict[str, Any]] = {
    # Web Servers
    "nginx": {
        "search_term": "nginx",
        "allowed_vendors": {"nginx", "f5", "nginx inc"},
        "allowed_products": {"nginx", "nginx plus", "nginx open source"},
        "cpe_vendor": "nginx"
    },
    "apache": {
        "search_term": "apache http server",
        "allowed_vendors": {"apache", "apache software foundation"},
        "allowed_products": {"http_server", "apache http server", "httpd"},
        "cpe_vendor": "apache"
    },
    "httpd": {
        "search_term": "apache http server",
        "allowed_vendors": {"apache"},
        "allowed_products": {"http_server", "httpd"},
        "cpe_vendor": "apache"
    },
    
    # Databases
    "postgresql": {
        "search_term": "postgresql",
        "allowed_vendors": {"postgresql", "postgresql global development group"},
        "allowed_products": {"postgresql"},
        "cpe_vendor": "postgresql"
    },
    "postgres": {
        "search_term": "postgresql",
        "allowed_vendors": {"postgresql"},
        "allowed_products": {"postgresql"},
        "cpe_vendor": "postgresql"
    },
    "mysql": {
        "search_term": "mysql",
        "allowed_vendors": {"mysql", "oracle", "mysql ab"},
        "allowed_products": {"mysql", "mysql server"},
        "cpe_vendor": "oracle"
    },
    "mariadb": {
        "search_term": "mariadb",
        "allowed_vendors": {"mariadb", "mariadb corporation ab"},
        "allowed_products": {"mariadb", "mariadb server"},
        "cpe_vendor": "mariadb"
    },
    "mongodb": {
        "search_term": "mongodb",
        "allowed_vendors": {"mongodb", "mongodb inc"},
        "allowed_products": {"mongodb"},
        "cpe_vendor": "mongodb"
    },
    
    # Cache/In-Memory
    "redis": {
        "search_term": "redis",
        "allowed_vendors": {"redis", "redislabs", "redis labs"},
        "allowed_products": {"redis"},
        "cpe_vendor": "redis"
    },
    "memcached": {
        "search_term": "memcached",
        "allowed_vendors": {"memcached", "danga"},
        "allowed_products": {"memcached"},
        "cpe_vendor": "memcached"
    },
    
    # Application Frameworks
    "django": {
        "search_term": "django",
        "allowed_vendors": {"djangoproject", "django software foundation"},
        "allowed_products": {"django"},
        "cpe_vendor": "djangoproject"
    },
    "flask": {
        "search_term": "flask",
        "allowed_vendors": {"palletsprojects", "pocoo"},
        "allowed_products": {"flask"},
        "cpe_vendor": "palletsprojects"
    },
    "spring": {
        "search_term": "spring framework",
        "allowed_vendors": {"vmware", "pivotal", "springsource"},
        "allowed_products": {"spring_framework", "spring boot", "spring security"},
        "cpe_vendor": "vmware"
    },
    "express": {
        "search_term": "express.js",
        "allowed_vendors": {"expressjs", "openjsf"},
        "allowed_products": {"express"},
        "cpe_vendor": "expressjs"
    },
    "rails": {
        "search_term": "ruby on rails",
        "allowed_vendors": {"rubyonrails"},
        "allowed_products": {"rails", "ruby_on_rails"},
        "cpe_vendor": "rubyonrails"
    },
    
    # Message Queues
    "rabbitmq": {
        "search_term": "rabbitmq",
        "allowed_vendors": {"vmware", "pivotal", "rabbitmq"},
        "allowed_products": {"rabbitmq"},
        "cpe_vendor": "vmware"
    },
    "kafka": {
        "search_term": "apache kafka",
        "allowed_vendors": {"apache"},
        "allowed_products": {"kafka"},
        "cpe_vendor": "apache"
    },
    
    # Container/Orchestration
    "docker": {
        "search_term": "docker",
        "allowed_vendors": {"docker", "moby"},
        "allowed_products": {"docker", "docker engine", "docker desktop"},
        "cpe_vendor": "docker"
    },
    "kubernetes": {
        "search_term": "kubernetes",
        "allowed_vendors": {"kubernetes", "k8s"},
        "allowed_products": {"kubernetes"},
        "cpe_vendor": "kubernetes"
    },
    
    # Search
    "elasticsearch": {
        "search_term": "elasticsearch",
        "allowed_vendors": {"elastic", "elasticsearch"},
        "allowed_products": {"elasticsearch"},
        "cpe_vendor": "elastic"
    },
    
    # Proxy/Load Balancer
    "haproxy": {
        "search_term": "haproxy",
        "allowed_vendors": {"haproxy"},
        "allowed_products": {"haproxy"},
        "cpe_vendor": "haproxy"
    },
    "traefik": {
        "search_term": "traefik",
        "allowed_vendors": {"traefik", "containous"},
        "allowed_products": {"traefik"},
        "cpe_vendor": "traefik"
    },
    
    # JavaScript Runtime
    "nodejs": {
        "search_term": "node.js",
        "allowed_vendors": {"nodejs", "node.js"},
        "allowed_products": {"node.js", "nodejs"},
        "cpe_vendor": "nodejs"
    },
    "node.js": {
        "search_term": "node.js",
        "allowed_vendors": {"nodejs"},
        "allowed_products": {"node.js"},
        "cpe_vendor": "nodejs"
    },
    
    # CI/CD
    "jenkins": {
        "search_term": "jenkins",
        "allowed_vendors": {"jenkins", "cloudbees"},
        "allowed_products": {"jenkins"},
        "cpe_vendor": "jenkins"
    },
    "gitlab": {
        "search_term": "gitlab",
        "allowed_vendors": {"gitlab"},
        "allowed_products": {"gitlab"},
        "cpe_vendor": "gitlab"
    },
}


# =============================================================================
# CISA KEV Integration
# =============================================================================

@lru_cache(maxsize=1)
def _fetch_kev_cve_ids() -> Set[str]:
    """
    Fetch CISA KEV (Known Exploited Vulnerabilities) catalog.
    
    Returns:
        Set of CVE IDs that are known to be actively exploited
    """
    logger.info("Fetching CISA KEV catalog...")
    
    try:
        response = requests.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        kev_ids = {vuln.get("cveID") for vuln in vulnerabilities if vuln.get("cveID")}
        
        logger.info(f"Loaded {len(kev_ids)} CVE IDs from CISA KEV catalog")
        return kev_ids
        
    except requests.RequestException as e:
        logger.error(f"Failed to fetch CISA KEV catalog: {e}")
        return set()
    except (KeyError, ValueError) as e:
        logger.error(f"Failed to parse CISA KEV catalog: {e}")
        return set()


def is_actively_exploited(cve_id: str) -> bool:
    """
    Check if a CVE is in the CISA KEV catalog.
    
    Args:
        cve_id: CVE identifier to check
        
    Returns:
        True if the CVE is known to be actively exploited
    """
    kev_ids = _fetch_kev_cve_ids()
    return cve_id in kev_ids


# =============================================================================
# Product Identifier Detection
# =============================================================================

def _looks_like_software_identifier(name: str) -> bool:
    """
    Check if a component name looks like a specific software product.
    
    This is imported from component_understanding_agent but duplicated here
    for independence.
    """
    if not name or not name.strip():
        return False
    
    normalized = name.lower().strip()
    
    # Check against product mapping
    for product_key in PRODUCT_MAPPING.keys():
        if product_key in normalized:
            return True
    
    # Check for version numbers
    if re.search(r'\d+\.\d+', name):
        return True
    
    # Generic labels that should be skipped
    generic_labels = {
        "server", "database", "cache", "queue", "storage", "service",
        "gateway", "proxy", "balancer", "frontend", "backend", "api",
        "web server", "app server", "load balancer", "message queue"
    }
    
    if normalized in generic_labels:
        return False
    
    # Check if name contains known product keywords
    known_products = set(PRODUCT_MAPPING.keys())
    words = re.split(r'[\s\-_/]+', normalized)
    
    for word in words:
        if word in known_products:
            return True
    
    return False


def _extract_product_key(component_name: str) -> Optional[str]:
    """
    Extract the product mapping key from a component name.
    
    Args:
        component_name: Full component name
        
    Returns:
        Product key for PRODUCT_MAPPING or None
    """
    normalized = component_name.lower().strip()
    
    # Direct match
    if normalized in PRODUCT_MAPPING:
        return normalized
    
    # Check if any product key is in the name
    for key in PRODUCT_MAPPING.keys():
        if key in normalized:
            return key
    
    return None


# =============================================================================
# NVD API Integration
# =============================================================================

def _convert_nvd_cve_to_threat_record(
    cve: Any,
    kev_ids: Set[str]
) -> Optional[ThreatRecord]:
    """
    Convert an NVD CVE object to a ThreatRecord.
    
    Args:
        cve: NVD CVE object from nvdlib
        kev_ids: Set of actively exploited CVE IDs
        
    Returns:
        ThreatRecord or None if conversion fails
    """
    try:
        cve_id = cve.id
        
        # Get description
        descriptions = getattr(cve, 'descriptions', [])
        summary = ""
        for desc in descriptions:
            if hasattr(desc, 'lang') and desc.lang == 'en':
                summary = desc.value
                break
        if not summary and descriptions:
            summary = descriptions[0].value if hasattr(descriptions[0], 'value') else str(descriptions[0])
        
        # Get CVSS score and severity
        cvss_score = None
        cvss_vector = None
        severity = "MEDIUM"
        
        # Try CVSS v3.1 first, then v3.0, then v2
        metrics = getattr(cve, 'metrics', None)
        if metrics:
            if hasattr(metrics, 'cvssMetricV31') and metrics.cvssMetricV31:
                cvss_data = metrics.cvssMetricV31[0].cvssData
                cvss_score = cvss_data.baseScore
                cvss_vector = cvss_data.vectorString
                severity = cvss_data.baseSeverity
            elif hasattr(metrics, 'cvssMetricV30') and metrics.cvssMetricV30:
                cvss_data = metrics.cvssMetricV30[0].cvssData
                cvss_score = cvss_data.baseScore
                cvss_vector = cvss_data.vectorString
                severity = cvss_data.baseSeverity
            elif hasattr(metrics, 'cvssMetricV2') and metrics.cvssMetricV2:
                cvss_data = metrics.cvssMetricV2[0].cvssData
                cvss_score = cvss_data.baseScore
                cvss_vector = cvss_data.vectorString
                # Map v2 score to severity
                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
        
        # Get CWE ID
        cwe_id = None
        weaknesses = getattr(cve, 'weaknesses', [])
        for weakness in weaknesses:
            if hasattr(weakness, 'description'):
                for desc in weakness.description:
                    if hasattr(desc, 'value') and desc.value.startswith('CWE-'):
                        cwe_id = desc.value
                        break
                if cwe_id:
                    break
        
        # Get references
        references = []
        refs = getattr(cve, 'references', [])
        for ref in refs[:5]:  # Limit to 5 references
            if hasattr(ref, 'url'):
                references.append(ref.url)
        
        # Get affected products
        affected_products = []
        configurations = getattr(cve, 'configurations', [])
        for config in configurations:
            if hasattr(config, 'nodes'):
                for node in config.nodes:
                    if hasattr(node, 'cpeMatch'):
                        for match in node.cpeMatch[:3]:  # Limit
                            if hasattr(match, 'criteria'):
                                affected_products.append(match.criteria)
        
        affected_str = ", ".join(affected_products[:3]) if affected_products else "See CVE details"
        
        # Check if actively exploited
        is_kev = cve_id in kev_ids
        
        return ThreatRecord(
            cve_id=cve_id,
            summary=summary[:500] if summary else "No description available",
            severity=severity.upper(),
            affected_products=affected_str,
            is_actively_exploited=is_kev,
            source="CISA KEV" if is_kev else "NVD",
            cvss_vector=cvss_vector,
            cvss_score=cvss_score,
            cwe_id=cwe_id,
            references=references
        )
        
    except Exception as e:
        logger.error(f"Failed to convert CVE to ThreatRecord: {e}")
        return None


def _search_nvd_for_product(
    product_key: str,
    kev_ids: Set[str]
) -> List[ThreatRecord]:
    """
    Search NVD for vulnerabilities affecting a specific product.
    
    Args:
        product_key: Product key from PRODUCT_MAPPING
        kev_ids: Set of actively exploited CVE IDs
        
    Returns:
        List of ThreatRecord objects
    """
    if not NVDLIB_AVAILABLE:
        logger.warning("nvdlib not available - skipping NVD search")
        return []
    
    mapping = PRODUCT_MAPPING.get(product_key)
    if not mapping:
        logger.warning(f"No mapping found for product: {product_key}")
        return []
    
    search_term = mapping["search_term"]
    allowed_vendors = mapping["allowed_vendors"]
    allowed_products = mapping["allowed_products"]
    
    logger.info(f"Searching NVD for: {search_term}")
    
    threats = []
    
    try:
        # Search NVD - using simpler approach without date filtering
        # (nvdlib handles the API quirks)
        search_kwargs = {
            "keywordSearch": search_term,
            "cvssV3Severity": "HIGH",  # HIGH and CRITICAL
        }
        
        if NVD_API_KEY:
            search_kwargs["key"] = NVD_API_KEY
        
        # Search for HIGH severity
        try:
            results_high = list(nvdlib.searchCVE(**search_kwargs))
        except Exception as e:
            logger.warning(f"HIGH severity search failed: {e}")
            results_high = []
        
        # Also search for CRITICAL
        search_kwargs["cvssV3Severity"] = "CRITICAL"
        try:
            results_critical = list(nvdlib.searchCVE(**search_kwargs))
        except Exception as e:
            logger.warning(f"CRITICAL severity search failed: {e}")
            results_critical = []
        
        # Combine results
        all_results = results_high + results_critical
        
        # Calculate cutoff date for recency filter
        cutoff_date = datetime.now() - timedelta(days=CVE_RECENCY_YEARS * 365)
        
        # Remove duplicates by CVE ID and filter by recency
        seen_ids = set()
        unique_results = []
        for cve in all_results:
            if cve.id not in seen_ids:
                seen_ids.add(cve.id)
                
                # Filter by publish date if available
                try:
                    pub_date = getattr(cve, 'published', None)
                    if pub_date:
                        # pub_date is typically a string like "2024-01-15T12:00:00.000"
                        if isinstance(pub_date, str):
                            pub_datetime = datetime.fromisoformat(pub_date.replace('Z', '+00:00').split('+')[0])
                        else:
                            pub_datetime = pub_date
                        
                        if pub_datetime < cutoff_date:
                            continue  # Skip old CVEs
                except Exception:
                    pass  # If date parsing fails, include the CVE
                
                unique_results.append(cve)
        
        logger.info(f"Found {len(unique_results)} CVEs for {search_term}")
        
        # Convert to ThreatRecords and filter
        for cve in unique_results[:20]:  # Limit to 20 per product
            threat = _convert_nvd_cve_to_threat_record(cve, kev_ids)
            if threat:
                # Verify vendor/product match to avoid false positives
                affected_lower = threat.affected_products.lower()
                
                # Check if any allowed vendor/product is in affected products
                is_match = False
                for vendor in allowed_vendors:
                    if vendor.lower() in affected_lower:
                        is_match = True
                        break
                for product in allowed_products:
                    if product.lower() in affected_lower or product.lower() in threat.summary.lower():
                        is_match = True
                        break
                
                # Also match on search term in summary
                if search_term.lower() in threat.summary.lower():
                    is_match = True
                
                if is_match:
                    threats.append(threat)
        
        logger.info(f"Filtered to {len(threats)} relevant CVEs for {product_key}")
        
    except Exception as e:
        logger.error(f"NVD search failed for {product_key}: {e}")
    
    return threats


def search_vulnerabilities(
    tool_context: Any,
    components: List[str]
) -> ThreatSearchResults:
    """
    Search for vulnerabilities affecting the specified components.
    
    Args:
        tool_context: Tool context (can be None)
        components: List of component names to search for
        
    Returns:
        ThreatSearchResults containing found vulnerabilities
    """
    logger.info(f"Searching vulnerabilities for {len(components)} components")
    
    # Fetch KEV IDs
    kev_ids = _fetch_kev_cve_ids()
    
    # Filter to concrete product identifiers
    concrete_products = []
    for comp in components:
        if _looks_like_software_identifier(comp):
            product_key = _extract_product_key(comp)
            if product_key and product_key not in concrete_products:
                concrete_products.append(product_key)
        else:
            logger.debug(f"Skipping generic component: {comp}")
    
    logger.info(f"Identified {len(concrete_products)} concrete products: {concrete_products}")
    
    # Search for each product
    all_threats = []
    for product_key in concrete_products:
        # Rate limiting
        if all_threats:  # Don't delay before first query
            time.sleep(NVD_RATE_LIMIT_DELAY)
        
        threats = _search_nvd_for_product(product_key, kev_ids)
        all_threats.extend(threats)
    
    # Sort by severity and CVSS score
    def sort_key(t):
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return (severity_order.get(t.severity, 4), -(t.cvss_score or 0))
    
    all_threats.sort(key=sort_key)
    
    logger.info(f"Total vulnerabilities found: {len(all_threats)}")
    
    return ThreatSearchResults(threats=all_threats)


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "search_vulnerabilities",
    "is_actively_exploited",
    "PRODUCT_MAPPING",
    "CISA_KEV_URL",
    "_fetch_kev_cve_ids",
    "_looks_like_software_identifier",
]
