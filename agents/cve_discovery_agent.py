"""
CVE Discovery Agent for Left<<Shift Threat Modeling System.

This agent discovers relevant CVEs for architecture components by:
1. Extracting product identifiers from inferred components
2. Searching NVD and CISA KEV for vulnerabilities
3. Enriching threats with mitigation strategies
"""

import logging
from typing import Any, Dict, List, Optional

from tools.models import ThreatRecord, ThreatSearchResults
from tools.threat_intel_api import (
    search_vulnerabilities,
    is_actively_exploited,
    PRODUCT_MAPPING,
    _looks_like_software_identifier,
)
from tools.mitigation_engine import enrich_threat_with_mitigation

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CVEDiscoveryAgent:
    """
    Agent for discovering CVEs relevant to architecture components.
    
    This agent:
    1. Extracts product identifiers from inferred components
    2. Filters out generic categories
    3. Searches vulnerability databases for relevant CVEs
    4. Enriches threats with mitigation strategies
    """
    
    def __init__(self):
        """Initialize the CVE Discovery Agent."""
        logger.info("CVE Discovery Agent initialized")
    
    def _extract_products(
        self,
        inferred_components: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Extract concrete product identifiers from inferred components.
        
        Args:
            inferred_components: List of component inference results
            
        Returns:
            List of product identifiers suitable for CVE search
        """
        products = []
        seen = set()
        
        for comp in inferred_components:
            # Get component name and inferred products
            comp_name = comp.get("component_name", "")
            inferred = comp.get("inferred_product_categories", [])
            confidence = comp.get("confidence", 0.0)
            
            # Skip low-confidence inferences
            if confidence < 0.5:
                logger.debug(f"Skipping low-confidence component: {comp_name}")
                continue
            
            # Extract products from component name
            if _looks_like_software_identifier(comp_name):
                normalized = comp_name.lower().strip()
                if normalized not in seen:
                    products.append(comp_name)
                    seen.add(normalized)
            
            # Extract from inferred categories
            for product in inferred:
                if product and product.lower() != "generic":
                    normalized = product.lower().strip()
                    if normalized not in seen:
                        if _looks_like_software_identifier(product):
                            products.append(product)
                            seen.add(normalized)
        
        logger.info(f"Extracted {len(products)} product identifiers: {products}")
        return products
    
    def _filter_generic_categories(
        self,
        products: List[str]
    ) -> List[str]:
        """
        Filter out generic categories that won't yield useful CVE results.
        
        Args:
            products: List of potential product names
            
        Returns:
            Filtered list of concrete products
        """
        generic_terms = {
            "generic", "unknown", "service", "server", "database",
            "cache", "queue", "gateway", "proxy", "frontend", "backend",
            "microservice", "api", "web", "application", "system"
        }
        
        filtered = []
        for product in products:
            normalized = product.lower().strip()
            
            # Skip if it's a generic term
            if normalized in generic_terms:
                logger.debug(f"Filtering generic term: {product}")
                continue
            
            # Skip if all words are generic
            words = normalized.split()
            if all(word in generic_terms for word in words):
                logger.debug(f"Filtering all-generic product: {product}")
                continue
            
            # Check if it maps to a known product
            has_mapping = False
            for key in PRODUCT_MAPPING.keys():
                if key in normalized:
                    has_mapping = True
                    break
            
            if has_mapping or _looks_like_software_identifier(product):
                filtered.append(product)
        
        logger.info(f"Filtered to {len(filtered)} concrete products")
        return filtered
    
    def discover_cves(
        self,
        inferred_components: List[Dict[str, Any]]
    ) -> List[ThreatRecord]:
        """
        Discover CVEs for the given inferred components.
        
        Args:
            inferred_components: List of component inference results with structure:
                - component_name: str
                - inferred_product_categories: List[str]
                - confidence: float
                
        Returns:
            List of ThreatRecord objects with CVE data and mitigations
        """
        logger.info(f"Starting CVE discovery for {len(inferred_components)} components")
        
        # Step 1: Extract product identifiers
        products = self._extract_products(inferred_components)
        
        if not products:
            logger.warning("No product identifiers extracted - no CVEs to discover")
            return []
        
        # Step 2: Filter out generic categories
        concrete_products = self._filter_generic_categories(products)
        
        if not concrete_products:
            logger.warning("All products filtered out as generic")
            return []
        
        # Step 3: Search for vulnerabilities
        logger.info(f"Searching CVEs for: {concrete_products}")
        results = search_vulnerabilities(None, concrete_products)
        
        threats = results.threats
        logger.info(f"Found {len(threats)} CVEs from vulnerability search")
        
        # Step 4: Deduplicate CVEs (same CVE might appear from multiple product searches)
        seen_cve_ids = set()
        unique_threats = []
        duplicates_removed = 0
        
        for threat in threats:
            if threat.cve_id not in seen_cve_ids:
                seen_cve_ids.add(threat.cve_id)
                unique_threats.append(threat)
            else:
                duplicates_removed += 1
        
        if duplicates_removed > 0:
            logger.info(f"Removed {duplicates_removed} duplicate CVE entries")
        
        # Step 5: Enrich with mitigations
        enriched_threats = []
        for threat in unique_threats:
            try:
                enriched = enrich_threat_with_mitigation(threat)
                enriched_threats.append(enriched)
            except Exception as e:
                logger.error(f"Failed to enrich {threat.cve_id} with mitigation: {e}")
                enriched_threats.append(threat)
        
        logger.info(f"CVE discovery complete: {len(enriched_threats)} unique threats with mitigations")
        
        return enriched_threats
    
    def discover_for_product(
        self,
        product_name: str
    ) -> List[ThreatRecord]:
        """
        Discover CVEs for a single product.
        
        Args:
            product_name: Name of the product to search
            
        Returns:
            List of ThreatRecord objects
        """
        # Create a simple inference structure
        inferred = [{
            "component_name": product_name,
            "inferred_product_categories": [product_name],
            "confidence": 0.95
        }]
        
        return self.discover_cves(inferred)
    
    def get_kev_status(self, cve_id: str) -> bool:
        """
        Check if a CVE is in CISA's Known Exploited Vulnerabilities catalog.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            True if actively exploited
        """
        return is_actively_exploited(cve_id)
    
    def summarize_findings(
        self,
        threats: List[ThreatRecord]
    ) -> Dict[str, Any]:
        """
        Generate a summary of CVE findings.
        
        Args:
            threats: List of discovered threats
            
        Returns:
            Summary dictionary with statistics
        """
        if not threats:
            return {
                "total_cves": 0,
                "critical": 0,
                "high": 0,
                "actively_exploited": 0,
                "with_mitigation": 0
            }
        
        summary = {
            "total_cves": len(threats),
            "critical": sum(1 for t in threats if t.severity == "CRITICAL"),
            "high": sum(1 for t in threats if t.severity == "HIGH"),
            "actively_exploited": sum(1 for t in threats if t.is_actively_exploited),
            "with_mitigation": sum(1 for t in threats if t.mitigation is not None),
            "by_cwe": {},
            "by_product": {}
        }
        
        # Group by CWE
        for threat in threats:
            cwe = threat.cwe_id or "Unknown"
            summary["by_cwe"][cwe] = summary["by_cwe"].get(cwe, 0) + 1
        
        return summary


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "CVEDiscoveryAgent",
]
