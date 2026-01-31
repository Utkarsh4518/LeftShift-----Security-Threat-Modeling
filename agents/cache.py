"""
Caching utilities for the threat modeling pipeline.

Provides:
- LRU cache for component inference results
- TTL-based cache for CVE lookups
- Cache key generation utilities
"""

import hashlib
import json
import time
import threading
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


def make_cache_key(data: Any) -> str:
    """
    Generate a deterministic cache key from any JSON-serializable data.
    
    Args:
        data: Any JSON-serializable Python object
        
    Returns:
        SHA256 hash string of the serialized data
    """
    try:
        serialized = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()
    except (TypeError, ValueError) as e:
        logger.warning(f"Failed to create cache key: {e}")
        return hashlib.sha256(str(data).encode()).hexdigest()


class ComponentInferenceCache:
    """
    Thread-safe cache for component inference results.
    Uses a simple dict with no expiration (inference is deterministic).
    """
    
    def __init__(self, maxsize: int = 256):
        self._cache: Dict[str, List[Dict]] = {}
        self._maxsize = maxsize
        self._lock = threading.Lock()
        self._access_order: List[str] = []
    
    def get(self, cache_key: str) -> Optional[List[Dict]]:
        """Get cached inference result."""
        with self._lock:
            if cache_key in self._cache:
                # Move to end (most recently accessed)
                self._access_order.remove(cache_key)
                self._access_order.append(cache_key)
                logger.debug(f"Cache HIT for component inference: {cache_key[:16]}...")
                return self._cache[cache_key]
            logger.debug(f"Cache MISS for component inference: {cache_key[:16]}...")
            return None
    
    def set(self, cache_key: str, result: List[Dict]) -> None:
        """Store inference result in cache."""
        with self._lock:
            # Evict oldest if at capacity
            while len(self._cache) >= self._maxsize and self._access_order:
                oldest = self._access_order.pop(0)
                self._cache.pop(oldest, None)
            
            self._cache[cache_key] = result
            if cache_key not in self._access_order:
                self._access_order.append(cache_key)
            logger.debug(f"Cached component inference: {cache_key[:16]}...")
    
    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()
            self._access_order.clear()
    
    @property
    def size(self) -> int:
        """Current number of cached entries."""
        return len(self._cache)


class CVECache:
    """
    Thread-safe cache for CVE lookup results with TTL expiration.
    NVD data changes infrequently, so 24-hour TTL is reasonable.
    """
    
    def __init__(self, ttl_seconds: int = 86400):  # 24 hours default
        self._cache: Dict[str, Tuple[float, List]] = {}
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
    
    def get(self, product: str) -> Optional[List]:
        """
        Get cached CVE results for a product.
        
        Args:
            product: Product name to look up
            
        Returns:
            List of CVE records if cached and not expired, None otherwise
        """
        with self._lock:
            if product in self._cache:
                timestamp, data = self._cache[product]
                if time.time() - timestamp < self._ttl:
                    logger.debug(f"CVE cache HIT for: {product}")
                    return data
                else:
                    # Expired, remove it
                    del self._cache[product]
                    logger.debug(f"CVE cache EXPIRED for: {product}")
            logger.debug(f"CVE cache MISS for: {product}")
            return None
    
    def set(self, product: str, cves: List) -> None:
        """
        Store CVE results in cache.
        
        Args:
            product: Product name
            cves: List of CVE records
        """
        with self._lock:
            self._cache[product] = (time.time(), cves)
            logger.debug(f"Cached {len(cves)} CVEs for: {product}")
    
    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()
    
    def cleanup_expired(self) -> int:
        """
        Remove expired entries from cache.
        
        Returns:
            Number of entries removed
        """
        removed = 0
        current_time = time.time()
        with self._lock:
            expired_keys = [
                k for k, (ts, _) in self._cache.items()
                if current_time - ts >= self._ttl
            ]
            for key in expired_keys:
                del self._cache[key]
                removed += 1
        if removed:
            logger.debug(f"Cleaned up {removed} expired CVE cache entries")
        return removed
    
    @property
    def size(self) -> int:
        """Current number of cached entries (including possibly expired)."""
        return len(self._cache)


class ThreatAnalysisCache:
    """
    Cache for STRIDE threat analysis results.
    Keyed by component name + type + context hash.
    """
    
    def __init__(self, maxsize: int = 128):
        self._cache: Dict[str, Dict] = {}
        self._maxsize = maxsize
        self._lock = threading.Lock()
        self._access_order: List[str] = []
    
    def _make_key(self, component_name: str, component_type: str, context: Optional[Dict] = None) -> str:
        """Generate cache key from component info."""
        key_data = {
            "name": component_name,
            "type": component_type,
            "context": context or {}
        }
        return make_cache_key(key_data)
    
    def get(self, component_name: str, component_type: str, context: Optional[Dict] = None) -> Optional[Dict]:
        """Get cached threat analysis result."""
        cache_key = self._make_key(component_name, component_type, context)
        with self._lock:
            if cache_key in self._cache:
                self._access_order.remove(cache_key)
                self._access_order.append(cache_key)
                logger.debug(f"Threat cache HIT for: {component_name}")
                return self._cache[cache_key]
            return None
    
    def set(self, component_name: str, component_type: str, result: Dict, context: Optional[Dict] = None) -> None:
        """Store threat analysis result."""
        cache_key = self._make_key(component_name, component_type, context)
        with self._lock:
            while len(self._cache) >= self._maxsize and self._access_order:
                oldest = self._access_order.pop(0)
                self._cache.pop(oldest, None)
            
            self._cache[cache_key] = result
            if cache_key not in self._access_order:
                self._access_order.append(cache_key)
    
    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()
            self._access_order.clear()


# Global cache instances (singleton pattern)
_component_cache: Optional[ComponentInferenceCache] = None
_cve_cache: Optional[CVECache] = None
_threat_cache: Optional[ThreatAnalysisCache] = None


def get_component_cache() -> ComponentInferenceCache:
    """Get or create the global component inference cache."""
    global _component_cache
    if _component_cache is None:
        _component_cache = ComponentInferenceCache()
    return _component_cache


def get_cve_cache() -> CVECache:
    """Get or create the global CVE cache."""
    global _cve_cache
    if _cve_cache is None:
        _cve_cache = CVECache()
    return _cve_cache


def get_threat_cache() -> ThreatAnalysisCache:
    """Get or create the global threat analysis cache."""
    global _threat_cache
    if _threat_cache is None:
        _threat_cache = ThreatAnalysisCache()
    return _threat_cache


def clear_all_caches() -> None:
    """Clear all global caches."""
    if _component_cache:
        _component_cache.clear()
    if _cve_cache:
        _cve_cache.clear()
    if _threat_cache:
        _threat_cache.clear()
    logger.info("All caches cleared")


def get_cache_stats() -> Dict[str, int]:
    """Get statistics about all caches."""
    return {
        "component_cache_size": _component_cache.size if _component_cache else 0,
        "cve_cache_size": _cve_cache.size if _cve_cache else 0,
        "threat_cache_size": _threat_cache.size if _threat_cache else 0,
    }
