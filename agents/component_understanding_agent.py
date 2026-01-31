"""
Component Understanding Agent for Left<<Shift Threat Modeling System.

This agent analyzes component labels from architecture diagrams and determines
whether they represent specific software products or generic labels. For generic
labels, it uses LLM-based inference to suggest likely technologies based on context.

Uses OpenAI GPT-5.2 for text-based reasoning tasks.
"""

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Set

from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field

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
PRIMARY_MODEL = "gpt-5.2"
FALLBACK_MODEL = "gpt-5"

# =============================================================================
# Generic Labels Detection
# =============================================================================

# Generic labels that don't identify specific software products
# These are representative patterns - the detection logic infers similar terms
GENERIC_LABELS: Set[str] = {
    # Infrastructure terms
    "server", "database", "cache", "queue", "storage", "cluster", "node",
    "instance", "container", "vm", "virtual machine", "host", "machine",
    "computer", "workstation", "desktop", "laptop", "device",
    
    # Environment terms
    "production", "staging", "development", "dev", "prod", "stage", "test",
    "qa", "uat", "sandbox", "demo", "preview", "canary",
    
    # Role/Function terms
    "web server", "app server", "application server", "api server",
    "backend", "frontend", "middleware", "gateway", "proxy", "reverse proxy",
    "load balancer", "firewall", "router", "switch", "dns", "cdn",
    
    # Generic service terms
    "service", "microservice", "api", "rest api", "graphql api", "endpoint",
    "worker", "scheduler", "cron", "job", "task", "process", "daemon",
    
    # Data terms
    "data store", "data warehouse", "data lake", "blob storage", "file storage",
    "object storage", "block storage", "nas", "san", "backup",
    
    # Security terms
    "auth", "authentication", "authorization", "identity", "sso", "oauth",
    "security", "waf", "ids", "ips", "siem",
    
    # Monitoring terms
    "monitoring", "logging", "metrics", "tracing", "alerting", "dashboard",
    
    # Network terms
    "network", "subnet", "vpc", "vnet", "lan", "wan", "dmz", "internet",
    "intranet", "extranet", "vpn", "tunnel",
    
    # Generic component terms
    "component", "module", "system", "subsystem", "layer", "tier",
    "infrastructure", "platform", "environment", "resource", "asset",
    
    # User/Client terms
    "user", "client", "browser", "mobile", "app", "application",
    "consumer", "subscriber", "publisher",
    
    # Generic database terms
    "sql database", "nosql database", "relational database", "document database",
    "graph database", "key-value store", "time series database",
    
    # Placeholder terms
    "external", "internal", "third party", "third-party", "external service",
    "legacy", "legacy system", "mainframe", "on-premise", "on-prem", "cloud",
}

# Known technology products and frameworks
# These are representative patterns - the detection expands to similar products
KNOWN_TECH: Set[str] = {
    # Web Servers
    "nginx", "apache", "httpd", "iis", "lighttpd", "caddy", "traefik",
    "haproxy", "envoy", "istio",
    
    # Application Frameworks
    "django", "flask", "fastapi", "express", "nestjs", "spring", "spring boot",
    "rails", "ruby on rails", "laravel", "symfony", "asp.net", "dotnet",
    "node", "nodejs", "node.js", "deno", "bun",
    
    # Databases - Relational
    "postgresql", "postgres", "mysql", "mariadb", "oracle", "sql server",
    "mssql", "sqlite", "cockroachdb", "tidb", "vitess", "planetscale",
    
    # Databases - NoSQL
    "mongodb", "mongo", "cassandra", "dynamodb", "couchdb", "couchbase",
    "firebase", "firestore", "fauna", "faunadb", "rethinkdb", "arangodb",
    
    # Databases - Graph
    "neo4j", "neptune", "janusgraph", "tigergraph", "dgraph",
    
    # Databases - Time Series
    "influxdb", "timescaledb", "prometheus", "victoriametrics", "questdb",
    
    # Databases - Search
    "elasticsearch", "opensearch", "solr", "meilisearch", "typesense", "algolia",
    
    # Cache/In-Memory
    "redis", "memcached", "hazelcast", "ignite", "aerospike", "dragonfly",
    
    # Message Queues
    "rabbitmq", "kafka", "activemq", "zeromq", "nats", "pulsar",
    "sqs", "sns", "kinesis", "eventbridge",
    
    # Container/Orchestration
    "docker", "kubernetes", "k8s", "openshift", "rancher", "nomad",
    "docker compose", "docker swarm", "podman", "containerd", "cri-o",
    
    # CI/CD
    "jenkins", "gitlab", "github actions", "circleci", "travis", "teamcity",
    "azure devops", "bamboo", "argo", "argocd", "flux", "tekton", "spinnaker",
    
    # Cloud Providers
    "aws", "azure", "gcp", "google cloud", "digitalocean", "linode",
    "vultr", "heroku", "vercel", "netlify", "cloudflare", "fastly",
    
    # Cloud Services - AWS
    "ec2", "s3", "rds", "lambda", "ecs", "eks", "fargate", "api gateway",
    "cloudfront", "route53", "elasticache", "aurora", "redshift", "athena",
    
    # Cloud Services - Azure
    "azure functions", "azure sql", "cosmos db", "cosmosdb", "azure blob",
    "aks", "azure app service", "azure devops",
    
    # Cloud Services - GCP
    "cloud run", "cloud functions", "bigquery", "cloud sql", "gke",
    "cloud storage", "pub/sub", "pubsub", "dataflow", "bigtable",
    
    # Authentication/Identity
    "auth0", "okta", "keycloak", "cognito", "firebase auth", "clerk",
    "supertokens", "fusionauth", "ping identity",
    
    # API Gateways
    "kong", "apigee", "tyk", "aws api gateway", "azure api management",
    "gravitee", "krakend", "zuul",
    
    # Monitoring/Observability
    "datadog", "newrelic", "new relic", "splunk", "grafana", "kibana",
    "jaeger", "zipkin", "honeycomb", "lightstep", "dynatrace", "appdynamics",
    "sentry", "rollbar", "bugsnag", "pagerduty", "opsgenie",
    
    # Logging
    "logstash", "fluentd", "fluent bit", "loki", "graylog", "papertrail",
    "loggly", "sumologic",
    
    # Secret Management
    "vault", "hashicorp vault", "aws secrets manager", "azure key vault",
    "gcp secret manager", "doppler", "infisical",
    
    # Service Mesh
    "istio", "linkerd", "consul", "consul connect",
    
    # Load Testing
    "jmeter", "gatling", "locust", "k6", "artillery", "vegeta",
    
    # Security
    "snyk", "sonarqube", "checkmarx", "veracode", "fortify", "owasp zap",
    "burp", "nessus", "qualys", "crowdstrike", "sentinel one",
    
    # Misc Tools
    "terraform", "ansible", "puppet", "chef", "saltstack", "pulumi",
    "vagrant", "packer", "helm", "kustomize",
    
    # Frontend
    "react", "vue", "angular", "svelte", "next.js", "nextjs", "nuxt",
    "gatsby", "remix", "astro", "solidjs", "qwik",
    
    # Mobile
    "react native", "flutter", "ionic", "xamarin", "kotlin", "swift",
    
    # Payment
    "stripe", "paypal", "braintree", "adyen", "square", "plaid",
    
    # Email
    "sendgrid", "mailgun", "ses", "postmark", "mailchimp", "sendinblue",
    
    # CMS
    "wordpress", "drupal", "strapi", "contentful", "sanity", "ghost",
}

# Mapping from generic labels to likely technology categories
GENERIC_TO_TECH: Dict[str, List[str]] = {
    "database": ["PostgreSQL", "MySQL", "MongoDB", "Redis"],
    "sql database": ["PostgreSQL", "MySQL", "MariaDB", "SQL Server"],
    "nosql database": ["MongoDB", "Cassandra", "DynamoDB", "CouchDB"],
    "relational database": ["PostgreSQL", "MySQL", "MariaDB"],
    "document database": ["MongoDB", "CouchDB", "Firebase Firestore"],
    "cache": ["Redis", "Memcached", "Hazelcast"],
    "message queue": ["RabbitMQ", "Apache Kafka", "Amazon SQS", "Redis"],
    "queue": ["RabbitMQ", "Apache Kafka", "Amazon SQS"],
    "web server": ["Nginx", "Apache HTTP Server", "Caddy"],
    "app server": ["Node.js", "Gunicorn", "uWSGI", "Tomcat"],
    "application server": ["Node.js", "Gunicorn", "Tomcat", "JBoss"],
    "api server": ["Express.js", "FastAPI", "Spring Boot", "Django REST"],
    "load balancer": ["Nginx", "HAProxy", "AWS ALB", "Traefik"],
    "reverse proxy": ["Nginx", "Traefik", "HAProxy", "Envoy"],
    "api gateway": ["Kong", "AWS API Gateway", "Apigee", "Traefik"],
    "gateway": ["Kong", "AWS API Gateway", "Nginx", "Envoy"],
    "proxy": ["Nginx", "HAProxy", "Squid", "Envoy"],
    "container": ["Docker", "Podman", "containerd"],
    "orchestration": ["Kubernetes", "Docker Swarm", "Nomad"],
    "monitoring": ["Prometheus", "Grafana", "Datadog", "New Relic"],
    "logging": ["ELK Stack", "Splunk", "Loki", "Fluentd"],
    "search": ["Elasticsearch", "OpenSearch", "Solr", "Meilisearch"],
    "object storage": ["Amazon S3", "MinIO", "Azure Blob", "GCS"],
    "blob storage": ["Amazon S3", "Azure Blob Storage", "GCS"],
    "file storage": ["NFS", "Amazon EFS", "Azure Files"],
    "auth": ["Auth0", "Keycloak", "Okta", "AWS Cognito"],
    "authentication": ["Auth0", "Keycloak", "Okta", "Firebase Auth"],
    "identity": ["Okta", "Auth0", "Azure AD", "Keycloak"],
    "cdn": ["CloudFlare", "AWS CloudFront", "Fastly", "Akamai"],
    "firewall": ["AWS WAF", "Cloudflare WAF", "ModSecurity"],
    "waf": ["AWS WAF", "Cloudflare WAF", "Imperva", "F5"],
    "ci/cd": ["Jenkins", "GitHub Actions", "GitLab CI", "CircleCI"],
    "secrets": ["HashiCorp Vault", "AWS Secrets Manager", "Azure Key Vault"],
    "service mesh": ["Istio", "Linkerd", "Consul Connect"],
    "frontend": ["React", "Vue.js", "Angular", "Next.js"],
    "backend": ["Node.js", "Python/Django", "Java/Spring", "Go"],
    "microservice": ["Docker Container", "Kubernetes Pod"],
    "serverless": ["AWS Lambda", "Azure Functions", "Google Cloud Functions"],
    "function": ["AWS Lambda", "Azure Functions", "Google Cloud Functions"],
    "worker": ["Celery", "Sidekiq", "Bull", "AWS SQS Worker"],
    "scheduler": ["Celery Beat", "Apache Airflow", "cron", "Kubernetes CronJob"],
    "email": ["SendGrid", "Amazon SES", "Mailgun", "Postmark"],
    "payment": ["Stripe", "PayPal", "Braintree", "Square"],
    "analytics": ["Google Analytics", "Mixpanel", "Amplitude", "Segment"],
    "data warehouse": ["Snowflake", "BigQuery", "Redshift", "Databricks"],
}


# =============================================================================
# Pydantic Models for Inference Output
# =============================================================================

class ProductInference(BaseModel):
    """Result of inferring a specific product from a generic label."""
    
    suggested_product: str = Field(
        ...,
        description="The inferred product name, or 'Generic' if confidence is low"
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score from 0.0 to 1.0"
    )
    reasoning: str = Field(
        ...,
        description="Explanation for the inference"
    )


class ComponentInferenceItem(BaseModel):
    """Inference result for a single component."""
    
    component_name: str = Field(
        ...,
        description="Original component name from the architecture"
    )
    inference: ProductInference = Field(
        ...,
        description="The product inference for this component"
    )


class BatchInferenceResult(BaseModel):
    """Results from batch inference of multiple components."""
    
    results: List[ComponentInferenceItem] = Field(
        default_factory=list,
        description="List of inference results for each component"
    )


# =============================================================================
# Heuristic Detection Functions
# =============================================================================

def _normalize_name(name: str) -> str:
    """Normalize a component name for comparison."""
    return name.lower().strip()


def _extract_words(name: str) -> List[str]:
    """Extract individual words from a component name."""
    # Split on common delimiters
    words = re.split(r'[\s\-_/\\()[\]{}]+', name.lower())
    return [w for w in words if w]


def _contains_version_number(name: str) -> bool:
    """Check if the name contains a version number pattern."""
    # Match patterns like: 1.0, v1.2.3, 14.2, 2024.1
    version_patterns = [
        r'\d+\.\d+',           # 1.0, 14.2
        r'v\d+',               # v1, v2
        r'\d+\.\d+\.\d+',      # 1.2.3
        r'\d{4}\.\d+',         # 2024.1
    ]
    for pattern in version_patterns:
        if re.search(pattern, name, re.IGNORECASE):
            return True
    return False


def _contains_known_tech(name: str) -> bool:
    """Check if the name contains any known technology keywords."""
    normalized = _normalize_name(name)
    words = _extract_words(name)
    
    # Check exact match
    if normalized in KNOWN_TECH:
        return True
    
    # Check if any word is a known tech
    for word in words:
        if word in KNOWN_TECH:
            return True
    
    # Check if known tech is contained in the name
    for tech in KNOWN_TECH:
        if tech in normalized:
            return True
    
    return False


def _is_all_generic_words(name: str) -> bool:
    """Check if all words in the name are generic labels."""
    words = _extract_words(name)
    if not words:
        return True
    
    for word in words:
        # Skip very short words and numbers
        if len(word) <= 2 or word.isdigit():
            continue
        
        # Check if word is generic
        is_generic = False
        for generic in GENERIC_LABELS:
            generic_words = _extract_words(generic)
            if word in generic_words:
                is_generic = True
                break
        
        if not is_generic:
            return False
    
    return True


def _looks_like_software_identifier(name: str) -> bool:
    """
    Determine if a component name looks like a specific software product.
    
    Args:
        name: The component name to analyze
        
    Returns:
        True if the name appears to identify specific software,
        False if it appears to be a generic label
    """
    if not name or not name.strip():
        return False
    
    normalized = _normalize_name(name)
    
    # Check if it's a known generic label
    if normalized in GENERIC_LABELS:
        return False
    
    # Check if all words are generic
    if _is_all_generic_words(name):
        return False
    
    # Check for version numbers (strong indicator of specific software)
    if _contains_version_number(name):
        return True
    
    # Check for known technology keywords
    if _contains_known_tech(name):
        return True
    
    # Default to False for unknown terms
    return False


def get_generic_category(name: str) -> Optional[List[str]]:
    """
    Get likely technology categories for a generic label.
    
    Args:
        name: The generic component name
        
    Returns:
        List of likely technology categories, or None if not found
    """
    normalized = _normalize_name(name)
    
    # Direct match
    if normalized in GENERIC_TO_TECH:
        return GENERIC_TO_TECH[normalized]
    
    # Partial match
    for generic, techs in GENERIC_TO_TECH.items():
        if generic in normalized or normalized in generic:
            return techs
    
    return None


# =============================================================================
# LLM-Based Inference
# =============================================================================

INFERENCE_SYSTEM_PROMPT = """You are a software architecture expert analyzing component labels from system diagrams.

Your task is to infer specific technology products from generic component labels, using context from the full architecture.

INFERENCE RULES:
1. Consider the technology stack context:
   - If Django is present, a "Database" is likely PostgreSQL
   - If Java/Spring is present, databases might be MySQL or PostgreSQL
   - If Node.js is present, MongoDB or PostgreSQL are common
   - If AWS services are present, consider AWS-native options first

2. Consider component relationships:
   - A "Cache" near a database is likely Redis or Memcached
   - An "API Gateway" in a microservices architecture is likely Kong, Traefik, or AWS API Gateway
   - A "Message Queue" in an event-driven system is likely Kafka, RabbitMQ, or SQS

3. Confidence scoring:
   - 0.9-1.0: Strong context clues make this almost certain
   - 0.7-0.8: Good context clues suggest this product
   - 0.5-0.6: Reasonable guess based on common patterns
   - Below 0.5: Return "Generic" as suggested_product

4. When uncertain:
   - If confidence would be below 0.5, set suggested_product to "Generic"
   - Provide reasoning about why the inference is uncertain

5. Output format:
   - Return a JSON object matching the BatchInferenceResult schema
   - Each component needs: component_name, suggested_product, confidence, reasoning
"""


def _create_inference_schema() -> dict:
    """Create JSON schema for batch inference output."""
    return {
        "type": "object",
        "properties": {
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "component_name": {"type": "string"},
                        "inference": {
                            "type": "object",
                            "properties": {
                                "suggested_product": {"type": "string"},
                                "confidence": {"type": "number"},
                                "reasoning": {"type": "string"}
                            },
                            "required": ["suggested_product", "confidence", "reasoning"]
                        }
                    },
                    "required": ["component_name", "inference"]
                }
            }
        },
        "required": ["results"]
    }


class ComponentUnderstandingAgent:
    """
    Agent for understanding and inferring software components from architecture labels.
    
    This agent combines heuristic detection with LLM-based inference to:
    1. Identify known software products directly
    2. Infer likely products for generic labels using context
    3. Provide confidence scores and reasoning for inferences
    
    Uses OpenAI GPT-5.2 for inference tasks.
    """
    
    def __init__(self):
        """Initialize the Component Understanding Agent."""
        self.client: Optional[OpenAI] = None
        self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize OpenAI client if API key is available."""
        api_key = os.getenv("OPENAI_API_KEY")
        if api_key and api_key != "your_openai_api_key_here":
            try:
                self.client = OpenAI(api_key=api_key)
                logger.info("OpenAI client initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize OpenAI client: {e}")
                self.client = None
        else:
            logger.warning("OPENAI_API_KEY not configured - LLM inference disabled")
            self.client = None
    
    def _call_llm_with_retry(
        self,
        prompt: str,
        model: str = PRIMARY_MODEL,
        attempt: int = 1
    ) -> Optional[str]:
        """
        Call LLM with retry logic and fallback.
        
        Args:
            prompt: The prompt to send
            model: Model to use
            attempt: Current attempt number
            
        Returns:
            Response text or None if all attempts fail
        """
        if not self.client:
            logger.warning("No LLM client available")
            return None
        
        try:
            logger.info(f"LLM call attempt {attempt}/{MAX_RETRIES} using {model}")
            
            response = self.client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": INFERENCE_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                response_format={"type": "json_object"}
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.warning(f"LLM call failed (attempt {attempt}): {e}")
            
            if attempt < MAX_RETRIES:
                # Exponential backoff
                delay = BASE_DELAY * (2 ** (attempt - 1))
                logger.info(f"Retrying in {delay}s...")
                time.sleep(delay)
                
                # Try fallback model on last retry
                next_model = FALLBACK_MODEL if attempt == MAX_RETRIES - 1 else model
                return self._call_llm_with_retry(prompt, next_model, attempt + 1)
            
            return None
    
    def _infer_batch_with_llm(
        self,
        target_components: List[str],
        all_components: List[str]
    ) -> Dict[str, ProductInference]:
        """
        Use LLM to infer products for a batch of generic components.
        
        Args:
            target_components: List of generic component names to analyze
            all_components: Full list of components for context
            
        Returns:
            Dict mapping component_name to ProductInference
        """
        if not target_components:
            return {}
        
        if not self.client:
            # Fallback to heuristic-only inference
            logger.info("LLM unavailable - using heuristic fallback")
            return self._fallback_inference(target_components)
        
        # Build prompt
        prompt = f"""Analyze these generic component labels and infer the likely specific technologies.

COMPONENTS TO ANALYZE:
{json.dumps(target_components, indent=2)}

FULL ARCHITECTURE CONTEXT (all components):
{json.dumps(all_components, indent=2)}

For each component in the "COMPONENTS TO ANALYZE" list, provide:
1. suggested_product: The most likely specific technology (or "Generic" if confidence < 0.5)
2. confidence: A score from 0.0 to 1.0
3. reasoning: Brief explanation for your inference

Return results as a JSON object matching the BatchInferenceResult schema."""

        # Call LLM with retry
        response_text = self._call_llm_with_retry(prompt)
        
        if not response_text:
            logger.warning("All LLM attempts failed - using fallback")
            return self._fallback_inference(target_components)
        
        # Parse response
        try:
            data = json.loads(response_text)
            result = BatchInferenceResult.model_validate(data)
            
            # Convert to dict
            inference_map = {}
            for item in result.results:
                inference_map[item.component_name] = item.inference
            
            logger.info(f"LLM inference successful for {len(inference_map)} components")
            return inference_map
            
        except Exception as e:
            logger.error(f"Failed to parse LLM response: {e}")
            return self._fallback_inference(target_components)
    
    def _fallback_inference(
        self,
        components: List[str]
    ) -> Dict[str, ProductInference]:
        """
        Fallback inference using heuristics when LLM is unavailable.
        
        Args:
            components: List of component names
            
        Returns:
            Dict mapping component_name to ProductInference
        """
        result = {}
        
        for comp in components:
            categories = get_generic_category(comp)
            
            if categories:
                result[comp] = ProductInference(
                    suggested_product=categories[0],  # Most likely
                    confidence=0.5,  # Medium confidence for heuristic
                    reasoning=f"Heuristic match: '{comp}' commonly maps to {categories[0]}. Other options: {', '.join(categories[1:3])}"
                )
            else:
                result[comp] = ProductInference(
                    suggested_product="Generic",
                    confidence=0.3,
                    reasoning=f"No heuristic match for '{comp}' - requires manual identification"
                )
        
        return result
    
    def infer_components(
        self,
        raw_labels: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Analyze component labels and infer specific products.
        
        This method:
        1. Identifies known software products directly (high confidence)
        2. Batches generic labels for LLM inference
        3. Returns structured results with confidence scores
        
        Args:
            raw_labels: List of component labels from architecture diagram
            
        Returns:
            List of dicts with:
            - component_name: Original label
            - inferred_product_categories: List of likely products
            - confidence: Float from 0.0 to 1.0
            - reasoning: Explanation for the inference
            - detection_method: "heuristic" or "llm"
        """
        if not raw_labels:
            return []
        
        results = []
        generic_components = []
        
        # First pass: identify known products vs generic labels
        for label in raw_labels:
            if not label or not label.strip():
                # Handle empty labels
                results.append({
                    "component_name": label or "",
                    "inferred_product_categories": ["Unknown"],
                    "confidence": 0.0,
                    "reasoning": "Empty or invalid component label",
                    "detection_method": "heuristic"
                })
                continue
            
            label = label.strip()
            
            if _looks_like_software_identifier(label):
                # Known product - high confidence
                logger.debug(f"Identified known product: {label}")
                results.append({
                    "component_name": label,
                    "inferred_product_categories": [label],
                    "confidence": 0.95,
                    "reasoning": f"'{label}' is a recognized software product/technology",
                    "detection_method": "heuristic"
                })
            else:
                # Generic label - needs inference
                logger.debug(f"Generic label detected: {label}")
                generic_components.append(label)
        
        # Second pass: batch inference for generic components
        if generic_components:
            logger.info(f"Inferring {len(generic_components)} generic components")
            
            # Get context from all components (including known ones)
            all_labels = [r["component_name"] for r in results] + generic_components
            
            # Perform batch inference
            inferences = self._infer_batch_with_llm(generic_components, all_labels)
            
            # Add inference results
            for comp in generic_components:
                if comp in inferences:
                    inference = inferences[comp]
                    
                    # Get additional categories from heuristics
                    heuristic_cats = get_generic_category(comp) or []
                    
                    # Combine LLM inference with heuristics
                    categories = [inference.suggested_product]
                    for cat in heuristic_cats:
                        if cat not in categories:
                            categories.append(cat)
                    
                    results.append({
                        "component_name": comp,
                        "inferred_product_categories": categories[:4],  # Top 4
                        "confidence": inference.confidence,
                        "reasoning": inference.reasoning,
                        "detection_method": "llm" if self.client else "heuristic"
                    })
                else:
                    # Fallback for missing inferences
                    categories = get_generic_category(comp) or ["Generic"]
                    results.append({
                        "component_name": comp,
                        "inferred_product_categories": categories[:4],
                        "confidence": 0.3,
                        "reasoning": f"Unable to infer specific product for '{comp}'",
                        "detection_method": "fallback"
                    })
        
        return results
    
    def analyze_architecture_components(
        self,
        components: List[Dict[str, str]]
    ) -> List[Dict[str, Any]]:
        """
        Analyze components from an ArchitectureSchema.
        
        Args:
            components: List of component dicts with 'name' and 'type' fields
            
        Returns:
            Enhanced component list with inference results
        """
        labels = [c.get("name", "") for c in components]
        inferences = self.infer_components(labels)
        
        # Merge with original component data
        enhanced = []
        for comp, inference in zip(components, inferences):
            enhanced.append({
                **comp,
                **inference
            })
        
        return enhanced


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "ComponentUnderstandingAgent",
    "ProductInference",
    "ComponentInferenceItem",
    "BatchInferenceResult",
    "_looks_like_software_identifier",
    "get_generic_category",
    "GENERIC_LABELS",
    "KNOWN_TECH",
    "GENERIC_TO_TECH",
]
