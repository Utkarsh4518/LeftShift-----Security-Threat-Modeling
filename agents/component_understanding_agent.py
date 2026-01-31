"""
Component Understanding Agent for Left<<Shift Threat Modeling System.

This agent analyzes component labels from architecture diagrams and determines
whether they represent specific software products or generic labels. For generic
labels, it uses LLM-based inference to suggest likely technologies based on context.

Uses Google Gemini for text-based reasoning tasks.
Includes caching for improved performance on repeated analyses.
"""

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Set

from dotenv import load_dotenv
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

from agents.cache import get_component_cache, make_cache_key

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
    
    # Cloud Services - AWS (short names)
    "ec2", "s3", "rds", "lambda", "ecs", "eks", "fargate", "api gateway",
    "cloudfront", "route53", "elasticache", "aurora", "redshift", "athena",
    "ebs", "elb", "alb", "nlb", "sqs", "sns", "iam", "vpc", "acm",
    
    # Cloud Services - AWS (full names - critical for diagram recognition)
    "amazon ec2", "ec2 instance", "amazon s3", "s3 bucket", "amazon s3 bucket",
    "amazon rds", "amazon route 53", "route 53", "amazon route53",
    "elastic load balancing", "elastic load balancer", "application load balancer",
    "network load balancer", "classic load balancer",
    "amazon cloudfront", "amazon ebs", "ebs volume", "ebs snapshot",
    "amazon ebs snapshot", "root volume", "data volume",
    "auto scaling", "auto scaling group", "amazon auto scaling",
    "amazon vpc", "amazon iam", "aws lambda", "amazon lambda",
    "amazon dynamodb", "amazon elasticache", "amazon aurora",
    "amazon redshift", "amazon athena", "amazon kinesis",
    "amazon sqs", "amazon sns", "amazon eventbridge",
    "aws waf", "amazon waf", "aws shield", "amazon cloudwatch",
    "aws cloudtrail", "amazon cloudtrail", "aws secrets manager",
    "aws kms", "amazon kms", "key management service",
    
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


def _is_aws_service(name: str) -> bool:
    """
    Check if a component name is an AWS service.
    AWS services should always map to themselves, not be inferred as something else.
    """
    normalized = _normalize_name(name)
    
    # AWS service patterns - these should ALWAYS be recognized
    aws_patterns = [
        'amazon', 'aws', 'ec2', 's3', 'rds', 'lambda', 'cloudfront',
        'route 53', 'route53', 'elastic load', 'elb', 'alb', 'nlb',
        'ebs', 'auto scaling', 'autoscaling', 'dynamodb', 'elasticache',
        'sqs', 'sns', 'kinesis', 'cloudwatch', 'cloudtrail', 'iam',
        'vpc', 'kms', 'waf', 'shield', 'secrets manager', 'aurora',
        'redshift', 'athena', 'glue', 'emr', 'eks', 'ecs', 'fargate',
        'api gateway', 'cognito', 'eventbridge'
    ]
    
    for pattern in aws_patterns:
        if pattern in normalized:
            return True
    
    return False


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
    
    # AWS services are ALWAYS recognized as specific software
    if _is_aws_service(name):
        return True
    
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
    
    STRICT MATCHING: Only returns tech suggestions when there's a clear infrastructure match.
    Business services (Orders, Customer, Catalog) should NOT be mapped to analytics/etc.
    
    Args:
        name: The generic component name
        
    Returns:
        List of likely technology categories, or None if not found
    """
    normalized = _normalize_name(name)
    
    # EXCLUSIONS: These component types should NOT be mapped to tech products
    # They are business services, not infrastructure
    exclusion_patterns = [
        'service', 'orders', 'customer', 'catalog', 'inventory', 'payment',
        'browser', 'mobile', 'client', 'user', 'frontend', 'web browser',
        'mobile app', 'application', 'app', 'backend service', 'microservice'
    ]
    
    for pattern in exclusion_patterns:
        if pattern in normalized:
            return None  # Don't infer tech for business services
    
    # Direct match only - partial matches are too error-prone
    if normalized in GENERIC_TO_TECH:
        return GENERIC_TO_TECH[normalized]
    
    # Only do partial match for INFRASTRUCTURE keywords, not services
    infrastructure_keywords = ['database', 'cache', 'queue', 'server', 'proxy', 
                               'gateway', 'storage', 'cdn', 'load balancer']
    
    for keyword in infrastructure_keywords:
        if keyword in normalized:
            if keyword in GENERIC_TO_TECH:
                return GENERIC_TO_TECH[keyword]
    
    return None


# =============================================================================
# LLM-Based Inference
# =============================================================================

INFERENCE_SYSTEM_PROMPT = """You are a software architecture expert. Your job is to identify what technology a component ACTUALLY IS, not what it connects to.

## CRITICAL RULES - READ CAREFULLY:

### RULE 0: AWS/CLOUD SERVICES MUST MAP TO THEMSELVES
This is the most important rule. If a component IS an AWS/Azure/GCP service, return that service name:
- "EC2 Instance" -> suggested_product: "EC2 Instance" (NOT CloudFront, NOT anything else)
- "Auto Scaling group" -> suggested_product: "Auto Scaling group" (NOT Route 53)
- "Elastic Load Balancing" -> suggested_product: "Elastic Load Balancing"
- "Amazon S3 Bucket" -> suggested_product: "Amazon S3 Bucket"
- "Amazon Route 53" -> suggested_product: "Amazon Route 53"
- "CloudFront" -> suggested_product: "CloudFront"
- "Amazon EBS Snapshot" -> suggested_product: "Amazon EBS Snapshot"
- "Root Volume" -> suggested_product: "EBS Volume" (it's an EBS volume)
- "Data Volume" -> suggested_product: "EBS Volume" (it's an EBS volume)
DO NOT infer a DIFFERENT AWS service. The component IS what it says it is.

### RULE 1: Match the component itself, NOT its connections
- "Web Browser" = the user's browser (Chrome, Firefox) - NOT a backend database
- "Mobile App" = a mobile application (iOS/Android) - NOT a server
- "Public Route" = an ingress/load balancer - NOT a database
- "Orders Service" = a business microservice - NOT analytics software

### RULE 2: If the component name already identifies the technology, USE IT
- "MySQL (Inventory)" -> suggested_product: "MySQL"
- "Redis Cache" -> suggested_product: "Redis"
- "Elasticsearch (Catalog)" -> suggested_product: "Elasticsearch"
- "PostgreSQL Database" -> suggested_product: "PostgreSQL"

### RULE 3: For generic frontend/client components, mark as Generic
These should have suggested_product = "Generic" (they are not specific products):
- "Web Browser" -> Generic (it's a client, not a specific tech)
- "Mobile App" -> Generic (could be any mobile platform)
- "Frontend Service" -> Generic (unless React/Vue/Angular is specified)
- "Web Frontend" -> Generic

### RULE 4: For backend services without specific tech, mark as Generic
- "Orders Service" -> Generic (it's a business service, not a specific tech)
- "Customer Service" -> Generic
- "Catalog Service" -> Generic
- "Auth Service" -> Generic (unless Keycloak/Auth0/etc specified)

### RULE 5: NEVER infer unrelated products
WRONG: "EC2 Instance" -> "CloudFront" (EC2 is EC2, not CloudFront)
WRONG: "Auto Scaling group" -> "Route 53" (Auto Scaling is not DNS)
WRONG: "Root Volume" -> "Elastic Load Balancing" (Volume is storage, not networking)
WRONG: "Orders Service" -> "Google Analytics" (analytics is unrelated)
WRONG: "Web Browser" -> "Elasticsearch" (browser is not a search engine)

### RULE 6: Confidence calibration
- 1.0: Name explicitly contains the product (e.g., "MySQL Database", "EC2 Instance")
- 0.95: Very clear indicator (e.g., "Redis Cache", "Auto Scaling group")
- 0.7-0.8: Strong contextual inference
- 0.5-0.6: Reasonable guess
- Below 0.5: Use "Generic"

## OUTPUT:
Return JSON with results array. Each item:
- component_name: exact name from input
- inference.suggested_product: the product name OR "Generic"
- inference.confidence: 0.0-1.0
- inference.reasoning: brief explanation
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
        self.client: Optional[genai.Client] = None
        self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize Gemini client if API key is available."""
        api_key = os.getenv("GEMINI_API_KEY")
        if api_key and api_key != "your_gemini_api_key_here":
            try:
                self.client = genai.Client(api_key=api_key)
                logger.info("Gemini client initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini client: {e}")
                self.client = None
        else:
            logger.warning("GEMINI_API_KEY not configured - LLM inference disabled")
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
            
            full_prompt = f"{INFERENCE_SYSTEM_PROMPT}\n\n{prompt}"
            
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
        components: List[Dict[str, str]],
        use_cache: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Analyze components from an ArchitectureSchema.
        
        Args:
            components: List of component dicts with 'name' and 'type' fields
            use_cache: Whether to use caching for repeated analyses (default: True)
            
        Returns:
            Enhanced component list with inference results
        """
        # Check cache first
        if use_cache:
            cache = get_component_cache()
            cache_key = make_cache_key(components)
            cached_result = cache.get(cache_key)
            if cached_result is not None:
                logger.info(f"Using cached component inference ({len(cached_result)} components)")
                return cached_result
        
        labels = [c.get("name", "") for c in components]
        inferences = self.infer_components(labels)
        
        # Merge with original component data
        enhanced = []
        for comp, inference in zip(components, inferences):
            enhanced.append({
                **comp,
                **inference
            })
        
        # Store in cache
        if use_cache:
            cache.set(cache_key, enhanced)
            logger.info(f"Cached component inference for {len(enhanced)} components")
        
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
