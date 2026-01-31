"""
Vision Agent - Architecture Diagram Processor for Left<<Shift.

This module uses Google Gemini's multimodal API to analyze architecture
diagram images and extract structured security-relevant information.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv
from google import genai
from google.genai import types
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from tools.models import ArchitectureSchema, Component, DataFlow

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Vision prompt for architecture diagram analysis
VISION_PROMPT = """
Analyze the uploaded system architecture diagram. Your task is to identify
all software components, their versions (if labeled), describe the data flows,
and identify all trust boundaries or security zones shown.

You MUST respond with a single JSON object that strictly conforms to the
ArchitectureSchema defined in the response_schema.

Instructions:
1. IDENTIFY ALL SOFTWARE COMPONENTS visible in the diagram:
   - Web servers, application servers, databases, load balancers, firewalls
   - APIs, microservices, message queues, caches
   - External services, third-party integrations
   - Include version numbers if they are labeled in the diagram

2. EXTRACT DATA FLOWS between components:
   - Source component name
   - Destination component name
   - Protocol used (HTTP, HTTPS, TCP, gRPC, AMQP, etc.)
   - Include port numbers if visible (e.g., "TCP/5432", "HTTPS/443")

3. IDENTIFY TRUST BOUNDARIES and security zones:
   - Internet/External zone
   - DMZ (Demilitarized Zone)
   - Internal network zones
   - Database zones
   - Any labeled security perimeters

4. For the project_name field:
   - Use any title visible in the diagram
   - If no title, use "Analyzed Architecture"

5. For the description field:
   - Provide a brief summary of what the architecture represents
   - Include any assumptions you made about unlabeled elements

CRITICAL RULES:
- DO NOT include any conversational text, explanations, or code fences outside the JSON
- DO NOT invent components that are not clearly visible in the diagram
- DO NOT guess at internal implementation details not shown
- If you need to make assumptions about unlabeled elements, document them in the description field
- Output ONLY the raw JSON object, no markdown formatting
"""


def _get_gemini_client() -> genai.Client:
    """Initialize and return Gemini client."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY environment variable not set")
    return genai.Client(api_key=api_key)


def _load_image_from_path(image_path: str) -> tuple[bytes, str]:
    """
    Load image from local path.
    
    Returns:
        Tuple of (image_bytes, mime_type)
    """
    path = Path(image_path)
    
    if not path.exists():
        raise FileNotFoundError(f"Image file not found: {image_path}")
    
    # Determine MIME type
    suffix = path.suffix.lower()
    mime_types = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".bmp": "image/bmp",
    }
    
    mime_type = mime_types.get(suffix)
    if not mime_type:
        raise ValueError(f"Unsupported image format: {suffix}. Supported: {list(mime_types.keys())}")
    
    # Read image bytes
    with open(path, "rb") as f:
        image_bytes = f.read()
    
    if len(image_bytes) == 0:
        raise ValueError(f"Image file is empty: {image_path}")
    
    return image_bytes, mime_type


def _is_json_file(file_path: str) -> bool:
    """Check if the file is a JSON file (bypass mode)."""
    return file_path.lower().endswith(".json")


def _is_gcs_uri(path: str) -> bool:
    """Check if path is a Google Cloud Storage URI."""
    return path.startswith("gs://")


def _create_response_schema() -> dict:
    """Create JSON schema for structured output based on ArchitectureSchema."""
    return {
        "type": "object",
        "properties": {
            "project_name": {
                "type": "string",
                "description": "Name of the project or system"
            },
            "description": {
                "type": "string",
                "description": "Description of the architecture"
            },
            "components": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "type": {"type": "string"}
                    },
                    "required": ["name", "type"]
                }
            },
            "data_flows": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "source": {"type": "string"},
                        "destination": {"type": "string"},
                        "protocol": {"type": "string"}
                    },
                    "required": ["source", "destination", "protocol"]
                }
            },
            "trust_boundaries": {
                "type": "array",
                "items": {"type": "string"}
            }
        },
        "required": ["project_name", "description", "components", "data_flows", "trust_boundaries"]
    }


@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=60),
    retry=retry_if_exception_type((ConnectionError, TimeoutError)),
    before_sleep=lambda retry_state: logger.warning(
        f"Retry attempt {retry_state.attempt_number} after error: {retry_state.outcome.exception()}"
    )
)
def _call_gemini_vision(
    client: genai.Client,
    image_data: Any,
    mime_type: Optional[str] = None,
    is_gcs: bool = False
) -> str:
    """
    Call Gemini Vision API with retry logic.
    
    Args:
        client: Gemini client
        image_data: Image bytes or GCS URI
        mime_type: MIME type for local images
        is_gcs: Whether image_data is a GCS URI
        
    Returns:
        JSON string response from the model
    """
    # Build content parts
    if is_gcs:
        # For GCS URIs, use file_data
        image_part = types.Part.from_uri(
            file_uri=image_data,
            mime_type="image/png"  # Default, adjust if needed
        )
    else:
        # For local files, use inline_data
        image_part = types.Part.from_bytes(
            data=image_data,
            mime_type=mime_type
        )
    
    contents = [
        types.Content(
            role="user",
            parts=[
                image_part,
                types.Part.from_text(text=VISION_PROMPT)
            ]
        )
    ]
    
    # Configure generation with response schema
    generation_config = types.GenerateContentConfig(
        temperature=0.1,  # Low temperature for consistent structured output
        response_mime_type="application/json",
        response_schema=_create_response_schema()
    )
    
    # Call the model
    response = client.models.generate_content(
        model="gemini-3-pro-image-preview",  # Gemini 3 Pro Image for vision/diagram analysis
        contents=contents,
        config=generation_config
    )
    
    return response.text


def process_architecture_diagram(
    tool_context: Any,
    image_path: str
) -> str:
    """
    Process an architecture diagram and extract structured information.
    
    This function analyzes an architecture diagram image using Google Gemini's
    multimodal capabilities and returns structured JSON matching ArchitectureSchema.
    
    Args:
        tool_context: Tool context (can be None for standalone usage)
        image_path: Path to the image file (local path or gs:// URI)
                   Also supports .json files for testing bypass
    
    Returns:
        JSON string containing the extracted architecture information,
        or an error dict as JSON string if processing fails
    
    Examples:
        >>> result = process_architecture_diagram(None, "data/architecture.png")
        >>> result = process_architecture_diagram(None, "gs://bucket/diagram.png")
        >>> result = process_architecture_diagram(None, "data/test_arch.json")
    """
    logger.info(f"Processing architecture diagram: {image_path}")
    
    try:
        # Handle JSON bypass mode for testing
        if _is_json_file(image_path):
            logger.info("JSON file detected - using bypass mode")
            path = Path(image_path)
            if not path.exists():
                return json.dumps({"error": f"JSON file not found: {image_path}"})
            
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            
            # Validate it's valid JSON and matches schema
            try:
                data = json.loads(content)
                # Validate against ArchitectureSchema
                schema = ArchitectureSchema.model_validate(data)
                logger.info(f"JSON bypass successful - loaded {len(schema.components)} components")
                return schema.model_dump_json(indent=2)
            except json.JSONDecodeError as e:
                return json.dumps({"error": f"Invalid JSON in file: {e}"})
            except Exception as e:
                return json.dumps({"error": f"JSON validation failed: {e}"})
        
        # Initialize Gemini client
        try:
            client = _get_gemini_client()
        except ValueError as e:
            logger.error(f"Client initialization failed: {e}")
            return json.dumps({"error": str(e)})
        
        # Handle GCS URIs
        if _is_gcs_uri(image_path):
            logger.info("Processing GCS URI")
            try:
                response_text = _call_gemini_vision(
                    client=client,
                    image_data=image_path,
                    is_gcs=True
                )
            except Exception as e:
                logger.error(f"GCS processing failed: {e}")
                return json.dumps({"error": f"Failed to process GCS image: {e}"})
        else:
            # Handle local files
            logger.info("Processing local image file")
            try:
                image_bytes, mime_type = _load_image_from_path(image_path)
            except FileNotFoundError as e:
                logger.error(f"File not found: {e}")
                return json.dumps({"error": str(e)})
            except ValueError as e:
                logger.error(f"Invalid image: {e}")
                return json.dumps({"error": str(e)})
            
            try:
                response_text = _call_gemini_vision(
                    client=client,
                    image_data=image_bytes,
                    mime_type=mime_type,
                    is_gcs=False
                )
            except Exception as e:
                logger.error(f"Vision API call failed: {e}")
                return json.dumps({"error": f"Gemini API error: {e}"})
        
        # Parse and validate response
        try:
            data = json.loads(response_text)
            schema = ArchitectureSchema.model_validate(data)
            logger.info(
                f"Successfully extracted: {len(schema.components)} components, "
                f"{len(schema.data_flows)} data flows, "
                f"{len(schema.trust_boundaries)} trust boundaries"
            )
            return schema.model_dump_json(indent=2)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse response JSON: {e}")
            return json.dumps({"error": f"Invalid JSON response from model: {e}"})
        except Exception as e:
            logger.error(f"Response validation failed: {e}")
            return json.dumps({"error": f"Response validation failed: {e}"})
            
    except Exception as e:
        logger.exception(f"Unexpected error processing diagram: {e}")
        return json.dumps({"error": f"Unexpected error: {e}"})


def validate_architecture_output(json_str: str) -> tuple[bool, Optional[ArchitectureSchema], Optional[str]]:
    """
    Validate that a JSON string matches ArchitectureSchema.
    
    Args:
        json_str: JSON string to validate
        
    Returns:
        Tuple of (is_valid, schema_or_none, error_message_or_none)
    """
    try:
        data = json.loads(json_str)
        
        # Check for error response
        if "error" in data and len(data) == 1:
            return False, None, data["error"]
        
        schema = ArchitectureSchema.model_validate(data)
        return True, schema, None
    except json.JSONDecodeError as e:
        return False, None, f"Invalid JSON: {e}"
    except Exception as e:
        return False, None, f"Validation error: {e}"


# Export for ADK tool registration
__all__ = [
    "process_architecture_diagram",
    "validate_architecture_output",
    "VISION_PROMPT",
]
