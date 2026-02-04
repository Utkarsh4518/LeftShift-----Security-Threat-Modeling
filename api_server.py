"""
FastAPI Backend Server for Left<<Shift Frontend.

Provides the /analyze endpoint that:
1. Accepts image or JSON architecture files
2. Runs the Sentinel threat modeling pipeline
3. Returns structured analysis results for visualization
"""

import os
import sys
import io
import json
import tempfile
from datetime import datetime
from typing import Optional

# Fix Windows console encoding for Unicode characters
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Import Sentinel pipeline
from agents.core import run_threat_modeling_pipeline
from tools.models import ArchitectureSchema

app = FastAPI(
    title="Left<<Shift API",
    description="Security Threat Modeling API",
    version="1.0.0"
)

# Enable CORS for frontend (allow multiple ports for dev, Vercel, and Render)
# Get allowed origins from environment or use defaults
allowed_origins = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
    "http://localhost:5176",
    "http://localhost:5177",
    "http://localhost:5178",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "http://127.0.0.1:5175",
    "http://127.0.0.1:5176",
    "http://127.0.0.1:5177",
    "http://127.0.0.1:5178",
]

# Add Vercel deployment URL when running on Vercel (server-side env)
vercel_url = os.getenv("VERCEL_URL")
if vercel_url:
    allowed_origins.append(f"https://{vercel_url}")

# Optional explicit frontend URL (e.g. production Vercel app)
frontend_url = os.getenv("FRONTEND_URL")
if frontend_url:
    allowed_origins.append(frontend_url)

# Regex so all Vercel production and preview origins are allowed (browser sends exact origin)
allow_origin_regex = r"^https://(.*\.vercel\.app|.*\.vercel\.sh)$"

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=allow_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalysisResponse(BaseModel):
    """Response model for analysis endpoint."""
    status: str
    result: Optional[dict] = None
    error: Optional[str] = None


@app.get("/")
async def root():
    """Root route so API URL does not return 404."""
    return {
        "service": "Left<<Shift API",
        "docs": "/docs",
        "health": "/health",
        "analyze": "POST /analyze",
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "left-shift-api"}


@app.post("/analyze")
async def analyze_architecture(
    image: Optional[UploadFile] = File(None),
    json_data: Optional[str] = Form(None, alias="json"),
    example_id: Optional[str] = Form(None),
):
    """
    Analyze an architecture diagram or JSON specification.
    
    Accepts:
    - image: PNG/JPEG architecture diagram
    - json: JSON architecture specification
    - example_id: ID of a built-in example
    """
    try:
        temp_file_path = None
        json_input = None
        
        # Handle image upload
        if image and image.filename:
            # Save uploaded image to temp file
            suffix = os.path.splitext(image.filename)[1]
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
                content = await image.read()
                temp_file.write(content)
                temp_file_path = temp_file.name
        
        # Handle JSON input
        elif json_data:
            try:
                json_input = json.loads(json_data)
                # Validate it matches our schema
                ArchitectureSchema(**json_input)
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid JSON format")
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid architecture schema: {str(e)}")
        
        # Handle example selection
        elif example_id:
            example_files = {
                "ecommerce": "data/test_arch.json",
                "k8s-platform": "data/test_arch1.json",
            }
            if example_id in example_files:
                json_input = example_files[example_id]
            else:
                raise HTTPException(status_code=400, detail=f"Unknown example: {example_id}")
        
        else:
            raise HTTPException(status_code=400, detail="No input provided. Send image, json, or example_id.")
        
        # Run the threat modeling pipeline
        print(f"[API] Starting analysis...")
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"threat_report_{timestamp}.md"
        
        # Run pipeline
        if temp_file_path:
            # Image input
            report, results = run_threat_modeling_pipeline(
                image_path=temp_file_path,
                output_file=output_file,
                verbose=True
            )
            # Clean up temp file
            os.unlink(temp_file_path)
        elif isinstance(json_input, str):
            # JSON file path
            report, results = run_threat_modeling_pipeline(
                json_input=json_input,
                output_file=output_file,
                verbose=True
            )
        else:
            # JSON dict - save to temp file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as temp_json:
                json.dump(json_input, temp_json)
                temp_json_path = temp_json.name
            
            report, results = run_threat_modeling_pipeline(
                json_input=temp_json_path,
                output_file=output_file,
                verbose=True
            )
            os.unlink(temp_json_path)
        
        print(f"[API] Analysis complete. Report saved to {output_file}")
        
        # Debug: print raw results before formatting
        print(f"[API DEBUG] Raw results keys: {list(results.keys())}")
        if "architecture" in results:
            arch = results["architecture"]
            print(f"[API DEBUG] Raw architecture type: {type(arch)}")
            if hasattr(arch, 'components'):
                print(f"[API DEBUG] Raw components count: {len(arch.components)}")
                if arch.components:
                    print(f"[API DEBUG] First component: {arch.components[0]}")
        
        # Format response for frontend
        response_data = format_results_for_frontend(results, report)
        
        # Debug: print what we're returning
        print(f"[API DEBUG] Architecture components: {len(response_data.get('architecture', {}).get('components', []))}")
        print(f"[API DEBUG] Threats: {len(response_data.get('threats', []))}")
        print(f"[API DEBUG] Project name: {response_data.get('architecture', {}).get('project_name', 'N/A')}")
        
        return JSONResponse(content={
            "status": "complete",
            "result": response_data
        })
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"[API] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "error": str(e)
            }
        )


def format_results_for_frontend(results: dict, report_markdown: str) -> dict:
    """
    Format pipeline results for the frontend visualization.
    
    Converts internal Sentinel data structures to the frontend contract.
    """
    # Debug: print what we received
    print(f"[API DEBUG] Results keys: {list(results.keys())}")
    
    # Extract architecture (it's a Pydantic model or dict)
    architecture = results.get("architecture")
    print(f"[API DEBUG] Architecture type: {type(architecture)}")
    
    if architecture:
        if hasattr(architecture, 'components'):
            print(f"[API DEBUG] Architecture.components count: {len(architecture.components)}")
        elif isinstance(architecture, dict):
            print(f"[API DEBUG] Architecture dict components: {len(architecture.get('components', []))}")
    
    if architecture is None:
        frontend_architecture = {
            "project_name": "Unknown Project",
            "description": "",
            "components": [],
            "data_flows": [],
            "trust_boundaries": [],
        }
    elif hasattr(architecture, 'model_dump'):
        # Pydantic v2 model
        arch_dump = architecture.model_dump()
        # Ensure components are properly serialized
        frontend_architecture = {
            "project_name": arch_dump.get("project_name", "Unknown Project"),
            "description": arch_dump.get("description", ""),
            "components": [
                {"name": c.get("name", ""), "type": c.get("type", "")}
                for c in arch_dump.get("components", [])
            ],
            "data_flows": [
                {"source": f.get("source", ""), "destination": f.get("destination", ""), "protocol": f.get("protocol", "")}
                for f in arch_dump.get("data_flows", [])
            ],
            "trust_boundaries": arch_dump.get("trust_boundaries", []),
        }
        print(f"[API DEBUG] Serialized {len(frontend_architecture['components'])} components")
    elif hasattr(architecture, 'dict'):
        # Pydantic v1 model
        frontend_architecture = architecture.dict()
    else:
        # Already a dict
        frontend_architecture = {
            "project_name": architecture.get("project_name", "Unknown Project"),
            "description": architecture.get("description", ""),
            "components": architecture.get("components", []),
            "data_flows": architecture.get("data_flows", []),
            "trust_boundaries": architecture.get("trust_boundaries", []),
        }
    
    # Extract and format threats (list of Pydantic models or dicts)
    threats = []
    raw_threats = results.get("threats", [])
    for threat in raw_threats:
        if hasattr(threat, 'model_dump'):
            threat_dict = threat.model_dump()
        elif hasattr(threat, 'dict'):
            threat_dict = threat.dict()
        elif isinstance(threat, dict):
            threat_dict = threat
        else:
            continue
            
        threats.append({
            "threat_id": threat_dict.get("threat_id", ""),
            "category": threat_dict.get("category", ""),
            "description": threat_dict.get("description", ""),
            "affected_component": threat_dict.get("affected_component", ""),
            "severity": threat_dict.get("severity", "Medium"),
            "mitigation_steps": threat_dict.get("mitigation_steps", []),
            "cwe_id": threat_dict.get("cwe_id"),
            "impact": threat_dict.get("impact"),
        })
    
    # Extract weaknesses
    weaknesses = []
    raw_weaknesses = results.get("weaknesses", [])
    for weakness in raw_weaknesses:
        if hasattr(weakness, 'model_dump'):
            weaknesses.append(weakness.model_dump())
        elif hasattr(weakness, 'dict'):
            weaknesses.append(weakness.dict())
        elif isinstance(weakness, dict):
            weaknesses.append(weakness)
    
    # Extract CVEs
    cves = []
    raw_cves = results.get("cves", [])
    for cve in raw_cves:
        if hasattr(cve, 'model_dump'):
            cve_dict = cve.model_dump()
        elif hasattr(cve, 'dict'):
            cve_dict = cve.dict()
        elif isinstance(cve, dict):
            cve_dict = cve
        else:
            continue
            
        cves.append({
            "cve_id": cve_dict.get("cve_id", ""),
            "summary": cve_dict.get("summary", ""),
            "severity": cve_dict.get("severity", "Medium"),
            "affected_products": cve_dict.get("affected_products", ""),
            "cvss_score": cve_dict.get("cvss_score"),
            "is_actively_exploited": cve_dict.get("is_actively_exploited", False),
        })
    
    return {
        "architecture": frontend_architecture,
        "threats": threats,
        "weaknesses": weaknesses,
        "cves": cves,
        "report_markdown": report_markdown,
    }


if __name__ == "__main__":
    import uvicorn
    print("Starting Left<<Shift API Server...")
    print("Frontend should connect to: http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
