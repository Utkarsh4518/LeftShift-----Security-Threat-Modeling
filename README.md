# Left<<Shift

## AI-Powered Threat Modeling System

**Left<<Shift** is an advanced, multi-agent threat modeling system that leverages Google Gemini AI to automate security analysis of software architectures. Developed for the **Cursor – AI Hackathon**, it shifts security analysis *left* in the software development lifecycle by enabling early-stage, design-time threat modeling.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Pipeline Stages](#pipeline-stages)
- [Agent Details](#agent-details)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Team](#team)
- [License](#license)

---

## Overview

Left<<Shift analyzes software architecture diagrams or JSON specifications and produces comprehensive security threat reports including:

- **STRIDE Threat Analysis** - Systematic identification of Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege threats
- **CVE Discovery** - Real-time vulnerability lookup from NVD and CISA KEV databases
- **Attack Path Simulation** - Multi-step attack scenarios with MITRE ATT&CK technique mapping
- **Mitigation Recommendations** - Actionable security controls mapped to NIST 800-53

The system is designed for security engineers, architects, and developers who want to identify security risks during the design phase, before vulnerabilities become costly to fix.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Agent Architecture** | 7 specialized AI agents working in concert |
| **Vision-Enabled Analysis** | Analyzes architecture diagrams directly using Gemini Vision |
| **LangGraph Orchestration** | Parallel execution with state management and checkpointing |
| **Intelligent Caching** | LRU cache for component inference, TTL cache for CVE lookups |
| **Architecture-Aware** | Detects AWS/Kubernetes/Serverless architectures and tailors analysis |
| **Strict Validation** | Pydantic models ensure data integrity throughout the pipeline |
| **No Hallucination** | Explicit rules prevent the AI from inventing CVEs or incorrect mappings |

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        LEFT<<SHIFT PIPELINE ARCHITECTURE                     │
└─────────────────────────────────────────────────────────────────────────────┘

                              ┌──────────────────┐
                              │   Input Source   │
                              │  (Image / JSON)  │
                              └────────┬─────────┘
                                       │
                                       ▼
                    ┌──────────────────────────────────────┐
                    │    Stage 1: Architecture Extraction   │
                    │         (Vision Agent / JSON)         │
                    │      Model: gemini-3-pro-image-preview│
                    └────────────────┬─────────────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    │         PARALLEL EXECUTION       │
                    ▼                                  ▼
     ┌──────────────────────────┐    ┌──────────────────────────┐
     │ Stage 2a: Component      │    │ Stage 2b: Threat         │
     │ Understanding Agent      │    │ Knowledge Agent (STRIDE) │
     │ Model: gemini-3-pro-     │    │ Model: gemini-3-pro-     │
     │        preview           │    │        preview           │
     └───────────┬──────────────┘    └───────────┬──────────────┘
                 │                                │
                 └────────────────┬───────────────┘
                                  │
                                  ▼
                    ┌──────────────────────────────────────┐
                    │     Stage 3: CVE Discovery Agent      │
                    │         (NVD + CISA KEV APIs)         │
                    │            No LLM Required            │
                    └────────────────┬─────────────────────┘
                                     │
                                     ▼
                    ┌──────────────────────────────────────┐
                    │   Stage 4: Threat Relevance Agent     │
                    │       Model: gemini-3-pro-preview     │
                    └────────────────┬─────────────────────┘
                                     │
                                     ▼
                    ┌──────────────────────────────────────┐
                    │   Stage 5: Attack Path Generation     │
                    │    (Architecture-Aware, No LLM)       │
                    └────────────────┬─────────────────────┘
                                     │
                                     ▼
                    ┌──────────────────────────────────────┐
                    │   Stage 6: Report Synthesizer Agent   │
                    │       Model: gemini-3-pro-preview     │
                    └────────────────┬─────────────────────┘
                                     │
                                     ▼
                              ┌──────────────────┐
                              │  Markdown Report │
                              │   (12 Sections)  │
                              └──────────────────┘
```

### LangGraph State Machine

The pipeline uses LangGraph for orchestration, enabling:

- **Parallel Execution**: Stages 2a and 2b run simultaneously
- **State Management**: TypedDict state flows between nodes
- **Checkpointing**: Failed runs can be resumed from the last successful stage
- **Error Handling**: Graceful degradation with fallback mechanisms

```
                    ┌─────────────────────┐
                    │  extract_architecture│
                    └─────────┬───────────┘
                              │
              ┌───────────────┴───────────────┐
              │                               │
              ▼                               ▼
    ┌─────────────────────┐     ┌──────────────────────┐
    │ understand_components│     │   generate_threats   │
    └─────────┬───────────┘     └──────────┬───────────┘
              │                             │
              └───────────────┬─────────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │    discover_cves    │
                    └─────────┬───────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │  analyze_relevance  │
                    └─────────┬───────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │generate_attack_paths│
                    └─────────┬───────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │  synthesize_report  │
                    └─────────────────────┘
```

---

## Pipeline Stages

### Stage 1: Architecture Extraction

**Purpose**: Extract components, data flows, and trust boundaries from architecture diagrams or JSON specifications.

**Input**: 
- PNG/JPEG architecture diagram, OR
- JSON architecture specification

**Output**: `ArchitectureSchema` with:
- List of components (name, type)
- Data flows (source, destination, protocol)
- Trust boundaries

**Model**: `gemini-3-pro-image-preview` (for images)

### Stage 2a: Component Understanding (Parallel)

**Purpose**: Infer specific technologies from component labels. Distinguishes between known software products and generic labels.

**Key Features**:
- AWS service detection (EC2, S3, Lambda, etc. map to themselves)
- Technology product recognition (MySQL, Redis, Nginx, etc.)
- LLM inference for ambiguous labels
- Caching for repeated analyses

**Output**: Enhanced components with:
- `inferred_product_categories`
- `confidence` score (0.0-1.0)
- `reasoning` explanation

**Model**: `gemini-3-pro-preview` (primary), `gemini-2.5-pro` (fallback)

### Stage 2b: Threat Knowledge - STRIDE Analysis (Parallel)

**Purpose**: Generate STRIDE threats for each component based on its role in the architecture.

**Key Features**:
- Quality over quantity (2-4 targeted threats per component)
- Strict severity calibration (Critical/High/Medium/Low)
- CWE mapping with validation
- Architecture context awareness

**STRIDE Categories**:
| Category | Description |
|----------|-------------|
| **S**poofing | Impersonating users or systems |
| **T**ampering | Modifying data or code |
| **R**epudiation | Denying actions without proof |
| **I**nformation Disclosure | Exposing sensitive data |
| **D**enial of Service | Disrupting availability |
| **E**levation of Privilege | Gaining unauthorized access |

**Model**: `gemini-3-pro-preview` (primary), `gemini-2.5-pro` (fallback)

### Stage 3: CVE Discovery

**Purpose**: Discover known vulnerabilities affecting the identified technologies.

**Data Sources**:
- **NVD** (National Vulnerability Database) - CVE details, CVSS scores
- **CISA KEV** (Known Exploited Vulnerabilities) - Actively exploited CVEs

**Key Features**:
- Product name normalization
- Recency filtering (last 3 years)
- Deduplication
- 24-hour TTL caching
- Mitigation enrichment

**Output**: List of `ThreatRecord` objects with:
- CVE ID, severity, CVSS score
- Affected products
- CISA KEV status
- Mitigation strategies

**Model**: No LLM required (API-based)

### Stage 4: Threat Relevance Analysis

**Purpose**: Filter CVEs for architectural relevance and promote critical ones to threats.

**Key Features**:
- Conservative scoring (most CVEs are irrelevant)
- Prerequisite analysis
- Likelihood assessment
- CVE-to-threat promotion

**Relevance Levels**:
| Level | Criteria |
|-------|----------|
| HIGH | Directly exploitable, no prerequisites |
| MEDIUM | Requires specific conditions |
| LOW | Theoretical risk, unlikely exploit |
| IRRELEVANT | Does not apply to this architecture |

**Model**: `gemini-3-pro-preview` (primary), `gemini-2.5-pro` (fallback)

### Stage 5: Attack Path Generation

**Purpose**: Simulate realistic multi-step attack scenarios.

**Architecture-Aware Paths**:

| Architecture Type | Attack Path |
|-------------------|-------------|
| **AWS EC2** | IMDS Credential Theft → IAM Enumeration → S3 Exfiltration |
| **Kubernetes** | Supply Chain → Pod Compromise → Service Mesh Pivot |
| **Serverless** | Function Injection → Environment Variables → Connected Services |

**Key Features**:
- Follows actual data flows
- References identified threats and CVEs
- MITRE ATT&CK technique mapping
- Likelihood based on threat severity

**Model**: No LLM required (rule-based)

### Stage 6: Report Synthesis

**Purpose**: Generate a comprehensive, human-readable security report.

**Report Sections** (12 total):
1. Executive Summary
2. Architecture Extraction
3. Component Inventory Table
4. STRIDE Threat Enumeration
5. Architectural Weaknesses
6. CVE Discovery Results
7. Threat ↔ CVE Correlation Matrix
8. Attack Path Simulations
9. Component Security Profiles
10. NIST 800-53 Control Mapping
11. Hardening Plan (Quick Wins, Short-term, Long-term)
12. Appendix

**Model**: `gemini-3-pro-preview` (primary), `gemini-2.5-pro` (fallback)

---

## Agent Details

### 1. Vision Agent (`tools/diagram_processor.py`)

| Property | Value |
|----------|-------|
| **Purpose** | Extract architecture from images |
| **Model** | `gemini-3-pro-image-preview` |
| **Input** | PNG/JPEG diagram or GCS URI |
| **Output** | JSON matching `ArchitectureSchema` |
| **Fallback** | JSON file bypass for testing |

### 2. Component Understanding Agent (`agents/component_understanding_agent.py`)

| Property | Value |
|----------|-------|
| **Purpose** | Infer technologies from labels |
| **Primary Model** | `gemini-3-pro-preview` |
| **Fallback Model** | `gemini-2.5-pro` |
| **Retry Logic** | 3 attempts with exponential backoff |
| **Caching** | LRU cache (256 entries) |

**Special Handling**:
- AWS services always map to themselves
- Known technologies detected via heuristics
- Generic labels sent to LLM for inference

### 3. Threat Knowledge Agent (`agents/threat_knowledge_agent.py`)

| Property | Value |
|----------|-------|
| **Purpose** | STRIDE threat generation |
| **Primary Model** | `gemini-3-pro-preview` |
| **Fallback Model** | `gemini-2.5-pro` |
| **Output** | `ArchitecturalThreat` + `ArchitecturalWeakness` |
| **Validation** | CWE mapping verification |

**Severity Calibration**:
- **CRITICAL**: Remote code execution, auth bypass, data breach at scale
- **HIGH**: Significant data exposure, privilege escalation
- **MEDIUM**: Limited scope attacks, requires conditions
- **LOW**: Informational, minimal impact

### 4. CVE Discovery Agent (`agents/cve_discovery_agent.py`)

| Property | Value |
|----------|-------|
| **Purpose** | Vulnerability lookup |
| **APIs** | NVD (nvdlib), CISA KEV |
| **Caching** | 24-hour TTL per product |
| **Deduplication** | CVE ID based |

### 5. Threat Relevance Agent (`agents/threat_relevance_agent.py`)

| Property | Value |
|----------|-------|
| **Purpose** | Filter and score CVEs |
| **Primary Model** | `gemini-3-pro-preview` |
| **Fallback Model** | `gemini-2.5-pro` |
| **Output** | Filtered CVEs + promoted threats |

### 6. Report Synthesizer Agent (`agents/report_synthesizer_agent.py`)

| Property | Value |
|----------|-------|
| **Purpose** | Generate Markdown report |
| **Primary Model** | `gemini-3-pro-preview` |
| **Fallback Model** | `gemini-2.5-pro` |
| **Max Tokens** | 32,768 |
| **Validation** | Strict CVE/threat data integrity |

---

## Technology Stack

### AI/LLM
- **Google Gemini 3 Pro Preview** - Primary text model
- **Google Gemini 3 Pro Image Preview** - Vision/diagram analysis
- **Google Gemini 2.5 Pro** - Fallback model

### Orchestration
- **LangGraph** - State machine orchestration with parallel execution
- **LangChain Core** - Foundation for LangGraph

### Data Validation
- **Pydantic v2** - Schema validation and serialization

### APIs
- **NVD (nvdlib)** - CVE data from NIST
- **CISA KEV** - Known exploited vulnerabilities

### Utilities
- **Tenacity** - Retry logic with exponential backoff
- **python-dotenv** - Environment variable management

---

## Installation

### Prerequisites
- Python 3.10+
- Google Gemini API key

### Steps

```bash
# Clone the repository
git clone https://github.com/Utkarsh4518/LeftShift-----Security-Threat-Modeling.git
cd LeftShift-----Security-Threat-Modeling

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# OR
.venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

### Environment Variables

```env
GEMINI_API_KEY=your_gemini_api_key_here
OPENAI_API_KEY=your_openai_api_key_here  # Optional, for future use
```

---

## Usage

### Command Line

```bash
# Analyze an architecture diagram
python main.py --image data/test_arch.png --output report.md

# Analyze a JSON specification
python main.py --input data/architecture.json --output report.md
```

### Programmatic

```python
from agents.core import run_threat_modeling_pipeline

# With LangGraph (default - parallel execution)
report, results = run_threat_modeling_pipeline(
    json_input="data/architecture.json",
    output_file="report.md",
    verbose=True
)

# Without LangGraph (sequential execution)
report, results = run_threat_modeling_pipeline(
    json_input="data/architecture.json",
    use_langgraph=False
)
```

---

## Project Structure

```
LeftShift-----Security-Threat-Modeling/
├── agents/
│   ├── __init__.py
│   ├── cache.py                    # Caching utilities (LRU, TTL)
│   ├── component_understanding_agent.py  # Technology inference
│   ├── core.py                     # Pipeline orchestration
│   ├── cve_discovery_agent.py      # NVD/CISA KEV integration
│   ├── graph.py                    # LangGraph pipeline
│   ├── report_synthesizer_agent.py # Report generation
│   ├── threat_knowledge_agent.py   # STRIDE analysis
│   └── threat_relevance_agent.py   # CVE filtering
├── tools/
│   ├── __init__.py
│   ├── diagram_processor.py        # Vision agent
│   ├── mitigation_engine.py        # Mitigation generation
│   ├── models.py                   # Pydantic data models
│   └── threat_intel_api.py         # NVD/KEV API clients
├── tests/
│   ├── test_*.py                   # Unit tests
│   └── test_integration.py         # Integration tests
├── data/
│   ├── test_arch1.png              # Sample architecture diagram
│   ├── test_arch1.json             # Sample JSON specification
│   └── test_arch2.png              # AWS architecture diagram
├── main.py                         # CLI entry point
├── requirements.txt                # Python dependencies
├── .env                            # Environment variables
└── README.md                       # This file
```

---

## Future Enhancements

- [ ] Azure/GCP service detection
- [ ] SBOM (Software Bill of Materials) integration
- [ ] Interactive report viewer
- [ ] CI/CD pipeline integration
- [ ] Custom threat taxonomy support
- [ ] Multi-language report generation

---

## Team

Developed by Master's students from **Hamburg University of Technology (TUHH)**:

- **Utkarsh Maurya**
- **Manish Mahesh Kumar**
- **Priyanu Tushar**
- **Pratham Hegde**

---

## Hackathon Context

This project was developed as part of the **Cursor – AI Hackathon**, demonstrating practical AI-assisted security engineering workflows.

---

## License

MIT License - See LICENSE file for details.

---

## Acknowledgments

- Google Gemini team for the powerful AI models
- NIST NVD for vulnerability data
- CISA for the Known Exploited Vulnerabilities catalog
- MITRE for ATT&CK framework
- LangChain team for LangGraph
