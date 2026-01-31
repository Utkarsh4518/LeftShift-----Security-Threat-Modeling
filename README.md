# Left<<Shift

## Overview
**Left<<Shift** is an AI-powered threat modeling system developed as part of the **Cursor – AI Hackathon**.

The project focuses on shifting security analysis *left* in the software lifecycle by automating early-stage threat modeling using a multi-agent, AI-assisted pipeline. The system is designed to analyze software architectures and generate structured security insights such as STRIDE threats, relevant vulnerabilities, attack paths, and consolidated security reports.

This project is research-oriented and aims to support security engineers, architects, and students during design and review phases.

---

## Objectives
- Enable early-stage (design-time) threat modeling
- Extract architecture components, data flows, and trust boundaries
- Perform STRIDE-based threat analysis
- Discover and contextualize relevant CVEs
- Simulate realistic attack paths
- Generate structured, explainable security reports

---

## Project Scope
**In scope**
- Architecture-level threat modeling
- STRIDE-based security analysis
- CVE discovery using public vulnerability databases
- Attack path simulation
- Markdown-based security reporting

**Out of scope**
- Automated exploitation
- Runtime monitoring or detection
- Penetration testing
- Zero-day vulnerability discovery

---

## System Concept
Left<<Shift is designed as a **multi-agent pipeline**, where each agent is responsible for a clearly defined stage of analysis, such as:
- Architecture understanding
- Component interpretation
- Threat knowledge generation
- Vulnerability intelligence
- Threat relevance assessment
- Attack path simulation
- Report synthesis

Each stage consumes validated outputs from the previous stage to ensure consistency and traceability.

---

## Planned Phases
> The following phases represent the **current plan**.  
> The design and implementation details may evolve as the project progresses.

1. **Project Setup & Foundations**
   - Repository structure
   - Dependency and environment setup

2. **Core Data Models**
   - Architecture schemas
   - Threat, vulnerability, and attack path models

3. **Architecture Understanding**
   - Diagram or structured input processing
   - Component, data flow, and trust boundary extraction

4. **Threat Modeling**
   - STRIDE-based threat enumeration
   - CWE mappings

5. **Vulnerability Intelligence**
   - CVE discovery and enrichment
   - Relevance filtering based on architecture context

6. **Attack Path Simulation**
   - Multi-step attacker workflows
   - Impact and likelihood analysis

7. **Report Generation**
   - Structured, human-readable security reports
   - Mitigation and hardening recommendations

---

## Team
This project is developed collaboratively by Master's students from  
**Hamburg University of Technology (TUHH)**.

- **Utkarsh Maurya**
- **Manish Mahesh Kumar**
- **Priyanu Tushar**
- **Pratham Hegde**

---

## Hackathon Context
This project is developed as part of the **Cursor – AI Hackathon**, with a focus on practical, AI-assisted software engineering and security workflows.

---

## Project Status
🚧 **Planning and early development phase**  
The repository currently contains structural documentation and planned phases.  
Implementation will proceed incrementally with validated milestones.

---

## License
To be decided.
