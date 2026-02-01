# Left<<Shift Frontend

Architecture visualization layer for the Sentinel threat modeling system.

## Features

- **Interactive Architecture Diagram**: Visualize system components with React Flow
- **Threat Overlay**: Components colored by threat severity (Critical/High/Medium/Low)
- **ELK Layout**: Deterministic left-to-right layered layout
- **Threat Panel**: Click any component to view associated threats
- **Report Preview**: View and download the markdown threat report
- **Example Architectures**: Try pre-built examples without uploading

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

## Project Structure

```
src/
├── api/                    # Backend API service
│   └── analysisService.ts  # Backend-agnostic API client
├── compiler/               # Diagram compilation
│   ├── DiagramCompiler.ts  # JSON → RenderGraph
│   ├── roleMapper.ts       # Component type → lane mapping
│   └── types.ts            # TypeScript definitions
├── layout/
│   └── elkLayout.ts        # ELK layout engine integration
├── components/
│   ├── Canvas/             # React Flow visualization
│   ├── ThreatPanel/        # Threat details sidebar
│   ├── ReportPreview/      # Markdown report modal
│   └── Upload/             # File upload and example selector
├── hooks/
│   └── useAnalysis.ts      # Analysis state management
├── data/
│   └── examples.ts         # Built-in example architectures
├── App.tsx                 # Main application
└── main.tsx                # Entry point
```

## Configuration

Create a `.env` file:

```
VITE_API_BASE_URL=http://localhost:8000
```

## Lane Mapping

Components are assigned to lanes based on their type:

| Lane | Role | Examples |
|------|------|----------|
| 0 | External | Clients, browsers, mobile apps |
| 1 | Ingress | Gateways, load balancers, CDN |
| 2 | Compute | Services, APIs, microservices |
| 3 | Data | Databases, caches, storage |
| 4 | Infra | DNS, queues, monitoring |

## Backend Integration

The frontend expects a `POST /analyze` endpoint that accepts:
- `image`: Architecture diagram (PNG/JPEG)
- `json`: Architecture JSON specification
- `example_id`: Built-in example identifier

Response format:
```json
{
  "status": "complete",
  "result": {
    "architecture": { ... },
    "threats": [ ... ],
    "report_markdown": "..."
  }
}
```

For async processing (n8n integration):
```json
{
  "status": "processing",
  "job_id": "abc123"
}
```

## Tech Stack

- **React 19** + TypeScript
- **Vite** - Build tool
- **React Flow** (@xyflow/react) - Graph visualization
- **ELK.js** - Layout algorithm
- **Tailwind CSS** - Styling
- **react-markdown** - Report rendering
