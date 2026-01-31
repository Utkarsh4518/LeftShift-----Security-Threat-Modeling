#!/usr/bin/env python3
"""
Left<<Shift - AI-Powered Threat Modeling System

Main entry point for the multi-agent threat modeling pipeline.

Usage:
    python main.py --image data/architecture.png
    python main.py --input data/test_arch.json
    python main.py --input data/test_arch.json --output report.md

Requirements:
    - GEMINI_API_KEY: Required for Vision Agent (image processing)
    - OPENAI_API_KEY: Required for text-based agents (GPT-5.2)
"""

import argparse
import os
import sys
from pathlib import Path
from datetime import datetime

from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def check_api_keys() -> dict:
    """Check which API keys are configured."""
    keys = {
        "GEMINI_API_KEY": False,
        "OPENAI_API_KEY": False
    }
    
    gemini_key = os.getenv("GEMINI_API_KEY")
    if gemini_key and gemini_key != "your_gemini_api_key_here":
        keys["GEMINI_API_KEY"] = True
    
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key and openai_key != "your_openai_api_key_here":
        keys["OPENAI_API_KEY"] = True
    
    return keys


def print_banner():
    """Print the application banner."""
    banner = """
+===============================================================+
|                                                               |
|     _      _____ _____ _____                                  |
|    | |    |  ___|  ___|_   _|                                 |
|    | |    | |__ | |__   | |                                   |
|    | |    |  __||  __|  | |                                   |
|    | |___ | |___| |     | |                                   |
|    |_____||_____|_|     |_|                                   |
|                                                               |
|     << SHIFT - AI-Powered Threat Modeling                     |
|                                                               |
|     Multi-Agent Security Analysis Pipeline                    |
|                                                               |
+===============================================================+
"""
    print(banner)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Left<<Shift - AI-Powered Threat Modeling System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --image data/architecture.png
  python main.py --input data/test_arch.json
  python main.py --input data/test_arch.json --output report.md
  python main.py --input data/test_arch.json --output report.md --quiet

Environment Variables:
  GEMINI_API_KEY    Google Gemini API key (for Vision Agent)
  OPENAI_API_KEY    OpenAI API key (for text agents)
        """
    )
    
    parser.add_argument(
        "--image", "-i",
        type=str,
        help="Path to architecture diagram image (PNG, JPG)"
    )
    
    parser.add_argument(
        "--input", "-f",
        type=str,
        help="Path to JSON file with architecture data"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Path to save the Markdown report (default: auto-generated)"
    )
    
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output"
    )
    
    parser.add_argument(
        "--version", "-v",
        action="version",
        version="Left<<Shift v1.0.0 - AI Hackathon Edition"
    )
    
    args = parser.parse_args()
    
    # Print banner
    if not args.quiet:
        print_banner()
    
    # Validate input
    if not args.image and not args.input:
        parser.error("Must provide either --image or --input")
    
    if args.image and args.input:
        parser.error("Cannot provide both --image and --input")
    
    # Check file existence
    input_path = args.image or args.input
    if not Path(input_path).exists():
        print(f"Error: File not found: {input_path}")
        sys.exit(1)
    
    # Check API keys
    if not args.quiet:
        print("Checking API configuration...")
    
    api_keys = check_api_keys()
    
    if args.image and not api_keys["GEMINI_API_KEY"]:
        print("Error: GEMINI_API_KEY is required for image processing")
        print("Please set your Gemini API key in the .env file")
        sys.exit(1)
    
    if not api_keys["OPENAI_API_KEY"]:
        print("Warning: OPENAI_API_KEY not configured")
        print("Text-based agents will use fallback/heuristic modes")
        print()
    
    if not args.quiet:
        print(f"  GEMINI_API_KEY: {'Configured' if api_keys['GEMINI_API_KEY'] else 'Not configured'}")
        print(f"  OPENAI_API_KEY: {'Configured' if api_keys['OPENAI_API_KEY'] else 'Not configured'}")
        print()
    
    # Determine output path
    output_path = args.output
    if not output_path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"threat_report_{timestamp}.md"
    
    # Import and run pipeline
    try:
        from agents.core import run_threat_modeling_pipeline
        
        report, results = run_threat_modeling_pipeline(
            image_path=args.image,
            json_input=args.input,
            output_file=output_path,
            verbose=not args.quiet
        )
        
        if args.quiet:
            print(f"Report generated: {output_path}")
            print(f"  Threats: {len(results['threats'])}")
            print(f"  CVEs: {len(results['cves'])}")
            print(f"  Attack Paths: {len(results['attack_paths'])}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\nPipeline interrupted by user")
        return 130
        
    except Exception as e:
        print(f"\nError: {e}")
        if not args.quiet:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
