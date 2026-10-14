
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from google import genai

# Load the API key from this project's .env file
PROJECT_DIR = Path(__file__).resolve().parent
load_dotenv(PROJECT_DIR / ".env")

API_KEY = os.getenv("GEMINI_API_KEY")
MODEL = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")

if not API_KEY:
    raise SystemExit("ERROR: GEMINI_API_KEY is missing from .env")

client = genai.Client(api_key=API_KEY)


def main():
    filename = sys.argv[1] if len(sys.argv) > 1 else "plan.json"
    plan_path = PROJECT_DIR / filename

    if not plan_path.is_file():
        raise SystemExit(f"ERROR: Plan file not found: {plan_path}")

    try:
        with plan_path.open("r", encoding="utf-8-sig") as file:
            plan = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"ERROR: Could not read plan JSON: {error}")

    # Send only the useful summary, not the entire Terraform state.
    changes = []
    for resource in plan.get("resource_changes", []):
        change = resource.get("change", {})
        changes.append({
            "address": resource.get("address", "unknown"),
            "type": resource.get("type", "unknown"),
            "actions": change.get("actions", []),
            "before": change.get("before"),
            "after": change.get("after"),
        })

    summary = {
        "resource_change_count": len(changes),
        "resource_changes": changes,
    }

    prompt = f"""
You are a cautious AWS and Terraform infrastructure reviewer.

Analyse this Terraform plan for:
1. Proposed infrastructure changes.
2. AWS networking and security risks.
3. Public exposure, risky security-group rules, and destructive changes.
4. Specific, actionable recommendations.

Use only the supplied plan evidence. Do not claim to have checked
settings that are absent from the plan. If information is insufficient,
say so. Distinguish confirmed findings from potential risks.
Do not execute Terraform or claim that the plan has been applied.

Terraform plan summary:
{json.dumps(summary, separators=(",", ":"))}
"""

    print(f"Reviewing {filename} with {MODEL}...")
    try:
        response = client.models.generate_content(
            model=MODEL,
            contents=prompt,
            config={
                "temperature": 0.2,
                "max_output_tokens": 900,
            },
        )
        print("\n=== Gemini Terraform Review ===\n")
        print(response.text or "Gemini returned no text.")
    except Exception as error:
        print("\nGemini request failed.")
        print(f"{type(error).__name__}: {error}")
        print("No AWS resources were changed.")


if __name__ == "__main__":
    main()
