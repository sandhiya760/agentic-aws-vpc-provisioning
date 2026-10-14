
import json
import os
import subprocess
import sys
from pathlib import Path

from dotenv import load_dotenv
from google import genai

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

MODEL = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise SystemExit("BLOCKED: GEMINI_API_KEY is missing from .env")

client = genai.Client(api_key=API_KEY)


def run_command(args):
    """Run a command and stop if it fails."""
    result = subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    if result.stdout:
        print(result.stdout)
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr)
        raise SystemExit(f"BLOCKED: Command failed: {args[0]}")
    return result.stdout


def inspect_plan(plan):
    findings = []
    destructive = []
    changes = plan.get("resource_changes", [])

    for resource in changes:
        address = resource.get("address", "unknown")
        change = resource.get("change", {})
        actions = change.get("actions", [])

        if "delete" in actions:
            destructive.append({
                "resource": address,
                "actions": actions,
            })

        if resource.get("type") != "aws_security_group":
            continue

        after = change.get("after") or {}
        for rule in after.get("ingress") or []:
            cidrs = rule.get("cidr_blocks") or []
            if "0.0.0.0/0" not in cidrs:
                continue

            protocol = rule.get("protocol")
            start = rule.get("from_port")
            end = rule.get("to_port")

            admin_port = (
                protocol in ("tcp", "6")
                and start is not None
                and end is not None
                and (
                    start <= 22 <= end
                    or start <= 3389 <= end
                )
            )

            if protocol == "-1" or admin_port:
                findings.append({
                    "severity": "HIGH",
                    "resource": address,
                    "issue": (
                        "All protocols exposed to the internet"
                        if protocol == "-1"
                        else "SSH/RDP potentially exposed to the internet"
                    ),
                })

    return changes, findings, destructive


def main():


    # SAFE TEST MODE: evaluates JSON only; never calls AWS or applies changes.
    if len(sys.argv) == 3 and sys.argv[1] == "--test-plan-json":
        test_path = Path(sys.argv[2])
        if not test_path.is_absolute():
            test_path = ROOT / test_path

        try:
            with test_path.open("r", encoding="utf-8-sig") as file:
                test_plan = json.load(file)
        except (OSError, json.JSONDecodeError) as error:
            raise SystemExit(f"TEST BLOCKED: Cannot read plan: {error}")

        changes, findings, destructive = inspect_plan(test_plan)

        print("\n=== SAFE TEST MODE ===")
        print(f"Resources: {len(changes)}")
        print(f"High-severity findings: {len(findings)}")
        print(f"Deletion actions: {len(destructive)}")

        if findings or destructive:
            print("PASS: Unsafe plan BLOCKED. No AWS calls made.")
            raise SystemExit(2)

        print("PASS: No matching blocking conditions found.")
        print("This is not an approval to apply the plan.")
        return
    elif len(sys.argv) != 1:
        raise SystemExit(
            "Usage: python approval_gate.py "
            "[--test-plan-json PLAN.json]"
        )

    # Generate a fresh plan; never trust a previously saved plan.
    print("Generating a fresh Terraform plan...")
    run_command(["terraform", "plan", "-out=tfplan"])

    print("Reading the saved plan as JSON...")
    raw_json = run_command(["terraform", "show", "-json", "tfplan"])
    plan = json.loads(raw_json)

    changes, findings, destructive = inspect_plan(plan)
    actions = [
        item.get("change", {}).get("actions", [])
        for item in changes
    ]

    print("\n=== Deterministic Safety Checks ===")
    print(f"Resources in plan: {len(changes)}")
    print(f"High-severity findings: {len(findings)}")
    print(f"Resources with deletion actions: {len(destructive)}")

    for finding in findings:
        print(
            f"[{finding['severity']}] {finding['resource']}: "
            f"{finding['issue']}"
        )

    if destructive:
        print("\nBLOCKED: Deletions or replacements require a separate review.")
        for item in destructive:
            print(item)
        raise SystemExit(1)

    if findings:
        print("\nBLOCKED: Resolve HIGH-severity findings before approval.")
        raise SystemExit(1)

    if all(action == ["no-op"] for action in actions):
        print("\nNo infrastructure changes are proposed. Nothing to apply.")
        return

    print("\n=== Gemini Review ===")
    review_input = {
        "resource_changes": [
            {
                "address": item.get("address"),
                "type": item.get("type"),
                "actions": item.get("change", {}).get("actions", []),
            }
            for item in changes
        ],
        "security_findings": findings,
    }

    try:
        response = client.models.generate_content(
            model=MODEL,
            contents=(
                "Review this Terraform plan cautiously. Explain proposed "
                "changes, remaining risks, and limitations. Do not claim "
                "that the plan is safe merely because automated checks "
                "found no issues. Recommend human review.\n\n"
                + json.dumps(review_input)
            ),
            config={"temperature": 0.2, "max_output_tokens": 800},
        )
        if not response.text:
            raise RuntimeError("Gemini returned an empty response")
        print(response.text)
    except Exception as error:
        raise SystemExit(
            f"BLOCKED: Gemini review failed ({type(error).__name__}). "
            "No changes were applied."
        )

    print("\nReview the plan above before proceeding.")
    confirmation = input('Type APPLY to approve this exact saved plan: ')

    if confirmation != "APPLY":
        print("Approval not provided. No changes were applied.")
        return

    print("\nApplying the reviewed saved plan...")
    run_command(["terraform", "apply", "tfplan"])
    print("Terraform apply completed.")


if __name__ == "__main__":
    main()
