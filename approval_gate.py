
"""Fail-closed Terraform approval gate for AWS VPC provisioning."""

import json
import subprocess
import sys
from pathlib import Path

from deterministic_requirements import check_plan
from requirements_review import (
    build_review_input,
    load_json,
    review_requirements,
    validate_review,
)


ROOT = Path(__file__).resolve().parent
REQUIREMENTS_FILE = ROOT / "requirements.json"
TERRAFORM_FILE = ROOT / "main.tf"
REVIEWER_FILE = ROOT / "requirements_review.py"
APPROVAL_GATE_FILE = ROOT / "approval_gate.py"


def run_command(command):
    """Run a command and stop if it fails."""
    print(f"\n$ {' '.join(command)}")

    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    if result.stdout:
        print(result.stdout, end="")

    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")

    if result.returncode != 0:
        raise SystemExit(
            f"BLOCKED: Command failed with exit code {result.returncode}."
        )

    return result.stdout


def inspect_plan(plan):
    """Detect security risks and destructive resource actions."""
    findings = []
    destructive = []
    changes = []

    if not isinstance(plan, dict):
        raise ValueError("Terraform plan must be a JSON object.")

    resource_changes = plan.get("resource_changes")

    if not isinstance(resource_changes, list):
        raise ValueError("Terraform plan has no valid resource_changes list.")

    for resource in resource_changes:
        if not isinstance(resource, dict):
            raise ValueError("Invalid resource change in Terraform plan.")

        address = resource.get("address", "unknown")
        resource_type = resource.get("type", "unknown")
        change = resource.get("change") or {}

        if not isinstance(change, dict):
            raise ValueError(f"Invalid change details for {address}.")

        actions = change.get("actions", [])

        if not isinstance(actions, list):
            raise ValueError(f"Invalid actions for {address}.")

        changes.append({
            "address": address,
            "type": resource_type,
            "actions": actions,
        })

        if "delete" in actions:
            destructive.append({
                "resource": address,
                "actions": actions,
            })

        if resource_type != "aws_security_group":
            continue

        after = change.get("after") or {}

        if not isinstance(after, dict):
            continue

        for rule in after.get("ingress") or []:
            if not isinstance(rule, dict):
                continue

            cidrs = rule.get("cidr_blocks") or []
            protocol = str(rule.get("protocol", "")).lower()
            from_port = rule.get("from_port")
            to_port = rule.get("to_port")

            if "0.0.0.0/0" not in cidrs:
                continue

            if protocol == "-1":
                findings.append({
                    "severity": "HIGH",
                    "resource": address,
                    "issue": (
                        "All protocols are allowed from the entire "
                        "IPv4 internet."
                    ),
                })

            elif (
                protocol in {"tcp", "6"}
                and isinstance(from_port, int)
                and isinstance(to_port, int)
                and (
                    from_port <= 22 <= to_port
                    or from_port <= 3389 <= to_port
                )
            ):
                findings.append({
                    "severity": "HIGH",
                    "resource": address,
                    "issue": (
                        "SSH or RDP may be exposed to the entire "
                        "IPv4 internet."
                    ),
                })

    return changes, findings, destructive


def load_plan_json(filename):
    """Read a Terraform plan JSON file."""
    path = Path(filename)

    if not path.is_absolute():
        path = ROOT / path

    try:
        with path.open("r", encoding="utf-8-sig") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(
            f"BLOCKED: Cannot read plan JSON: {error}"
        ) from error


def safe_test_mode(filename):
    """
    Inspect simulated plan JSON locally.

    Never runs Terraform, calls AWS, or calls Gemini.
    """
    plan = load_plan_json(filename)
    changes, findings, destructive = inspect_plan(plan)

    print("\n=== SAFE TEST MODE ===")
    print(f"Resources: {len(changes)}")
    print(
        "High-severity findings: "
        f"{sum(item['severity'] == 'HIGH' for item in findings)}"
    )
    print(f"Deletion actions: {len(destructive)}")

    if findings or destructive:
        print("PASS: Unsafe plan BLOCKED. No AWS calls made.")
        raise SystemExit(2)

    print("PASS: No matching blocking conditions found.")
    print("This is not an approval to apply the plan.")


def run_mandatory_requirements_review(plan):
    """
    Run the mandatory AI requirements review.

    Invalid responses, unresolved gaps, and AI errors must block apply.
    """
    requirements_document = load_json(REQUIREMENTS_FILE)
    terraform_source = TERRAFORM_FILE.read_text(encoding="utf-8")

    review_input = build_review_input(
        requirements_document,
        terraform_source,
        plan,
    )

    # Evidence used to assess the review and approval implementation.
    review_input["approval_gate_source"] = (
        APPROVAL_GATE_FILE.read_text(encoding="utf-8")
    )
    review_input["requirements_reviewer_source"] = (
        REVIEWER_FILE.read_text(encoding="utf-8")
    )

    print("\n=== Mandatory AI Requirements Review ===")
    print("Comparing requirements against Terraform and plan evidence.")

    result = review_requirements(review_input)
    validate_review(result, requirements_document)

    print(json.dumps(result, indent=2))

    if result["overall_status"] != "PASS":
        raise SystemExit(
            "BLOCKED: AI requirements review reported unresolved gaps."
        )

    print("AI requirements review passed.")


def main():
    """Generate a plan, run all gates, and request approval before apply."""
    if len(sys.argv) == 3 and sys.argv[1] == "--test-plan-json":
        safe_test_mode(sys.argv[2])
        return

    if len(sys.argv) != 1:
        raise SystemExit(
            "Usage: python approval_gate.py "
            "[--test-plan-json PLAN.json]"
        )

    # Phase 1: Generate a saved plan.
    run_command(["terraform", "plan", "-out=tfplan"])

    plan_json = run_command(
        ["terraform", "show", "-json", "tfplan"]
    )

    try:
        plan = json.loads(plan_json)
    except json.JSONDecodeError as error:
        raise SystemExit(
            f"BLOCKED: Terraform returned invalid JSON: {error}"
        ) from error

    # Phase 2: Inspect security risks and destructive actions.
    changes, security_findings, destructive = inspect_plan(plan)

    print("\n=== Deterministic Security Gate ===")
    print(f"Resources in plan: {len(changes)}")
    print(f"Security findings: {len(security_findings)}")
    print(f"Deletion/replacement actions: {len(destructive)}")

    # Phase 3: Verify mandatory infrastructure requirements.
    # If a check raises an exception, fail closed.
    try:
        requirements_findings = check_plan(plan)
    except Exception as error:
        raise SystemExit(
            "BLOCKED: Deterministic requirements checks failed "
            f"({type(error).__name__}). No apply was performed."
        ) from error

    if not isinstance(requirements_findings, list):
        raise SystemExit(
            "BLOCKED: Requirements checker returned an invalid result."
        )

    print("\n=== Deterministic Requirements Gate ===")

    for finding in requirements_findings:
        print(f"[BLOCKED] {finding}")

    if not requirements_findings:
        print("All deterministic requirements checks passed.")

    # Block before AI review or human approval.
    if security_findings or destructive or requirements_findings:
        print(
            "\nBLOCKED: Security, requirements, or destructive-change "
            "checks failed. No AI review or apply will proceed."
        )

        for finding in security_findings:
            print(
                f"[{finding['severity']}] {finding['resource']}: "
                f"{finding['issue']}"
            )

        for action in destructive:
            print(
                f"[DESTRUCTIVE] {action['resource']}: "
                f"{action['actions']}"
            )

        raise SystemExit(2)

    # Phase 4: Mandatory AI review.
    try:
        run_mandatory_requirements_review(plan)
    except SystemExit:
        raise
    except Exception as error:
        raise SystemExit(
            "BLOCKED: Mandatory requirements review failed "
            f"({type(error).__name__}). No apply was performed."
        ) from error

    # Phase 5: A no-op plan needs no apply.
    if all(item["actions"] == ["no-op"] for item in changes):
        print(
            "No infrastructure changes are proposed. "
            "Nothing to apply."
        )
        return

    # Phase 6: Explicit human approval.
    approval = input(
        "\nType APPLY to approve this saved plan: "
    ).strip()

    if approval != "APPLY":
        print("Approval not granted. No infrastructure changes applied.")
        return

    # Phase 7: Apply the exact saved plan that passed the gates.
    run_command(["terraform", "apply", "tfplan"])


if __name__ == "__main__":
    main()
