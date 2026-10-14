import json
import subprocess
import sys
from pathlib import Path

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
    """
    Inspect selected Terraform plan risks.

    Returns:
        changes: resource change summaries
        findings: security findings
        destructive: deletion or replacement actions
    """
    changes = []
    findings = []
    destructive = []

    for resource in plan.get("resource_changes", []):
        address = resource.get("address", "unknown")
        resource_type = resource.get("type", "unknown")
        change = resource.get("change", {})
        actions = change.get("actions", [])

        changes.append(
            {
                "address": address,
                "type": resource_type,
                "actions": actions,
            }
        )

        if "delete" in actions:
            destructive.append(
                {
                    "resource": address,
                    "actions": actions,
                }
            )

        if resource_type != "aws_security_group":
            continue

        after = change.get("after") or {}

        for rule in after.get("ingress") or []:
            cidrs = rule.get("cidr_blocks") or []
            protocol = rule.get("protocol")
            from_port = rule.get("from_port")
            to_port = rule.get("to_port")

            if "0.0.0.0/0" not in cidrs:
                continue

            if protocol == "-1":
                findings.append(
                    {
                        "severity": "HIGH",
                        "resource": address,
                        "issue": (
                            "All protocols are allowed from the entire "
                            "IPv4 internet."
                        ),
                    }
                )

            elif (
                protocol in ("tcp", "6")
                and from_port is not None
                and to_port is not None
                and (
                    from_port <= 22 <= to_port
                    or from_port <= 3389 <= to_port
                )
            ):
                findings.append(
                    {
                        "severity": "HIGH",
                        "resource": address,
                        "issue": (
                            "SSH or RDP may be exposed to the entire "
                            "IPv4 internet."
                        ),
                    }
                )

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
    Review requirements against Terraform and gate implementation.

    Any AI error, malformed response, or unresolved requirement blocks
    the deployment. This function never runs Terraform apply.
    """
    requirements_document = load_json(REQUIREMENTS_FILE)
    terraform_source = TERRAFORM_FILE.read_text(encoding="utf-8")

    review_input = build_review_input(
        requirements_document,
        terraform_source,
        plan,
    )

    # Supply process evidence so REQ-007 can be assessed against the
    # actual approval and requirements-review implementation.
    review_input["approval_gate_source"] = (
        APPROVAL_GATE_FILE.read_text(encoding="utf-8")
    )
    review_input["requirements_reviewer_source"] = (
        REVIEWER_FILE.read_text(encoding="utf-8")
    )

    print("\n=== Mandatory AI Requirements Review ===")
    print("Comparing requirements with Terraform and review-gate evidence.")

    result = review_requirements(review_input)

    # Validate the response independently; do not trust AI status alone.
    validate_review(result, requirements_document)

    print(json.dumps(result, indent=2))

    if result["overall_status"] != "PASS":
        raise SystemExit(
            "BLOCKED: AI requirements review reported unresolved gaps."
        )

    print("Requirements review passed.")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--test-plan-json":
        safe_test_mode(sys.argv[2])
        return

    if len(sys.argv) != 1:
        raise SystemExit(
            "Usage: python approval_gate.py "
            "[--test-plan-json PLAN.json]"
        )

    # Phase 1: Generate and inspect a saved Terraform plan.
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

    changes, findings, destructive = inspect_plan(plan)

    print("\n=== Deterministic Security Gate ===")
    print(f"Resources in plan: {len(changes)}")
    print(
        "High-severity findings: "
        f"{sum(item['severity'] == 'HIGH' for item in findings)}"
    )
    print(f"Deletion/replacement actions: {len(destructive)}")

    # Phase 2: Block known risks before making an AI request.
    if findings or destructive:
        print(
            "BLOCKED: Security findings or destructive actions "
            "require investigation."
        )

        for finding in findings:
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

    # Phase 3: Mandatory AI review. Fail closed on any exception.
    try:
        run_mandatory_requirements_review(plan)
    except SystemExit:
        raise
    except Exception as error:
        raise SystemExit(
            "BLOCKED: Mandatory requirements review failed "
            f"({type(error).__name__}). No apply was performed."
        ) from error

    # Phase 4: No changes means no apply is needed.
    if all(
        item["actions"] == ["no-op"]
        for item in changes
    ):
        print(
            "No infrastructure changes are proposed. "
            "Nothing to apply."
        )
        return

    # Phase 5: Require explicit human approval.
    approval = input(
        "\nType APPLY to approve this saved plan: "
    ).strip()

    if approval != "APPLY":
        print("Approval not granted. No infrastructure changes applied.")
        return

    # Apply the exact saved plan that was reviewed.
    run_command(["terraform", "apply", "tfplan"])


if __name__ == "__main__":
    main()
