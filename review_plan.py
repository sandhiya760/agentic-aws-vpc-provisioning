
import json
import sys
from pathlib import Path


def review_plan(filename):
    plan_file = Path(filename)

    if not plan_file.exists():
        print(f"ERROR: File not found: {plan_file}")
        return

    try:
        with plan_file.open("r", encoding="utf-8-sig") as file:
            plan = json.load(file)
    except (json.JSONDecodeError, OSError) as error:
        print(f"ERROR: Could not read plan JSON: {error}")
        return

    counts = {
        "create": 0,
        "update": 0,
        "delete": 0,
        "replace": 0,
        "no-op": 0,
    }
    findings = []

    print(f"\n=== Terraform Plan Reviewer: {filename} ===")

    for resource in plan.get("resource_changes", []):
        address = resource.get("address", "unknown")
        resource_type = resource.get("type", "")
        change = resource.get("change", {})
        actions = change.get("actions", [])

        if actions == ["create"]:
            counts["create"] += 1
        elif actions == ["update"]:
            counts["update"] += 1
        elif actions == ["delete"]:
            counts["delete"] += 1
        elif actions in (["delete", "create"], ["create", "delete"]):
            counts["replace"] += 1
        elif actions == ["no-op"]:
            counts["no-op"] += 1

        print(f"\nResource: {address}")
        print(f"Planned action: {', '.join(actions) or 'unknown'}")

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
                    f"HIGH: {address} permits all protocols "
                    "from the entire IPv4 internet."
                )
            elif from_port in (22, 3389) or to_port in (22, 3389):
                findings.append(
                    f"HIGH: {address} exposes a potentially "
                    "administrative port to the entire IPv4 internet."
                )
            else:
                findings.append(
                    f"WARNING: {address} permits inbound traffic "
                    "from the entire IPv4 internet. Review the ports."
                )

    print("\n=== Change Summary ===")
    for action, total in counts.items():
        print(f"{action.capitalize()}: {total}")

    print("\n=== Security Findings ===")
    if findings:
        for finding in findings:
            print(f"- {finding}")
    else:
        print("No matching risky inbound rules detected.")

    print(
        "\nNote: These checks cover selected IPv4 ingress patterns only. "
        "They are not a complete security audit."
    )


if __name__ == "__main__":
    filename = sys.argv[1] if len(sys.argv) > 1 else "plan.json"
    review_plan(filename)
