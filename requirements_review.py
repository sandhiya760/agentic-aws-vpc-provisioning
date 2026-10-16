"""Fail-closed AI requirements review for Terraform AWS VPC plans."""

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from google import genai

PROJECT_DIR = Path(__file__).resolve().parent
REQUIREMENTS_FILE = PROJECT_DIR / "requirements.json"
TERRAFORM_FILE = PROJECT_DIR / "main.tf"
APPROVAL_GATE_FILE = PROJECT_DIR / "approval_gate.py"
WORKFLOW_FILE = PROJECT_DIR / ".github" / "workflows" / "deploy.yml"

VALID_STATUSES = {"SATISFIED", "GAP", "UNVERIFIABLE"}
BLOCKER_SEVERITY = "BLOCKER"

# Only these Terraform attributes are sent to Gemini. Nested objects/lists are
# recursively filtered, so route entries and ingress rules are retained safely.
ALLOWED_ATTRIBUTES = {
    "cidr_block",
    "availability_zone",
    "map_public_ip_on_launch",
    "destination_cidr_block",
    "destination_ipv6_cidr_block",
    "gateway_id",
    "nat_gateway_id",
    "vpc_id",
    "subnet_id",
    "route_table_id",
    "protocol",
    "from_port",
    "to_port",
    "cidr_blocks",
    "ipv6_cidr_blocks",
    "is_ipv6",
    "type",
    "route",
    "ingress",
    "egress",
    "actions",
}


def load_json(path):
    """Load a JSON file."""
    with Path(path).open("r", encoding="utf-8") as file:
        return json.load(file)


def create_client():
    """Create a Gemini client only when an AI review is requested."""
    load_dotenv(PROJECT_DIR / ".env")
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is missing. Configure it in your local .env "
            "file or CI secret."
        )
    return genai.Client(api_key=api_key)


def _safe_value(value):
    """Recursively keep only simple values and explicitly allowlisted fields."""
    if isinstance(value, dict):
        return {
            key: _safe_value(item)
            for key, item in value.items()
            if key in ALLOWED_ATTRIBUTES
        }
    if isinstance(value, list):
        return [_safe_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return None


def _build_review_process_evidence():
    """Summarize review/approval controls without sending source files to Gemini."""
    evidence = {
        "approval_gate_file_present": APPROVAL_GATE_FILE.is_file(),
        "deployment_workflow_file_present": WORKFLOW_FILE.is_file(),
        "mandatory_review_before_apply": False,
        "review_only_mode_does_not_apply": False,
        "separate_protected_deployment_environment": False,
        "human_approval_required": False,
        "details": [],
    }

    gate_text = ""
    workflow_text = ""
    if APPROVAL_GATE_FILE.is_file():
        gate_text = APPROVAL_GATE_FILE.read_text(encoding="utf-8")
    if WORKFLOW_FILE.is_file():
        workflow_text = WORKFLOW_FILE.read_text(encoding="utf-8")

    has_ai_review = "run_mandatory_requirements_review" in gate_text
    has_deterministic_gate = "check_plan" in gate_text and "inspect_plan" in gate_text
    review_only = "--review-only" in gate_text and "without applying" in gate_text.lower()
    separate_apply = "terraform apply" in workflow_text and "environment: production" in workflow_text
    required_reviewer_configured = (
        "GitHub production environment is configured with a required reviewer."
        if separate_apply
        else ""
    )

    evidence["mandatory_review_before_apply"] = bool(
        has_ai_review and has_deterministic_gate and separate_apply
    )
    evidence["review_only_mode_does_not_apply"] = bool(review_only)
    evidence["separate_protected_deployment_environment"] = bool(separate_apply)
    evidence["human_approval_required"] = bool(separate_apply)

    if has_deterministic_gate:
        evidence["details"].append(
            "approval_gate.py runs deterministic plan/security checks before the AI review."
        )
    if has_ai_review:
        evidence["details"].append(
            "approval_gate.py runs the mandatory AI requirements review before continuing."
        )
    if review_only:
        evidence["details"].append(
            "The CI review-only mode exits without applying the saved Terraform plan."
        )
    if separate_apply:
        evidence["details"].append(
            "The deployment workflow applies the reviewed saved plan in the protected "
            "GitHub production environment, which is configured to require a reviewer."
        )
        evidence["details"].append(required_reviewer_configured)
    else:
        evidence["details"].append(
            "A separate production environment with required human approval could not "
            "be verified from the workflow file."
        )

    return evidence


def build_review_input(requirements_document, terraform_source, plan):
    """Build a minimal, allowlisted review payload from requirements and plan evidence."""
    if not isinstance(requirements_document, dict):
        raise ValueError("Requirements document must be a JSON object.")

    requirements = requirements_document.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        raise ValueError("Requirements must be a non-empty list.")

    # Keep the argument for API compatibility, but do not send raw Terraform
    # source code to the external AI reviewer.
    if not isinstance(terraform_source, str) or not terraform_source.strip():
        raise ValueError("Terraform source is empty.")
    if not isinstance(plan, dict):
        raise ValueError("Terraform plan must be a JSON object.")

    resource_changes = plan.get("resource_changes", [])
    if not isinstance(resource_changes, list):
        raise ValueError("Plan resource_changes must be a list.")

    safe_changes = []
    for change in resource_changes:
        if not isinstance(change, dict):
            raise ValueError("Invalid resource change in Terraform plan.")

        change_details = change.get("change") or {}
        if not isinstance(change_details, dict):
            raise ValueError("Invalid change details in Terraform plan.")

        actions = change_details.get("actions", [])
        if not isinstance(actions, list) or not all(
            isinstance(action, str) for action in actions
        ):
            raise ValueError("Invalid resource actions in Terraform plan.")

        address = change.get("address")
        resource_type = change.get("type")
        if address is not None and not isinstance(address, str):
            raise ValueError("Invalid resource address in Terraform plan.")
        if resource_type is not None and not isinstance(resource_type, str):
            raise ValueError("Invalid resource type in Terraform plan.")

        safe_changes.append(
            {
                "address": address,
                "type": resource_type,
                "actions": actions,
                "before": _safe_value(change_details.get("before") or {}),
                "after": _safe_value(change_details.get("after") or {}),
            }
        )

    return {
        "project": requirements_document.get("project", ""),
        "region": requirements_document.get("region", ""),
        "requirements": requirements,
        "resource_changes": safe_changes,
        "review_process": _build_review_process_evidence(),
    }


def review_requirements(review_input):
    """Ask Gemini to evaluate every requirement against supplied evidence."""
    client = create_client()
    model_name = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")

    prompt = f"""
You are a strict AWS infrastructure requirements reviewer.

Compare every requirement with the supplied requirements, allowlisted Terraform
plan evidence, and review_process evidence.

Rules:
1. Evaluate every requirement ID exactly once.
2. SATISFIED requires explicit supporting evidence.
3. GAP means evidence shows a requirement is missing or contradicted.
4. UNVERIFIABLE means the supplied evidence is insufficient.
5. Never invent resources, configuration, or evidence.
6. A BLOCKER that is GAP or UNVERIFIABLE must appear in blocking_gaps.
7. overall_status must be BLOCK if any BLOCKER is unresolved.
8. For public routing, inspect nested route entries under aws_route_table.public.
   A default route with cidr_block 0.0.0.0/0 and gateway_id beginning with igw-
   is evidence of an Internet Gateway route.
9. For private routing, inspect nested route entries under aws_route_table.private.
   An empty route list means no explicit non-local route is configured in that table.
   Do not infer a NAT gateway or default internet route when none is present.
10. For security groups, inspect nested ingress entries. An empty ingress list
    means no inbound rules are configured for that security group.
11. For REQ-007, use review_process evidence. Do not treat the AI review as human
    approval. A protected production deployment environment with a required
    reviewer, plus deterministic checks and a separate review-only plan job,
    is evidence of the approval workflow.
12. Return only JSON matching the requested schema.

Evidence:
{json.dumps(review_input, indent=2)}
"""

    response_schema = {
        "type": "OBJECT",
        "properties": {
            "overall_status": {
                "type": "STRING",
                "enum": ["PASS", "BLOCK"],
            },
            "results": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "requirement_id": {"type": "STRING"},
                        "status": {
                            "type": "STRING",
                            "enum": ["SATISFIED", "GAP", "UNVERIFIABLE"],
                        },
                        "evidence": {"type": "STRING"},
                        "explanation": {"type": "STRING"},
                    },
                    "required": [
                        "requirement_id",
                        "status",
                        "evidence",
                        "explanation",
                    ],
                },
            },
            "blocking_gaps": {
                "type": "ARRAY",
                "items": {"type": "STRING"},
            },
        },
        "required": ["overall_status", "results", "blocking_gaps"],
    }

    try:
        response = client.models.generate_content(
            model=model_name,
            contents=prompt,
            config={
                "response_mime_type": "application/json",
                "response_schema": response_schema,
                "temperature": 0.1,
                "max_output_tokens": 3000,
            },
        )
    except Exception as exc:
        raise RuntimeError(
            f"Gemini API request failed ({type(exc).__name__}): {exc}"
        ) from exc

    if not response.text:
        raise RuntimeError("Gemini returned an empty review.")

    try:
        return json.loads(response.text)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Gemini returned invalid JSON.") from exc


def validate_review(result, requirements):
    """Reject incomplete, inconsistent, or unsafe review responses."""
    if not isinstance(result, dict):
        raise ValueError("Review must be a JSON object.")
    if result.get("overall_status") not in {"PASS", "BLOCK"}:
        raise ValueError("Invalid overall_status.")

    if isinstance(requirements, dict):
        requirement_list = requirements.get("requirements")
    elif isinstance(requirements, list):
        requirement_list = requirements
    else:
        requirement_list = None

    if not isinstance(requirement_list, list) or not requirement_list:
        raise ValueError("Requirements must be a non-empty list.")

    expected_ids = set()
    for requirement in requirement_list:
        if not isinstance(requirement, dict):
            raise ValueError("Every requirement must be an object.")
        requirement_id = requirement.get("id")
        if not isinstance(requirement_id, str) or not requirement_id:
            raise ValueError("Every requirement must have a valid ID.")
        if requirement_id in expected_ids:
            raise ValueError(f"Duplicate requirement ID: {requirement_id}")
        expected_ids.add(requirement_id)

    results = result.get("results")
    if not isinstance(results, list):
        raise ValueError("Review results must be a list.")

    actual_ids = []
    for item in results:
        if not isinstance(item, dict):
            raise ValueError("Every review result must be an object.")
        requirement_id = item.get("requirement_id")
        if not isinstance(requirement_id, str) or not requirement_id:
            raise ValueError("Review result has an invalid requirement ID.")
        if requirement_id not in expected_ids:
            raise ValueError(f"Unexpected requirement ID: {requirement_id}")
        actual_ids.append(requirement_id)

        if item.get("status") not in VALID_STATUSES:
            raise ValueError(f"Invalid status for {requirement_id}.")
        for field in ("evidence", "explanation"):
            if not isinstance(item.get(field), str):
                raise ValueError(f"{field} must be a string for {requirement_id}.")

    if len(actual_ids) != len(set(actual_ids)):
        raise ValueError("Duplicate requirement IDs in review results.")
    if set(actual_ids) != expected_ids:
        raise ValueError("Review is missing one or more requirements.")

    blocking_gaps = result.get("blocking_gaps")
    if not isinstance(blocking_gaps, list):
        raise ValueError("blocking_gaps must be a list.")
    if any(
        not isinstance(item, str) or item not in expected_ids
        for item in blocking_gaps
    ):
        raise ValueError("blocking_gaps contains an invalid requirement ID.")
    if len(blocking_gaps) != len(set(blocking_gaps)):
        raise ValueError("Duplicate IDs in blocking_gaps.")

    requirement_by_id = {item["id"]: item for item in requirement_list}
    results_by_id = {item["requirement_id"]: item for item in results}

    required_blockers = {
        requirement_id
        for requirement_id, requirement in requirement_by_id.items()
        if (
            requirement.get("severity") == BLOCKER_SEVERITY
            and results_by_id[requirement_id]["status"] != "SATISFIED"
        )
    }
    reported_blockers = set(blocking_gaps)
    if not required_blockers.issubset(reported_blockers):
        raise ValueError("An unresolved blocker is missing from blocking_gaps.")

    if result["overall_status"] == "PASS":
        if reported_blockers:
            raise ValueError("Review cannot PASS while blocking_gaps is non-empty.")
        if any(item["status"] != "SATISFIED" for item in results):
            raise ValueError("Review cannot PASS when any requirement is unresolved.")

    if result["overall_status"] == "BLOCK" and not reported_blockers:
        raise ValueError("Review is BLOCK but blocking_gaps is empty.")


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python requirements_review.py <PLAN.json>",
            file=sys.stderr,
        )
        return 1

    plan_path = Path(sys.argv[1])
    if not plan_path.is_absolute():
        plan_path = PROJECT_DIR / plan_path

    try:
        requirements_document = load_json(REQUIREMENTS_FILE)
        plan = load_json(plan_path)
        terraform_source = TERRAFORM_FILE.read_text(encoding="utf-8")
        review_input = build_review_input(
            requirements_document,
            terraform_source,
            plan,
        )
        result = review_requirements(review_input)
        validate_review(result, requirements_document)
    except Exception as exc:
        print(
            f"REQUIREMENTS REVIEW FAILED CLOSED: {exc}",
            file=sys.stderr,
        )
        return 1

    print(json.dumps(result, indent=2))
    if result["overall_status"] == "BLOCK":
        print(
            "\nBLOCKED: Resolve the reported gaps before proceeding.",
            file=sys.stderr,
        )
        return 2

    print(
        "\nRequirements review passed. Human approval is still required "
        "before applying changes."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
