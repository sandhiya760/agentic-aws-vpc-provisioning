
import json
import sys

import pytest

import approval_gate
from approval_gate import (
    inspect_plan,
    run_mandatory_requirements_review,
)
from test_deterministic_requirements import valid_plan


def configure_review_test(monkeypatch, review_result):
    """Configure the requirements review without calling Gemini or AWS."""

    requirements_document = {
        "project": "Test project",
        "requirements": [
            {
                "id": "REQ-001",
                "description": "Create the required VPC.",
                "severity": "BLOCKER",
            }
        ],
    }

    class FakeFile:
        def __init__(self, content):
            self.content = content

        def read_text(self, encoding=None):
            return self.content

    monkeypatch.setattr(
        approval_gate,
        "load_json",
        lambda path: requirements_document,
    )
    monkeypatch.setattr(
        approval_gate,
        "TERRAFORM_FILE",
        FakeFile('resource "aws_vpc" "test" {}'),
    )
    monkeypatch.setattr(
        approval_gate,
        "APPROVAL_GATE_FILE",
        FakeFile("# simulated approval gate"),
    )
    monkeypatch.setattr(
        approval_gate,
        "REVIEWER_FILE",
        FakeFile("# simulated requirements reviewer"),
    )
    monkeypatch.setattr(
        approval_gate,
        "build_review_input",
        lambda requirements, source, plan: {
            "requirements": requirements["requirements"],
            "terraform_source": source,
            "resource_changes": [],
        },
    )
    monkeypatch.setattr(
        approval_gate,
        "review_requirements",
        lambda review_input: review_result,
    )


def test_public_ssh_access_is_detected():
    """Public SSH access must be reported as high severity."""

    plan = {
        "resource_changes": [
            {
                "address": "aws_security_group.example",
                "type": "aws_security_group",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "ingress": [
                            {
                                "protocol": "tcp",
                                "from_port": 22,
                                "to_port": 22,
                                "cidr_blocks": ["0.0.0.0/0"],
                            }
                        ]
                    },
                },
            }
        ]
    }

    _, findings, _ = inspect_plan(plan)

    assert findings
    assert findings[0]["severity"] == "HIGH"
    assert "SSH or RDP" in findings[0]["issue"]


def test_resource_deletion_is_detected():
    """Deleting a resource must be identified as destructive."""

    plan = {
        "resource_changes": [
            {
                "address": "aws_vpc.example",
                "type": "aws_vpc",
                "change": {
                    "actions": ["delete"],
                    "before": {"cidr_block": "10.0.0.0/16"},
                    "after": None,
                },
            }
        ]
    }

    _, _, destructive = inspect_plan(plan)

    assert len(destructive) == 1
    assert destructive[0]["resource"] == "aws_vpc.example"


def test_requirements_review_blocks_when_ai_reports_gap(monkeypatch):
    """An unresolved blocker must prevent the review from passing."""

    result = {
        "overall_status": "BLOCK",
        "results": [
            {
                "requirement_id": "REQ-001",
                "status": "GAP",
                "evidence": "The required VPC was not verified.",
                "explanation": "Required evidence is missing.",
            }
        ],
        "blocking_gaps": ["REQ-001"],
    }

    configure_review_test(monkeypatch, result)

    with pytest.raises(SystemExit, match="unresolved gaps"):
        run_mandatory_requirements_review(valid_plan())


def test_requirements_review_blocks_invalid_ai_response(monkeypatch):
    """An incomplete AI response must be rejected."""

    result = {
        "overall_status": "PASS",
        "results": [],
        "blocking_gaps": [],
    }

    configure_review_test(monkeypatch, result)

    with pytest.raises(ValueError, match="missing one or more requirements"):
        run_mandatory_requirements_review(valid_plan())


def test_failed_requirements_review_never_applies(monkeypatch):
    """A failed requirements review must prevent Terraform apply."""

    commands = []

    def fake_run_command(command):
        commands.append(command)

        if command == ["terraform", "show", "-json", "tfplan"]:
            return json.dumps(valid_plan())

        return ""

    monkeypatch.setattr(
        approval_gate,
        "run_command",
        fake_run_command,
    )

    def fake_requirements_review(plan):
        raise SystemExit("BLOCKED: Simulated requirements gap.")

    monkeypatch.setattr(
        approval_gate,
        "run_mandatory_requirements_review",
        fake_requirements_review,
    )
    monkeypatch.setattr(sys, "argv", ["approval_gate.py"])

    with pytest.raises(SystemExit, match="Simulated requirements gap"):
        approval_gate.main()

    assert ["terraform", "plan", "-out=tfplan"] in commands
    assert ["terraform", "show", "-json", "tfplan"] in commands
    assert ["terraform", "apply", "tfplan"] not in commands


def test_gemini_failure_never_applies(monkeypatch):
    """An AI service failure must prevent Terraform apply."""

    commands = []

    def fake_run_command(command):
        commands.append(command)

        if command == ["terraform", "show", "-json", "tfplan"]:
            return json.dumps(valid_plan())

        return ""

    monkeypatch.setattr(
        approval_gate,
        "run_command",
        fake_run_command,
    )

    def fake_requirements_review(plan):
        raise RuntimeError("Simulated Gemini failure.")

    monkeypatch.setattr(
        approval_gate,
        "run_mandatory_requirements_review",
        fake_requirements_review,
    )
    monkeypatch.setattr(sys, "argv", ["approval_gate.py"])

    with pytest.raises(
        SystemExit,
        match="Mandatory requirements review failed",
    ):
        approval_gate.main()

    assert ["terraform", "apply", "tfplan"] not in commands
