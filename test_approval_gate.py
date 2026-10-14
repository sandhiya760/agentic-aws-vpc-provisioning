import pytest

import approval_gate
from approval_gate import (
    inspect_plan,
    run_mandatory_requirements_review,
)


def test_public_ssh_access_is_detected():
    """Public SSH access should produce a HIGH-severity finding."""
    unsafe_plan = {
        "resource_changes": [
            {
                "address": "aws_security_group.test",
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

    changes, findings, destructive = inspect_plan(unsafe_plan)

    assert len(changes) == 1
    assert any(item["severity"] == "HIGH" for item in findings)
    assert destructive == []


def test_resource_deletion_is_detected():
    """A deletion action should be detected by the approval gate."""
    deletion_plan = {
        "resource_changes": [
            {
                "address": "aws_vpc.test",
                "type": "aws_vpc",
                "change": {
                    "actions": ["delete"],
                    "before": {"id": "vpc-simulated"},
                    "after": None,
                },
            }
        ]
    }

    changes, findings, destructive = inspect_plan(deletion_plan)

    assert len(changes) == 1
    assert findings == []
    assert len(destructive) == 1


def configure_review_test(monkeypatch, review_result):
    """Configure a review test without files, Gemini, or AWS access."""

    requirements_document = {
        "project": "Test project",
        "region": "ap-south-1",
        "requirements": [
            {
                "id": "REQ-001",
                "description": "Create a VPC.",
                "expected_evidence": "An AWS VPC resource.",
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


def test_requirements_review_blocks_when_ai_reports_gap(monkeypatch):
    """An unresolved blocker must prevent the requirements review passing."""
    blocked_review = {
        "overall_status": "BLOCK",
        "results": [
            {
                "requirement_id": "REQ-001",
                "status": "GAP",
                "evidence": "Simulated missing VPC evidence.",
                "explanation": "Simulated test failure.",
            }
        ],
        "blocking_gaps": ["REQ-001"],
    }

    configure_review_test(monkeypatch, blocked_review)

    with pytest.raises(SystemExit, match="unresolved gaps"):
        run_mandatory_requirements_review({"resource_changes": []})


def test_requirements_review_blocks_invalid_ai_response(monkeypatch):
    """An incomplete AI response must fail closed."""
    invalid_review = {
        "overall_status": "PASS",
        "results": [],
        "blocking_gaps": [],
    }

    configure_review_test(monkeypatch, invalid_review)

    with pytest.raises(
        ValueError,
        match="Review is missing one or more requirements",
    ):
        run_mandatory_requirements_review({"resource_changes": []})
def test_failed_requirements_review_never_applies(monkeypatch):
    """A failed requirements review must stop the deployment flow."""
    import json
    import sys

    commands = []

    def fake_run_command(command):
        commands.append(command)

        if command == ["terraform", "show", "-json", "tfplan"]:
            return json.dumps(
                {
                    "resource_changes": [
                        {
                            "address": "aws_vpc.test",
                            "type": "aws_vpc",
                            "change": {
                                "actions": ["create"],
                                "after": {"cidr_block": "10.0.0.0/16"},
                            },
                        }
                    ]
                }
            )

        return ""

    monkeypatch.setattr(approval_gate, "run_command", fake_run_command)

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
    """An AI service failure must stop the deployment flow."""
    import json
    import sys

    commands = []

    def fake_run_command(command):
        commands.append(command)

        if command == ["terraform", "show", "-json", "tfplan"]:
            return json.dumps({"resource_changes": []})

        return ""

    monkeypatch.setattr(approval_gate, "run_command", fake_run_command)

    def fake_requirements_review(plan):
        raise RuntimeError("Simulated Gemini failure.")

    monkeypatch.setattr(
        approval_gate,
        "run_mandatory_requirements_review",
        fake_requirements_review,
    )
    monkeypatch.setattr(sys, "argv", ["approval_gate.py"])

    with pytest.raises(SystemExit, match="Mandatory requirements review failed"):
        approval_gate.main()

    assert ["terraform", "apply", "tfplan"] not in commands
