
from approval_gate import inspect_plan


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
    assert any(f["severity"] == "HIGH" for f in findings)
    assert len(destructive) == 0


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
    assert len(destructive) == 1
