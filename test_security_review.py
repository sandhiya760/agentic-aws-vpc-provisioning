
from approval_gate import inspect_plan


def test_public_ssh_exposure_is_detected():
    """Verify that public SSH access is flagged as HIGH severity."""
    simulated_plan = {
        "resource_changes": [
            {
                "address": "aws_security_group.test",
                "type": "aws_security_group",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "ingress": [
                            {
                                "from_port": 22,
                                "to_port": 22,
                                "protocol": "tcp",
                                "cidr_blocks": ["0.0.0.0/0"],
                            }
                        ]
                    },
                },
            }
        ]
    }

    _, findings, _ = inspect_plan(simulated_plan)

    assert any(f["severity"] == "HIGH" for f in findings)


def test_private_ssh_cidr_does_not_trigger_high_severity():
    """Verify that a restricted SSH CIDR avoids the public-SSH HIGH finding."""
    simulated_plan = {
        "resource_changes": [
            {
                "address": "aws_security_group.test",
                "type": "aws_security_group",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "ingress": [
                            {
                                "from_port": 22,
                                "to_port": 22,
                                "protocol": "tcp",
                                "cidr_blocks": ["10.0.0.0/24"],
                            }
                        ]
                    },
                },
            }
        ]
    }

    _, findings, _ = inspect_plan(simulated_plan)

    assert not any(f["severity"] == "HIGH" for f in findings)
