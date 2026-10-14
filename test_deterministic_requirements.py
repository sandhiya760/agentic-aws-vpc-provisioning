
import pytest

from deterministic_requirements import check_plan


def resource(address, resource_type, after, actions=None):
    return {
        "address": address,
        "type": resource_type,
        "change": {
            "actions": actions or ["create"],
            "after": after,
        },
    }


def valid_plan():
    return {
        "resource_changes": [
            resource("aws_vpc.main", "aws_vpc", {
                "cidr_block": "10.0.0.0/16",
            }),
            *[
                resource(f"aws_subnet.public[{i}]", "aws_subnet", {
                    "availability_zone": zone,
                    "map_public_ip_on_launch": True,
                })
                for i, zone in enumerate(["ap-south-1a", "ap-south-1b"])
            ],
            *[
                resource(f"aws_subnet.private[{i}]", "aws_subnet", {
                    "availability_zone": zone,
                    "map_public_ip_on_launch": False,
                })
                for i, zone in enumerate(["ap-south-1a", "ap-south-1b"])
            ],
            resource("aws_internet_gateway.main", "aws_internet_gateway", {
                "vpc_id": "vpc-example",
            }),
            resource("aws_route_table.public", "aws_route_table", {
                "route": [{
                    "cidr_block": "0.0.0.0/0",
                    "gateway_id": "igw-example",
                    "nat_gateway_id": None,
                }],
            }),
            *[
                resource(f"aws_route_table.private[{i}]", "aws_route_table", {
                    "route": [],
                })
                for i in range(2)
            ],
            *[
                resource(f"aws_route_table_association.public[{i}]",
                         "aws_route_table_association", {})
                for i in range(2)
            ],
            *[
                resource(f"aws_route_table_association.private[{i}]",
                         "aws_route_table_association", {})
                for i in range(2)
            ],
            resource("aws_security_group.app", "aws_security_group", {
                "ingress": [],
            }),
        ]
    }


def test_valid_plan_passes():
    assert check_plan(valid_plan()) == []


def test_wrong_vpc_cidr_is_detected():
    plan = valid_plan()
    plan["resource_changes"][0]["change"]["after"]["cidr_block"] = "10.1.0.0/16"

    assert any("VPC CIDR" in finding for finding in check_plan(plan))


def test_missing_public_subnet_is_detected():
    plan = valid_plan()
    plan["resource_changes"] = [
        item for item in plan["resource_changes"]
        if item["address"] != "aws_subnet.public[1]"
    ]

    assert any("public subnets" in finding for finding in check_plan(plan))


def test_private_default_route_is_detected():
    plan = valid_plan()
    for item in plan["resource_changes"]:
        if item["address"] == "aws_route_table.private[0]":
            item["change"]["after"]["route"] = [
                {"cidr_block": "0.0.0.0/0", "gateway_id": "igw-example"}
            ]

    assert any("Private route table" in finding for finding in check_plan(plan))


def test_nat_gateway_is_detected():
    plan = valid_plan()
    plan["resource_changes"].append(
        resource("aws_nat_gateway.example", "aws_nat_gateway", {})
    )

    assert any("NAT Gateways" in finding for finding in check_plan(plan))


def test_public_ssh_is_detected():
    plan = valid_plan()
    for item in plan["resource_changes"]:
        if item["type"] == "aws_security_group":
            item["change"]["after"]["ingress"] = [{
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "cidr_blocks": ["0.0.0.0/0"],
            }]

    assert any("SSH/RDP" in finding for finding in check_plan(plan))


def test_deletion_is_detected():
    plan = valid_plan()
    plan["resource_changes"][0]["change"]["actions"] = ["delete"]

    assert any("Destructive change" in finding for finding in check_plan(plan))


@pytest.mark.parametrize("bad_plan", [None, [], {}, {"resource_changes": "invalid"}])
def test_invalid_plan_is_rejected(bad_plan):
    assert check_plan(bad_plan)
