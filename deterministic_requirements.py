
"""Deterministic checks for the proposed AWS VPC Terraform plan."""

from collections import defaultdict
from ipaddress import ip_network


EXPECTED_VPC_CIDR = "10.0.0.0/16"

EXPECTED_PUBLIC_CIDRS = {
    "10.0.1.0/24",
    "10.0.2.0/24",
}

EXPECTED_PRIVATE_CIDRS = {
    "10.0.11.0/24",
    "10.0.12.0/24",
}


def check_plan(plan):
    """Return blocking findings from Terraform plan resource changes."""
    findings = []
    resources = defaultdict(list)

    def fail(message):
        findings.append(message)

    if not isinstance(plan, dict):
        return ["Terraform plan must be a JSON object."]

    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        return ["Terraform plan has no valid resource_changes list."]

    for item in changes:
        if not isinstance(item, dict):
            fail("Invalid resource change entry.")
            continue

        change = item.get("change")
        if not isinstance(change, dict):
            fail(f"Invalid change details for {item.get('address', 'unknown')}.")
            continue

        address = item.get("address", "unknown")
        actions = change.get("actions")

        if not isinstance(actions, list):
            fail(f"Invalid actions for {address}.")
            continue

        if "delete" in actions:
            fail(f"Destructive change detected: {address}")

        # Deleted resources are not part of the proposed after-state.
        if actions == ["delete"]:
            continue

        resource_type = item.get("type")
        after = change.get("after")

        if not isinstance(after, dict):
            if resource_type in {
                "aws_vpc",
                "aws_subnet",
                "aws_internet_gateway",
                "aws_route_table",
                "aws_route_table_association",
                "aws_nat_gateway",
                "aws_security_group",
            }:
                fail(f"Cannot verify planned attributes for {address}.")
            continue

        if resource_type:
            resources[resource_type].append({
                "address": address,
                "after": after,
                "actions": actions,
            })

    # REQ-001: Exactly one VPC with the expected CIDR.
    vpcs = resources["aws_vpc"]

    if len(vpcs) != 1:
        fail(f"Expected one VPC; found {len(vpcs)}.")
    elif vpcs[0]["after"].get("cidr_block") != EXPECTED_VPC_CIDR:
        fail(f"VPC CIDR must be {EXPECTED_VPC_CIDR}.")

    # REQ-002 and REQ-003: Subnet counts and exact CIDRs.
    subnets = resources["aws_subnet"]

    public = [
        item for item in subnets
        if ".public[" in item["address"]
    ]
    private = [
        item for item in subnets
        if ".private[" in item["address"]
    ]

    if len(public) != 2:
        fail(f"Expected two public subnets; found {len(public)}.")

    if len(private) != 2:
        fail(f"Expected two private subnets; found {len(private)}.")

    def verify_subnet_cidrs(label, subnet_items, expected_cidrs):
        actual_cidrs = []

        for subnet in subnet_items:
            cidr = subnet["after"].get("cidr_block")

            if not isinstance(cidr, str) or not cidr:
                fail(f"Cannot verify CIDR for {label} subnet {subnet['address']}.")
                continue

            try:
                network = ip_network(cidr, strict=True)
            except ValueError:
                fail(f"Invalid CIDR for {label} subnet {subnet['address']}.")
                continue

            if network.version != 4:
                fail(f"{label.capitalize()} subnet must use IPv4 CIDR: {cidr}.")
                continue

            actual_cidrs.append(cidr)

        if set(actual_cidrs) != expected_cidrs or len(actual_cidrs) != len(expected_cidrs):
            fail(
                f"{label.capitalize()} subnet CIDRs must be "
                f"{sorted(expected_cidrs)}; found {sorted(actual_cidrs)}."
            )

    verify_subnet_cidrs("public", public, EXPECTED_PUBLIC_CIDRS)
    verify_subnet_cidrs("private", private, EXPECTED_PRIVATE_CIDRS)

    for label, subnet_items in (("public", public), ("private", private)):
        zones = [
            subnet["after"].get("availability_zone")
            for subnet in subnet_items
        ]

        if any(not isinstance(zone, str) or not zone for zone in zones):
            fail(f"Cannot verify Availability Zones for {label} subnets.")
        elif len(set(zones)) != len(zones):
            fail(f"{label.capitalize()} subnets must use distinct Availability Zones.")

    for subnet in public:
        if subnet["after"].get("map_public_ip_on_launch") is not True:
            fail(f"Public subnet must assign public IPs: {subnet['address']}")

    # REQ-004: Internet Gateway and public route through that gateway.
    gateways = resources["aws_internet_gateway"]

    if len(gateways) != 1:
        fail(f"Expected one Internet Gateway; found {len(gateways)}.")

    gateway_ids = {
        gateway["after"].get("id")
        for gateway in gateways
        if isinstance(gateway["after"].get("id"), str)
        and gateway["after"].get("id")
    }

    public_tables = [
        item for item in resources["aws_route_table"]
        if ".public" in item["address"]
    ]

    if len(public_tables) != 1:
        fail(f"Expected one public route table; found {len(public_tables)}.")
    else:
        routes = public_tables[0]["after"].get("route")

        if not isinstance(routes, list):
            fail("Cannot verify public route table routes.")
        else:
            valid_igw_route = any(
                isinstance(route, dict)
                and route.get("cidr_block") == "0.0.0.0/0"
                and isinstance(route.get("gateway_id"), str)
                and route.get("gateway_id", "").startswith("igw-")
                and route.get("gateway_id") in gateway_ids
                for route in routes
            )

            if not valid_igw_route:
                fail(
                    "Public route table must have a default route "
                    "targeting the planned Internet Gateway."
                )

    public_associations = [
        item for item in resources["aws_route_table_association"]
        if ".public[" in item["address"]
    ]

    if len(public_associations) != 2:
        fail("Both public subnets must have route-table associations.")

    # REQ-005: No NAT Gateway or private default internet route.
    if resources["aws_nat_gateway"]:
        fail("NAT Gateways are not permitted by the current requirements.")

    private_tables = [
        item for item in resources["aws_route_table"]
        if ".private[" in item["address"]
    ]

    if len(private_tables) != 2:
        fail(f"Expected two private route tables; found {len(private_tables)}.")

    for table in private_tables:
        routes = table["after"].get("route")

        if not isinstance(routes, list):
            fail(f"Cannot verify private routes: {table['address']}.")
            continue

        for route in routes:
            if not isinstance(route, dict):
                fail(f"Invalid route in {table['address']}.")
                continue

            if (
                route.get("cidr_block") == "0.0.0.0/0"
                or route.get("ipv6_cidr_block") == "::/0"
            ):
                fail(
                    "Private route table has a default internet route: "
                    f"{table['address']}"
                )
                break

    private_associations = [
        item for item in resources["aws_route_table_association"]
        if ".private[" in item["address"]
    ]

    if len(private_associations) != 2:
        fail("Both private subnets must have route-table associations.")

    # REQ-006: Block public SSH/RDP over IPv4 and IPv6.
    for security_group in resources["aws_security_group"]:
        ingress = security_group["after"].get("ingress")

        if not isinstance(ingress, list):
            fail(
                "Cannot verify security-group ingress: "
                f"{security_group['address']}."
            )
            continue

        for rule in ingress:
            if not isinstance(rule, dict):
                fail(
                    "Invalid ingress rule in "
                    f"{security_group['address']}."
                )
                continue

            cidrs = rule.get("cidr_blocks") or []
            ipv6_cidrs = rule.get("ipv6_cidr_blocks") or []
            protocol = str(rule.get("protocol", "")).lower()
            start = rule.get("from_port")
            end = rule.get("to_port")

            public_ipv4 = "0.0.0.0/0" in cidrs
            public_ipv6 = "::/0" in ipv6_cidrs

            if not (public_ipv4 or public_ipv6):
                continue

            if protocol == "-1":
                fail(
                    "All-protocol public ingress is forbidden: "
                    f"{security_group['address']}."
                )
                continue

            if protocol in {"tcp", "6"}:
                if not isinstance(start, int) or not isinstance(end, int):
                    fail(
                        "Cannot verify public TCP ingress ports: "
                        f"{security_group['address']}."
                    )
                    continue

                if start <= 22 <= end or start <= 3389 <= end:
                    fail(
                        "Public SSH/RDP ingress is forbidden: "
                        f"{security_group['address']}."
                    )

    return findings
