
"""Deterministic checks for the proposed AWS VPC Terraform plan."""

from collections import defaultdict


def check_plan(plan):
    """Return deterministic findings from Terraform plan resource changes."""
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

        change = item.get("change") or {}
        actions = change.get("actions", [])

        if not isinstance(actions, list):
            fail(f"Invalid actions for {item.get('address', 'unknown')}.")
            continue

        # A deletion or replacement must not silently pass this baseline.
        if "delete" in actions:
            fail(f"Destructive change detected: {item.get('address', 'unknown')}")

        if actions == ["delete"]:
            continue

        resource_type = item.get("type")
        after = change.get("after")

        if resource_type and isinstance(after, dict):
            resources[resource_type].append({
                "address": item.get("address", ""),
                "after": after,
                "actions": actions,
            })

    # REQ-001: Exactly one VPC with the expected CIDR.
    vpcs = resources["aws_vpc"]
    if len(vpcs) != 1:
        fail(f"Expected one VPC; found {len(vpcs)}.")
    elif vpcs[0]["after"].get("cidr_block") != "10.0.0.0/16":
        fail("VPC CIDR must be 10.0.0.0/16.")

    # REQ-002 and REQ-003: Two public and two private subnets.
    public = [
        r for r in resources["aws_subnet"]
        if ".public[" in r["address"]
    ]
    private = [
        r for r in resources["aws_subnet"]
        if ".private[" in r["address"]
    ]

    if len(public) != 2:
        fail(f"Expected two public subnets; found {len(public)}.")
    if len(private) != 2:
        fail(f"Expected two private subnets; found {len(private)}.")

    for label, subnets in (("public", public), ("private", private)):
        zones = [
            r["after"].get("availability_zone")
            for r in subnets
        ]
        if any(not zone for zone in zones):
            fail(f"Cannot verify Availability Zones for {label} subnets.")
        elif len(set(zones)) != len(zones):
            fail(f"{label.capitalize()} subnets must use distinct Availability Zones.")

    for subnet in public:
        if subnet["after"].get("map_public_ip_on_launch") is not True:
            fail(f"Public subnet must assign public IPs: {subnet['address']}")

    # REQ-004: Internet Gateway and public default route.
    gateways = resources["aws_internet_gateway"]
    if len(gateways) < 1:
        fail("An Internet Gateway is required.")

    public_tables = [
        r for r in resources["aws_route_table"]
        if ".public" in r["address"]
    ]
    if len(public_tables) != 1:
        fail(f"Expected one public route table; found {len(public_tables)}.")
    else:
        routes = public_tables[0]["after"].get("route") or []
        has_default_route = any(
            route.get("cidr_block") == "0.0.0.0/0"
            and (
                route.get("gateway_id")
                or route.get("gateway_id") is None
                and route.get("nat_gateway_id") is None
            )
            for route in routes
        )
        if not has_default_route:
            fail("Public route table must have a default internet route.")

    public_associations = [
        r for r in resources["aws_route_table_association"]
        if ".public[" in r["address"]
    ]
    if len(public_associations) != 2:
        fail("Both public subnets must have route-table associations.")

    # REQ-005: No NAT Gateway and no private default internet route.
    if resources["aws_nat_gateway"]:
        fail("NAT Gateways are not permitted by the current requirements.")

    private_tables = [
        r for r in resources["aws_route_table"]
        if ".private[" in r["address"]
    ]
    if len(private_tables) != 2:
        fail(f"Expected two private route tables; found {len(private_tables)}.")

    for table in private_tables:
        routes = table["after"].get("route") or []
        if any(
            route.get("cidr_block") == "0.0.0.0/0"
            or route.get("ipv6_cidr_block") == "::/0"
            for route in routes
        ):
            fail(f"Private route table has a default internet route: {table['address']}")

    private_associations = [
        r for r in resources["aws_route_table_association"]
        if ".private[" in r["address"]
    ]
    if len(private_associations) != 2:
        fail("Both private subnets must have route-table associations.")

    # REQ-006: No public SSH/RDP ingress.
    for sg in resources["aws_security_group"]:
        for rule in sg["after"].get("ingress") or []:
            cidrs = rule.get("cidr_blocks") or []
            protocol = str(rule.get("protocol", "")).lower()
            start = rule.get("from_port")
            end = rule.get("to_port")

            if "0.0.0.0/0" not in cidrs:
                continue

            if protocol == "-1":
                fail(f"All-protocol public ingress is forbidden: {sg['address']}")
            elif protocol in {"tcp", "6"} and start is not None and end is not None:
                if start <= 22 <= end or start <= 3389 <= end:
                    fail(f"Public SSH/RDP ingress is forbidden: {sg['address']}")

    return findings
