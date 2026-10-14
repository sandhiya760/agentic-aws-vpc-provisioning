# Agentic AI-Assisted AWS VPC Provisioning

An AI-assisted DevOps project that provisions AWS networking with Terraform, performs deterministic security checks using Python, and uses Google Gemini to explain infrastructure changes before human approval.

## Overview

This project demonstrates Infrastructure as Code (IaC), cloud networking, automated security checks, AI-assisted plan review, and continuous integration with GitHub Actions.

The goal is to make infrastructure changes easier to review while keeping the final deployment decision under human control.

## Architecture

- **AWS:** VPC and networking resources in the Mumbai region (`ap-south-1`)
- **Terraform:** Infrastructure provisioning and state management
- **Python:** Deterministic security checks and approval-gate logic
- **Google Gemini:** AI-assisted explanation of planned infrastructure changes
- **GitHub Actions:** Automated Terraform validation and Python testing
- **Amazon S3:** Encrypted, versioned remote Terraform state

## Infrastructure

The Terraform configuration provisions:

- One VPC with CIDR `10.0.0.0/16`
- Two public subnets across availability zones
- Two private subnets across availability zones
- An Internet Gateway and public routing
- Separate private route tables without NAT gateways
- An application security group

No EC2 instances or NAT gateways are provisioned by this configuration.

## Security and Approval Workflow

1. Terraform generates an infrastructure plan.
2. Python checks selected security-group ingress patterns and destructive actions.
3. Google Gemini explains the proposed changes when an AI review is needed.
4. The approval gate blocks detected high-risk ingress patterns and destructive changes.
5. A human must explicitly approve an eligible plan before Terraform apply.

The security checks are intentionally limited in scope. They are not a complete AWS security audit, and AI-generated recommendations must be verified independently.

## Continuous Integration

GitHub Actions currently runs:

- Terraform formatting checks
- Terraform initialization without the remote backend
- Terraform configuration validation
- Automated Python tests

The CI workflow does not deploy infrastructure or require AWS credentials.

## Project Structure

```text
aws-vpc-agent/
├── .github/
│   └── workflows/
│       └── ci.yml
├── approval_gate.py
├── check_gemini_connection.py
├── main.tf
├── review_plan.py
├── review_plan_ai.py
├── unified_reviewer.py
├── test_approval_gate.py
├── test_security_review.py
├── .gitignore
└── README.md
```

## Prerequisites

- Terraform CLI
- AWS CLI and appropriately scoped AWS credentials
- Python 3.13 or compatible version
- A Google Gemini API key for AI-assisted reviews
- Git

## Local Setup

1. Clone the repository.
2. Install the Python dependencies:

   ```bash
   python -m pip install pytest python-dotenv google-genai
   ```

3. Configure AWS credentials securely if you intend to work with real infrastructure.
4. Create a local `.env` file for AI reviews:

   ```text
   GEMINI_API_KEY=your_api_key_here
   GEMINI_MODEL=gemini-3.1-flash-lite
   ```

   Never commit `.env` or expose your API key.

5. Validate the Terraform configuration:

   ```bash
   terraform fmt -check -recursive
   terraform init -backend=false
   terraform validate
   ```

6. Run the automated tests:

   ```bash
   python -m pytest -v
   ```

## Safe Testing

Test the approval gate using simulated Terraform plan JSON:

```bash
python approval_gate.py --test-plan-json test_plan.json
python approval_gate.py --test-plan-json test_destroy_plan.json
```

These test cases should be used only with simulated JSON files. They do not apply infrastructure changes. An intentionally unsafe test is expected to be blocked.

## Cost and Safety Notes

- The configured VPC and networking resources do not include NAT gateways or compute instances.
- AWS charges can still apply to other services and resources, including remote state storage.
- Review current AWS pricing and account budgets before making infrastructure changes.
- Never run Terraform apply against a real environment without reviewing the plan and confirming authorization.

## Limitations

- Security checks cover selected IPv4 security-group ingress patterns and destructive actions only.
- Gemini provides recommendations, not a guarantee of security.
- CI validates the configuration and runs local tests; it does not verify the live AWS environment.
- Human approval in the local prototype is not equivalent to a protected, multi-person production approval system.

## Future Improvements

- Add an optional Gemini review stage to GitHub Actions.
- Configure AWS authentication through GitHub OIDC and least-privilege IAM.
- Add stronger Terraform security policies and broader automated tests.
- Introduce protected deployment environments with explicit approval.

## Author

Sandhiya S

Built as a hands-on project exploring Cloud Engineering, DevOps automation, Infrastructure as Code, and AI-assisted security review.
