# Agentic AI-Assisted AWS VPC Provisioning & DevOps Automation

An infrastructure automation project that combines **Terraform, AWS, GitHub Actions, Python, and Gemini AI** to validate infrastructure requirements, detect security risks, review Terraform plans, and control deployments through a human approval gate.

## Overview

This project implements a security-focused Infrastructure as Code (IaC) workflow for provisioning an AWS Virtual Private Cloud (VPC). It integrates deterministic Python validation with AI-assisted requirements review to help identify configuration gaps before infrastructure changes are applied.

The CI/CD pipeline authenticates to AWS using GitHub Actions OIDC, validates Terraform configurations, runs automated tests, reviews the execution plan, and skips deployment when no infrastructure changes are detected.

## Architecture

```text
Developer
    |
    v
GitHub Repository
    |
    v
GitHub Actions CI/CD
    |
    +--> Automated Python Tests
    |
    +--> AWS OIDC Authentication
    |
    +--> Terraform Init & Validate
    |
    +--> Terraform Plan
    |
    +--> Deterministic Security Checks
    |
    +--> Gemini AI Requirements Review
    |
    v
Reviewed Plan
    |
    +--> No Changes --> Skip Apply
    |
    +--> Changes Detected
              |
              v
       Human Approval Gate
              |
              v
       Terraform Apply
              |
              v
         AWS VPC
```

## AWS Infrastructure

The Terraform configuration defines the following resources:

- **Amazon VPC:** CIDR block `10.0.0.0/16`
- **Public subnets:** Two subnets across distinct Availability Zones
- **Private subnets:** Two subnets across distinct Availability Zones
- **Internet Gateway:** Enables internet routing for public subnets
- **Route tables:** Separate public and private routing configurations
- **Security group:** No inbound rules by default
- **Amazon S3:** Remote Terraform state storage with encryption, versioning, public-access blocking, and state locking

Private subnets are configured without a NAT Gateway or default internet route, reducing unnecessary exposure and infrastructure costs.

## Technology Stack

- **Cloud:** Amazon Web Services (AWS)
- **Infrastructure as Code:** Terraform
- **Automation:** Python
- **CI/CD:** GitHub Actions
- **AI-assisted review:** Google Gemini API
- **Testing:** pytest
- **Authentication:** GitHub Actions OIDC and AWS IAM roles
- **State management:** Amazon S3 with native Terraform state locking

## Security and Governance

### 1. Deterministic Infrastructure Validation
Python checks Terraform plan evidence against defined requirements, including VPC CIDR, subnet segmentation, routing, and security-group exposure.

### 2. AI-Assisted Requirements Review
Gemini reviews infrastructure requirements against Terraform configuration and plan evidence. Invalid or failed reviews block the workflow rather than allowing an unverified plan to proceed.

### 3. Secure GitHub-to-AWS Authentication
GitHub Actions uses OpenID Connect (OIDC) to obtain temporary AWS credentials instead of storing long-lived AWS access keys in GitHub secrets.

### 4. Human Approval Before Deployment
Infrastructure-changing plans must pass through a protected GitHub environment requiring human approval before the apply job can proceed.

### 5. Remote Terraform State
Terraform state is stored in Amazon S3 with encryption, versioning, public-access blocking, and state locking to support consistent infrastructure management.

### 6. Cost-Conscious Networking
The design avoids a NAT Gateway and private-subnet default internet routes. No EC2 instances are required for the core VPC provisioning workflow.

## CI/CD Workflow

The deployment workflow performs these steps:

1. Checks out the reviewed repository commit.
2. Installs Terraform and Python dependencies.
3. Runs automated tests.
4. Authenticates to AWS using OIDC.
5. Initializes and validates Terraform.
6. Generates a Terraform execution plan.
7. Runs deterministic security and requirements checks.
8. Performs the mandatory Gemini-assisted requirements review.
9. Determines whether the reviewed plan changes infrastructure.
10. Skips the apply stage if no changes are detected.
11. Requires protected-environment approval before applying a plan containing infrastructure changes.

## Test Results

**Latest verified workflow:** Terraform CD – Reviewed Deployment, run #8.

- GitHub Actions status: Success
- Workflow duration: 56 seconds
- Automated Python tests: 29 passed
- Terraform validation: Passed
- Deterministic requirements checks: Passed
- Gemini-assisted requirements review: Passed
- Infrastructure change detection: Completed successfully
- Apply stage: Skipped because no infrastructure changes were detected

The successful run validates the no-change path of the pipeline. A successful infrastructure-changing apply has not been demonstrated by this run.

## Project Structure

```text
agentic-aws-vpc-provisioning/
├── .github/
│   └── workflows/
│       └── deploy.yml
├── main.tf
├── requirements.json
├── approval_gate.py
├── deterministic_requirements.py
├── requirements_review.py
├── review_plan.py
├── test_approval_gate.py
├── test_deterministic_requirements.py
├── test_requirements_review.py
├── test_security_review.py
└── README.md
```

## Key Learnings

- Designing public and private subnet architectures in AWS.
- Implementing Infrastructure as Code using Terraform.
- Managing remote state and state locking.
- Building CI/CD pipelines with GitHub Actions.
- Configuring OIDC-based AWS authentication.
- Writing deterministic infrastructure security checks.
- Integrating AI-assisted review with fail-closed validation.
- Implementing human approval gates and conditional deployment logic.
- Testing infrastructure automation using pytest.

## Future Improvements

- Add infrastructure drift detection.
- Expand automated policy checks for additional AWS security controls.
- Introduce automated documentation and plan summaries.
- Add monitoring and operational visibility for deployed workloads.

## Repository

[View the source code on GitHub](https://github.com/sandhiya760/agentic-aws-vpc-provisioning)

**Disclaimer:** This project is a learning and portfolio project. Review IAM permissions, credentials, costs, and security controls before adapting it for production use.
