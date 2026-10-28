# Windows Server & Endpoint Security Compliance Auditor

A production-grade PowerShell auditing framework designed to evaluate Windows workstations and servers against core security baseline standards, helping administrators identify configuration drift and vulnerabilities.

## 🚀 Overview
In enterprise environments, maintaining consistent security configurations across endpoints is critical. This script performs automated checks on critical attack surface areas—such as local administrator memberships, password policies, firewall profiles, and SMBv1 status—and outputs clear status indicators.

## 🛠️ Core Features
* **Baseline Security Checks:** Inspects essential system hardening parameters (e.g., verifying legacy protocol status, password complexity enforcement, and Remote Desktop security).
* **Auditing vs. Remediation Design:** Built strictly as a read-only audit tool to ensure zero unintended side effects during compliance scans.
* **Structured Output:** Generates clean, color-coded console logs detailing passed and failed security checks for quick administrative review.

## 📂 Repository Structure
```text
└── scripts/
    └── Audit-SecurityBaseline.ps1   # Core security compliance auditing script

