# Databricks Workspace Builder

## Overview

Setting up a Databricks workspace is a crucial first step in initiating platform consumption. However, the process often requires significant customization, as each customer has unique network requirements that must be addressed during workspace creation.

To make this process more accessible, especially for new customers who want to try Databricks, the setup should be simplified. Ideally, it should be achievable with just a few clicks or by running straightforward scripts. This necessity has led to the adoption of Terraform, an Infrastructure as Code (IaC) tool, to streamline and automate the deployment of Databricks workspaces.

## The Challenge

While Terraform is powerful, its syntax can be challenging for those unfamiliar with IaC concepts. It requires a considerable amount of upskilling to use effectively, especially for Databricks workspace deployment. This complexity can be a barrier for customers who want to quickly get started with Databricks.

## Introducing the Workspace Builder

To address these challenges, the **Workspace Builder** tool has been developed. The main goal of this tool is to simplify the creation of Terraform scripts, incorporating all necessary network, IAM, and S3 customizations that customers may need.

### Key Features:
- **User-Friendly:** Customers simply need to input the required details for their Databricks workspace setup.
- **Customizable:** The tool allows for customization based on individual network and security requirements.
- **Automated Terraform Script Generation:** The tool generates the Terraform script needed for deployment, removing the need for customers to manually write complex code.

## Project Phases

The project is being developed in multiple phases to enhance its functionality and independence:

### Phase 1: Terraform Script Generation
In this initial phase, the primary goal is to generate the Terraform script. This script can either be provided to the customer or created by the customers themselves using the Workspace Builder tool.

### Phase 2: Tool Automation and Independence
In the second phase, the tool will be enhanced to become more independent by adding capabilities for automatic Terraform installation in the customer's environment, if needed. Once Terraform is installed, the tool will automatically run the script to create the workspace.

## Current Tool Capabilities

The Workspace Builder tool is currently equipped to create an AWS workspace with Bring your Own VPC (BYOVPC) & Secured Cluster Connectivity (SCC) enabled. Its capabilities include:

### Network Level:
1. **VPC Creation:** The tool can create a complete VPC along with all the necessary network components required for a Databricks workspace.
2. **Existing VPC:** If a VPC already exists, the tool can create either public or private subnets and other dependent network components required for the Databricks workspace based on the user's input.

### IAM Level:
- **Cross-Account IAM Role:** The tool can create the cross-account IAM role required for the Databricks workspace.

### Storage:
- **DBFS Root Bucket:** The tool can create the DBFS root bucket necessary for the Databricks workspace.

### Databricks Workspace Creation:
- The tool combines all these components to create a fully functional Databricks workspace.

## Pre-requisites

Before using the Workspace Builder tool, ensure the following:

1. **Terraform Installation:** Make sure Terraform is installed in your environment.
2. **Databricks Account:** A Databricks account needs to be created prior to running the tool.
3. **AWS Infrastructure Access:** The user must have the relevant permissions to create AWS infrastructure.
4. **Databricks Account Admin Access:** The user must have Account Admin access in the Databricks account.

## How to Authenticate

To authenticate and configure the necessary credentials for AWS and Databricks, follow these steps:

### AWS Authentication:
Configure AWS CLI using the official documentation provided by AWS:
[AWS CLI Configuration](https://docs.aws.amazon.com/cli/latest/userguide/welcome-examples.html)

### Databricks Authentication:
Configure Databricks authentication using the OAuth 2.0 documentation provided by Databricks:
[Databricks Authentication](https://docs.databricks.com/en/dev-tools/auth/oauth-u2m.html#language-Terraform)


## Repository Content

This repository contains all the code necessary to help customers build Terraform scripts for deploying their Databricks workspaces. By using this tool, customers can reduce the complexity of workspace setup and focus more on leveraging Databricks' capabilities.

## How to Use

To begin using the Workspace Builder tool, run the following command in your terminal:

```bash
python prompts.py
```

1. **Input Required Details:** Provide all necessary details regarding network configuration, IAM roles, and S3 settings.
2. **Generate Terraform Script:** The Workspace Builder tool will create a Terraform script based on your inputs.
3. **Deploy Workspace:** Use the generated Terraform script to deploy your Databricks workspace.

## Conclusion

The Workspace Builder tool is designed to make Databricks workspace deployment more accessible and efficient for all customers, regardless of their familiarity with Terraform. By simplifying the creation of Terraform scripts and automating the deployment process, this tool enables faster and more customized workspace setups, empowering customers to focus on their core business goals.
