version = '''terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">=4.57.0"
    }
    databricks = {
      source = "databricks/databricks"
      version = "1.51.0"
    }
  }
}
'''
provider = '''
provider "aws" {{
region = "{}"
}}

provider "databricks" {{
  alias = "mws"
  host = "https://accounts.cloud.databricks.com"
  account_id = "0d26daa6-5e44-4c97-a497-ef015f91254a"
  client_id = "0ecd45e2-7ab0-4dab-8e68-af4bc7f5bd64"
  client_secret = "dose7cbdc00e43cada83c773c35609dd97d6"
}}

'''
vpc_data_source = '''
data "aws_vpc" "existing_vpc" {{
  id = "{0}"
}}
'''
subnet_data_source = '''
data "aws_subnet" "{0}" {{
  id = "{1}"
}}'''
create_subnet_vpc = '''
resource "aws_subnet" {0} {{
  vpc_id                  = data.aws_vpc.existing_vpc.id
  cidr_block              = "{1}"
  availability_zone       = "{2}"
}}
'''
create_new_vpc_and_components = '''
terraform {{
  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = ">=4.57.0"
    }}
    databricks = {{
      source = "databricks/databricks"
      version = "1.51.0"
    }}
  }}
}}

provider "aws" {{
region = "{10}"
}}

provider "databricks" {{
  alias = "mws"
  host = "https://accounts.cloud.databricks.com"
}}

module "vpc" {{
  source = "terraform-aws-modules/vpc/aws"

  name = "{0}"
  cidr = "{1}"

  azs             = ["{2}","{3}"]
  private_subnets = ["{4}","{5}"]
  public_subnets  = ["{6}","{7}"]

  enable_nat_gateway = true
  single_nat_gateway = {8}
  one_nat_gateway_per_az = {9}
  
  manage_default_security_group = true
  default_security_group_name   = "{0}-default-sg"

  default_security_group_egress = [{{
    cidr_blocks = "0.0.0.0/0"
  }}]

  default_security_group_ingress = [{{
    description = "Allow all internal TCP and UDP"
    self        = true
  }}]

}}

module "vpc_endpoints" {{
  source  = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"

  vpc_id             = module.vpc.vpc_id
  security_group_ids = [module.vpc.default_security_group_id]

  endpoints = {{
    s3 = {{
      service      = "s3"
      service_type = "Gateway"
      route_table_ids = flatten([
        module.vpc.private_route_table_ids,
      module.vpc.public_route_table_ids])
      tags = {{
        Name = "{0}-s3-vpc-endpoint"
      }}
    }},
    sts = {{
      service             = "sts"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      tags = {{
        Name = "{0}-sts-vpc-endpoint"
      }}
    }},
    kinesis-streams = {{
      service             = "kinesis-streams"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      tags = {{
        Name = "{0}-kinesis-vpc-endpoint"
      }}
    }},
  }}

}}

resource "aws_security_group" "workspace_security_group" {{
  name        = "databricks_workspace_security_group"
  description = "Security group for Databricks workspace"
  vpc_id      = module.vpc.vpc_id

  # Ingress (Inbound) Rules

  # Allow TCP on all ports within the security group
  ingress {{
    description = "Allow TCP on all ports within the security group"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }}

  # Allow UDP on all ports within the security group
  ingress {{
    description = "Allow UDP on all ports within the security group"
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    self        = true
  }}

  # Egress (Outbound) Rules

  # Allow TCP on all ports within the security group
  egress {{
    description = "Allow TCP on all ports within the security group"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }}

  # Allow UDP on all ports within the security group
  egress {{
    description = "Allow UDP on all ports within the security group"
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    self        = true
  }}

  # Allow TCP access on specific ports to 0.0.0.0/0
  egress {{
    description = "for Databricks infrastructure, cloud data sources, and library repositories"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  egress {{
    description = "for the metastore"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  egress {{
    description = "for internal calls from the Databricks compute plane to the Databricks control plane API."
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  egress {{
    description = "for Unity Catalog logging and lineage data streaming into Databricks."
    from_port   = 8444
    to_port     = 8444
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  egress {{
    description = "Future extendability"
    from_port   = 8445
    to_port     = 8451
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  tags = {{
    Name = "databricks-workspace-sg"
  }}
}}


'''
security_group = '''
resource "aws_security_group" "workspace_security_group" {{
  name        = "databricks_workspace_security_group"
  description = "Security group for Databricks workspace"
  vpc_id      = data.aws_vpc.existing_vpc.id

  # Ingress (Inbound) Rules

  # Allow TCP on all ports within the security group
  ingress {{
    description = "Allow TCP on all ports within the security group"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }}

  # Allow UDP on all ports within the security group
  ingress {{
    description = "Allow UDP on all ports within the security group"
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    self        = true
  }}

  # Egress (Outbound) Rules

  # Allow TCP on all ports within the security group
  egress {{
    description = "Allow TCP on all ports within the security group"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }}

  # Allow UDP on all ports within the security group
  egress {{
    description = "Allow UDP on all ports within the security group"
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    self        = true
  }}

  # Allow TCP access on specific ports to 0.0.0.0/0
  egress {{
    description = "for Databricks infrastructure, cloud data sources, and library repositories"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  egress {{
    description = "for the metastore"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  egress {{
    description = "for internal calls from the Databricks compute plane to the Databricks control plane API."
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  egress {{
    description = "for Unity Catalog logging and lineage data streaming into Databricks."
    from_port   = 8444
    to_port     = 8444
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  egress {{
    description = "Future extendability"
    from_port   = 8445
    to_port     = 8451
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  tags = {{
    Name = "databricks-workspace-sg"
  }}
}}'''
bucket_policy = '''
resource "aws_s3_bucket" "root_bucket" {{
  bucket = "{0}"
}}

resource "aws_s3_bucket_policy" "test_bucket_policy" {{
  bucket = aws_s3_bucket.root_bucket.id

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid       = "Grant Databricks Access"
        Effect    = "Allow"
        Principal = {{
          AWS = "arn:aws:iam::414351767826:root"
        }}
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = [
          "arn:aws:s3:::{0}/*",
          "arn:aws:s3:::{0}"
        ]
        Condition = {{
          StringEquals = {{
            "aws:PrincipalTag/DatabricksAccountId" = [
              "0d26daa6-5e44-4c97-a497-ef015f91254a"
            ]
          }}
        }}
      }}
    ]
  }})
}}
'''
workspace_catalog_iam_role = '''
resource "aws_iam_role" "databricks_iam_role" {{
  name = "{0}"  # Replace with your IAM Role name

  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect = "Allow"
      Principal = {{
        AWS = "arn:aws:iam::414351767826:role/unity-catalog-prod-UCMasterRole-14S5ZJVKOTYTL"  # Databricks role
      }}
      Action = "sts:AssumeRole"
      Condition = {{
        StringEquals = {{
          "sts:ExternalId" = "{1}"  # Replace with your Databricks Account ID
        }}
      }}
    }}]
  }})
}}

resource "aws_iam_policy" "databricks_access_policy" {{
  name = "databricks-uc-access-policy"

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect = "Allow"
        Principal = {{
          AWS = [
            "arn:aws:iam::414351767826:role/unity-catalog-prod-UCMasterRole-14S5ZJVKOTYTL",
            "arn:aws:iam::{2}:role/${{aws_iam_role.databricks_iam_role.name}}"  # Self-assume role ARN
          ]
        }}
        Action = "sts:AssumeRole"
        Condition = {{
          StringEquals = {{
            "sts:ExternalId" = "{1}"
          }}
        }}
      }}
    ]
  }})
}}

resource "aws_iam_policy" "s3_access_policy" {{
  name = "s3-access-policy"

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = [
          "arn:aws:s3:::{3}/*",  # Replace <BUCKET> with your S3 bucket name
          "arn:aws:s3:::{3}"
        ]
        Effect = "Allow"
      }},
      {{
        Action = [
          "sts:AssumeRole"
        ]
        Resource = [
          "arn:aws:iam::{2}:role/${{aws_iam_role.databricks_iam_role.name}}"  # Replace with AWS account ID
        ]
        Effect = "Allow"
      }}
    ]
  }})
}}

resource "aws_iam_role_policy_attachment" "self_assume_trust" {{
  role       = aws_iam_role.databricks_iam_role.name
  policy_arn = aws_iam_policy.databricks_access_policy.arn
}}

resource "aws_iam_role_policy_attachment" "attach_s3_access_policy" {{
  role       = aws_iam_role.databricks_iam_role.name
  policy_arn = aws_iam_policy.s3_access_policy.arn
}}
'''


custom_with_default_restrictions = '''
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Stmt1403287045000",
      "Effect": "Allow",
      "Action": [
        "ec2:AssociateIamInstanceProfile",
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CancelSpotInstanceRequests",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteTags",
        "ec2:DeleteVolume",
        "ec2:DescribeAvailabilityZones",
        "ec2:DescribeIamInstanceProfileAssociations",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeInstances",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribePrefixLists",
        "ec2:DescribeReservedInstancesOfferings",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSpotInstanceRequests",
        "ec2:DescribeSpotPriceHistory",
        "ec2:DescribeSubnets",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcAttribute",
        "ec2:DescribeVpcs",
        "ec2:DetachVolume",
        "ec2:DisassociateIamInstanceProfile",
        "ec2:ReplaceIamInstanceProfileAssociation",
        "ec2:RequestSpotInstances",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:RunInstances",
        "ec2:TerminateInstances",
        "ec2:DescribeFleetHistory",
        "ec2:ModifyFleet",
        "ec2:DeleteFleets",
        "ec2:DescribeFleetInstances",
        "ec2:DescribeFleets",
        "ec2:CreateFleet",
        "ec2:DeleteLaunchTemplate",
        "ec2:GetLaunchTemplateData",
        "ec2:CreateLaunchTemplate",
        "ec2:DescribeLaunchTemplates",
        "ec2:DescribeLaunchTemplateVersions",
        "ec2:ModifyLaunchTemplate",
        "ec2:DeleteLaunchTemplateVersions",
        "ec2:CreateLaunchTemplateVersion",
        "ec2:AssignPrivateIpAddresses",
        "ec2:GetSpotPlacementScores"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole",
        "iam:PutRolePolicy"
      ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/spot.amazonaws.com/AWSServiceRoleForEC2Spot",
      "Condition": {
        "StringLike": {
          "iam:AWSServiceName": "spot.amazonaws.com"
        }
      }
    }
  ]
}
'''
custom_with_detailed_restrictions = '''
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "NonResourceBasedPermissions",
      "Effect": "Allow",
      "Action": [
        "ec2:AssignPrivateIpAddresses",
        "ec2:CancelSpotInstanceRequests",
        "ec2:DescribeAvailabilityZones",
        "ec2:DescribeIamInstanceProfileAssociations",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeInstances",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribePrefixLists",
        "ec2:DescribeReservedInstancesOfferings",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSpotInstanceRequests",
        "ec2:DescribeSpotPriceHistory",
        "ec2:DescribeSubnets",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcAttribute",
        "ec2:DescribeVpcs",
        "ec2:CreateTags",
        "ec2:DeleteTags",
        "ec2:GetSpotPlacementScores",
        "ec2:RequestSpotInstances",
        "ec2:DescribeFleetHistory",
        "ec2:ModifyFleet",
        "ec2:DeleteFleets",
        "ec2:DescribeFleetInstances",
        "ec2:DescribeFleets",
        "ec2:CreateFleet",
        "ec2:DeleteLaunchTemplate",
        "ec2:GetLaunchTemplateData",
        "ec2:CreateLaunchTemplate",
        "ec2:DescribeLaunchTemplates",
        "ec2:DescribeLaunchTemplateVersions",
        "ec2:ModifyLaunchTemplate",
        "ec2:DeleteLaunchTemplateVersions",
        "ec2:CreateLaunchTemplateVersion"
      ],
      "Resource": [
        "*"
      ]
    }},
    {{
      "Sid": "InstancePoolsSupport",
      "Effect": "Allow",
      "Action": [
        "ec2:AssociateIamInstanceProfile",
        "ec2:DisassociateIamInstanceProfile",
        "ec2:ReplaceIamInstanceProfileAssociation"
      ],
      "Resource": "arn:aws:ec2:{0}:{1}:instance/*",
      "Condition": {{
        "StringEquals": {{
          "ec2:ResourceTag/Vendor": "Databricks"
        }}
      }}
    }},
    {{
      "Sid": "AllowEc2RunInstancePerTag",
      "Effect": "Allow",
      "Action": "ec2:RunInstances",
      "Resource": [
        "arn:aws:ec2:{0}:{1}:volume/*",
        "arn:aws:ec2:{0}:{1}:instance/*"
      ],
      "Condition": {{
        "StringEquals": {{
          "aws:RequestTag/Vendor": "Databricks"
        }}
      }}
    }},
    {{
      "Sid": "AllowEc2RunInstanceImagePerTag",
      "Effect": "Allow",
      "Action": "ec2:RunInstances",
      "Resource": [
        "arn:aws:ec2:{0}:{1}:image/*"
      ],
      "Condition": {{
        "StringEquals": {{
          "aws:ResourceTag/Vendor": "Databricks"
        }}
      }}
    }},
    {{
      "Sid": "AllowEc2RunInstancePerVPCid",
      "Effect": "Allow",
      "Action": "ec2:RunInstances",
      "Resource": [
        "arn:aws:ec2:{0}:{1}:network-interface/*",
        "arn:aws:ec2:{0}:{1}:subnet/*",
        "arn:aws:ec2:{0}:{1}:security-group/*"
      ],
      "Condition": {{
        "StringEquals": {{
          "ec2:vpc": "arn:aws:ec2:{0}:{1}:vpc/${2}"
        }}
      }}
    }},
    {{
      "Sid": "AllowEc2RunInstanceOtherResources",
      "Effect": "Allow",
      "Action": "ec2:RunInstances",
      "NotResource": [
        "arn:aws:ec2:{0}:{1}:image/*",
        "arn:aws:ec2:{0}:{1}:network-interface/*",
        "arn:aws:ec2:{0}:{1}:subnet/*",
        "arn:aws:ec2:{0}:{1}:security-group/*",
        "arn:aws:ec2:{0}:{1}:volume/*",
        "arn:aws:ec2:{0}:{1}:instance/*"
      ]
    }},
    {{
      "Sid": "EC2TerminateInstancesTag",
      "Effect": "Allow",
      "Action": [
        "ec2:TerminateInstances"
      ],
      "Resource": [
        "arn:aws:ec2:{0}:{1}:instance/*"
      ],
      "Condition": {{
        "StringEquals": {{
          "ec2:ResourceTag/Vendor": "Databricks"
        }}
      }}
    }},
    {{
      "Sid": "EC2AttachDetachVolumeTag",
      "Effect": "Allow",
      "Action": [
        "ec2:AttachVolume",
        "ec2:DetachVolume"
      ],
      "Resource": [
        "arn:aws:ec2:{0}:{1}:instance/*",
        "arn:aws:ec2:{0}:{1}:volume/*"
      ],
      "Condition": {{
        "StringEquals": {{
          "ec2:ResourceTag/Vendor": "Databricks"
        }}
      }}
    }},
    {{
      "Sid": "EC2CreateVolumeByTag",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateVolume"
      ],
      "Resource": [
        "arn:aws:ec2:{0}:{1}:volume/*"
      ],
      "Condition": {{
        "StringEquals": {{
          "aws:RequestTag/Vendor": "Databricks"
        }}
      }}
    }},
    {{
      "Sid": "EC2DeleteVolumeByTag",
      "Effect": "Allow",
      "Action": [
        "ec2:DeleteVolume"
      ],
      "Resource": [
        "arn:aws:ec2:{0}:{1}:volume/*"
      ],
      "Condition": {{
        "StringEquals": {{
          "ec2:ResourceTag/Vendor": "Databricks"
        }}
      }}
    }},
    {{
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole",
        "iam:PutRolePolicy"
      ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/spot.amazonaws.com/AWSServiceRoleForEC2Spot",
      "Condition": {{
        "StringLike": {{
          "iam:AWSServiceName": "spot.amazonaws.com"
        }}
      }}
    }},
    {{
      "Sid": "VpcNonresourceSpecificActions",
      "Effect": "Allow",
      "Action": [
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupIngress"
      ],
      "Resource": "arn:aws:ec2:{0}:{1}:security-group/${3}",
      "Condition": {{
        "StringEquals": {{
          "ec2:vpc": "arn:aws:ec2:{0}:{1}:vpc/${2}"
        }}
      }}
    }}
  ]
}}
'''

cross_acc_role = '''
# Define the IAM role for cross-account access
resource "aws_iam_role" "cross_account_role" {{
  name               = "cross_account_role"
  assume_role_policy = jsonencode({{
    Version = "2012-10-17",
    Statement = [{{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = {{
        AWS = "414351767826" # Databricks account ID
      }},
      Condition = {{
        StringEquals = {{
          "sts:ExternalId" = "{0}" # Use your Databricks account ID as the External ID
        }}
      }}
    }}]
  }})
}}

# Create the inline policy for the IAM role
resource "aws_iam_role_policy" "cross_account_role_policy" {{
  name   = "cross_account_role_policy"
  role   = aws_iam_role.cross_account_role.id

  policy = jsonencode({1})
}}
'''

databricks_network_config = '''
resource "databricks_mws_networks" "this" {{
  provider           = databricks.mws
  account_id         = "{0}"
  network_name       = "{1}"
  security_group_ids = [{2}]
  subnet_ids         = [{3},{4}]
  vpc_id             = {5}
}}'''
databricks_credential_config = '''
resource "databricks_mws_credentials" "this" {{
provider         = databricks.mws
account_id       = "{0}"
credentials_name = "{1}"
role_arn         = aws_iam_role.cross_account_role.id
}}'''

databricks_storage_config = '''
resource "databricks_mws_storage_configurations" "this" {{
provider                   = databricks.mws
account_id                 = "{0}"
storage_configuration_name = "{1}"
bucket_name                = aws_s3_bucket.root_bucket.bucket
}}'''

create_databricks_workspace = '''
resource "databricks_mws_workspaces" "this" {{
provider       = databricks.mws
account_id     = "{0}"
workspace_name = "{1}"
aws_region     = "{2}"

credentials_id           = databricks_mws_credentials.this.credentials_id
storage_configuration_id = databricks_mws_storage_configurations.this.storage_configuration_id
network_id               = databricks_mws_networks.this.network_id
}}
'''

def create_pub_rt_igw_ngw(pvt_rt_1,pvt_rt_2):

    # Part of Public Subnet
    create_internet_gateway = '''
    resource "aws_internet_gateway" "databricks_igw" {{
      vpc_id = data.aws_vpc.existing_vpc.id
    }}
    '''
    create_public_route_table = '''
    resource "aws_route_table" "pub_rt" {{
      vpc_id = data.aws_vpc.existing_vpc.id
      route {
        cidr_block = data.aws_vpc.existing_vpc.cidr_block
        gateway_id = "local"
      }
    
      route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.databricks_igw.id
      }
    
    }}
    '''
    create_pub_1_rt_assoc = '''
        resource "aws_route_table_association" "pub_1_rt_assoc" {
        subnet_id = aws_subnet.pub_1.id
        route_table_id = aws_route_table.pub_rt.id
    }
    '''
    create_pub_2_rt_assoc = '''
            resource "aws_route_table_association" "pub_2_rt_assoc" {
            subnet_id = aws_subnet.pub_2.id
            route_table_id = aws_route_table.pub_rt.id
        }
        '''

    # Part of Private Subnet
    create_eip = '''
        resource "aws_eip" "eip" {
            vpc = true
        }
            '''
    create_eip2 = '''
            resource "aws_eip" "eip2" {
                vpc = true
            }
                '''
    create_nat_gateway_1 = '''
        resource "aws_nat_gateway" databricks_nat_pvt_1 {{
          allocation_id = aws_eip.eip.id
          subnet_id     = aws_subnet.pub_1.id
        }}
            '''
    create_nat_gateway_2 = '''
        resource "aws_nat_gateway" databricks_nat_pvt_2 {{
          allocation_id = aws_eip.eip2.id
          subnet_id     = aws_subnet.pub_2.id
        }}
            '''
    create_nat_route_1 = '''
    resource "aws_route" "pvt_route_1" {{
      route_table_id            = "{0}"
      destination_cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.databricks_nat_pvt_1.id
}}'''
    create_nat_route_2 = '''
        resource "aws_route" "pvt_route_2" {{
          route_table_id            = "{0}"
          destination_cidr_block = "0.0.0.0/0"
        nat_gateway_id = aws_nat_gateway.databricks_nat_pvt_2.id
    }}'''
    create_nat_route_1=create_nat_route_1.format(pvt_rt_1)
    create_nat_route_2 = create_nat_route_2.format(pvt_rt_2)

    return create_internet_gateway, create_public_route_table,create_pub_1_rt_assoc, create_pub_2_rt_assoc,create_eip,create_eip2,create_nat_gateway_1,create_nat_gateway_2,create_nat_route_1,create_nat_route_2
def create_pvt_rt_ngw(nat_gw_1,nat_gw_2):

    if nat_gw_1 != '':
        create_private_route_table_1 = '''
    resource "aws_route_table" "pvt_rt_1" {{
      vpc_id = data.aws_vpc.existing_vpc.id
      route {{
        cidr_block = data.aws_vpc.existing_vpc.cidr_block
        gateway_id = "local"
      }}

      route {{
        cidr_block = "0.0.0.0/0"
        nat_gateway_id = "{0}"
      }}

    }}
        '''
        create_private_route_table_1 = create_private_route_table_1.format(nat_gw_1)
        create_private_route_table_2 = '''
    resource "aws_route_table" "pvt_rt_2" {{
      vpc_id = data.aws_vpc.existing_vpc.id
      route {{
        cidr_block = data.aws_vpc.existing_vpc.cidr_block
        gateway_id = "local"
      }}

      route {{
        cidr_block = "0.0.0.0/0"
        nat_gateway_id = "{0}"
      }}

    }}
        '''
        create_private_route_table_2 = create_private_route_table_2.format(nat_gw_2)
        create_eip = ''
        create_eip2 = ''
        create_nat_gateway_1 = ''
        create_nat_gateway_2 = ''

    else:
        create_eip = '''
    resource "aws_eip" "eip" {
        vpc = true
    }
        '''
        create_eip2 = '''
        resource "aws_eip" "eip2" {
            vpc = true
        }
            '''
        create_nat_gateway_1 = '''
    resource "aws_nat_gateway" databricks_nat_pvt_1 {{
      allocation_id = aws_eip.eip.id
      subnet_id     = data.aws_subnet.create_public_subnet_1.id
    }}
        '''
        create_nat_gateway_2 = '''
    resource "aws_nat_gateway" databricks_nat_pvt_2 {{
      allocation_id = aws_eip.eip2.id
      subnet_id     = data.aws_subnet.create_public_subnet_2.id
    }}
        '''
        create_private_route_table_1 = '''
    resource "aws_route_table" "pvt_rt_1" {{
      vpc_id = data.aws_vpc.existing_vpc.id
      route {
        cidr_block = data.aws_vpc.existing_vpc.cidr_block
        gateway_id = "local"
      }
    
      route {
        cidr_block = "0.0.0.0/0"
        nat_gateway_id = aws_nat_gateway.databricks_nat_pvt_1.id
      }
    
    }}
        '''
        create_private_route_table_2 = '''
resource "aws_route_table" "pvt_rt_2" {{
  vpc_id = data.aws_vpc.existing_vpc.id
  route {
    cidr_block = data.aws_vpc.existing_vpc.cidr_block
    gateway_id = "local"
  }

  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.databricks_nat_pvt_2.id
  }

}}
    '''

    create_pvt_rt_assoc_1 = '''
resource "aws_route_table_association" "pvt_rt_1_assoc" {
    subnet_id = aws_subnet.pvt_1.id
    route_table_id = aws_route_table.pvt_rt_1.id
}
    '''
    create_pvt_rt_assoc_2 = '''
resource "aws_route_table_association" "pvt_rt_2_assoc" {
    subnet_id = aws_subnet.pvt_2.id
    route_table_id = aws_route_table.pvt_rt_2.id
}
    '''

    return create_eip,create_eip2, create_nat_gateway_1, create_nat_gateway_2, create_private_route_table_1, create_private_route_table_2, create_pvt_rt_assoc_1, create_pvt_rt_assoc_2







