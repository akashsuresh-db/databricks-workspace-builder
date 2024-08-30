terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">=4.57.0"
    }
    databricks = {
      source  = "databricks/databricks"
      version = "1.51.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

provider "databricks" {
  alias         = "mws"
  host          = "https://accounts.cloud.databricks.com"
  account_id    = "0d26daa6-5e44-4c97-a497-ef015f91254a"
}


data "aws_vpc" "existing_vpc" {
  id = "vpc-08cc278e3f4d7aa3f"
}

resource "aws_subnet" pub_1 {
  vpc_id            = data.aws_vpc.existing_vpc.id
  cidr_block        = "10.0.0.128/28"
  availability_zone = "eu-west-1a"
}

resource "aws_subnet" pub_2 {
  vpc_id            = data.aws_vpc.existing_vpc.id
  cidr_block        = "10.0.0.144/28"
  availability_zone = "eu-west-1b"
}

data "aws_subnet" "create_private_subnet_1" {
  id = "subnet-0b11a392352b53e9a"
}
data "aws_subnet" "create_private_subnet_2" {
  id = "subnet-0fe18f3e468bf03ce"
}
resource "aws_eip" "eip" {
  vpc = true
}

resource "aws_eip" "eip2" {
  vpc = true
}

resource "aws_nat_gateway" databricks_nat_pvt_1 {
  allocation_id = aws_eip.eip.id
  subnet_id     = aws_subnet.pub_1.id
}

resource "aws_nat_gateway" databricks_nat_pvt_2 {
  allocation_id = aws_eip.eip2.id
  subnet_id     = aws_subnet.pub_2.id
}

resource "aws_route" "pvt_route_1" {
  route_table_id         = "rtb-037fb75708726ab5e"
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.databricks_nat_pvt_1.id
}
resource "aws_route" "pvt_route_2" {
  route_table_id         = "rtb-037fb75708726ab5e"
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.databricks_nat_pvt_2.id
}
resource "aws_internet_gateway" "databricks_igw" {
  vpc_id = data.aws_vpc.existing_vpc.id
}

resource "aws_route_table" "pub_rt" {
  vpc_id = data.aws_vpc.existing_vpc.id
  route {
    cidr_block = data.aws_vpc.existing_vpc.cidr_block
    gateway_id = "local"
  }

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.databricks_igw.id
  }

}

resource "aws_route_table_association" "pub_1_rt_assoc" {
  subnet_id      = aws_subnet.pub_1.id
  route_table_id = aws_route_table.pub_rt.id
}

resource "aws_route_table_association" "pub_2_rt_assoc" {
  subnet_id      = aws_subnet.pub_2.id
  route_table_id = aws_route_table.pub_rt.id
}

resource "aws_security_group" "workspace_security_group" {
  name        = "databricks_workspace_security_group"
  description = "Security group for Databricks workspace"
  vpc_id      = data.aws_vpc.existing_vpc.id

  # Ingress (Inbound) Rules

  # Allow TCP on all ports within the security group
  ingress {
    description = "Allow TCP on all ports within the security group"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }

  # Allow UDP on all ports within the security group
  ingress {
    description = "Allow UDP on all ports within the security group"
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    self        = true
  }

  # Egress (Outbound) Rules

  # Allow TCP on all ports within the security group
  egress {
    description = "Allow TCP on all ports within the security group"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }

  # Allow UDP on all ports within the security group
  egress {
    description = "Allow UDP on all ports within the security group"
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    self        = true
  }

  # Allow TCP access on specific ports to 0.0.0.0/0
  egress {
    description = "for Databricks infrastructure, cloud data sources, and library repositories"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "for the metastore"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "for internal calls from the Databricks compute plane to the Databricks control plane API."
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "for Unity Catalog logging and lineage data streaming into Databricks."
    from_port   = 8444
    to_port     = 8444
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Future extendability"
    from_port   = 8445
    to_port     = 8451
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "databricks-workspace-sg"
  }
}
resource "aws_s3_bucket" "root_bucket" {
  bucket = "akash-tf-root-s3"
}

resource "aws_s3_bucket_policy" "test_bucket_policy" {
  bucket = aws_s3_bucket.root_bucket.id

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Sid       = "Grant Databricks Access"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::414351767826:root"
        }
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = [
          "arn:aws:s3:::akash-tf-root-s3/*",
          "arn:aws:s3:::akash-tf-root-s3"
        ]
        Condition = {
          StringEquals = {
            "aws:PrincipalTag/DatabricksAccountId" = [
              "0d26daa6-5e44-4c97-a497-ef015f91254a"
            ]
          }
        }
      }
    ]
  })
}

#resource "aws_iam_role" "databricks_iam_role" {
#  name = "akash-uc-role"  # Replace with your IAM Role name
#
#  assume_role_policy = jsonencode({
#    Version   = "2012-10-17"
#    Statement = [
#      {
#        Effect    = "Allow"
#        Principal = {
#          AWS = "arn:aws:iam::414351767826:role/unity-catalog-prod-UCMasterRole-14S5ZJVKOTYTL"  # Databricks role
#        }
#        Action    = "sts:AssumeRole"
#        Condition = {
#          StringEquals = {
#            "sts:ExternalId" = "0d26daa6-5e44-4c97-a497-ef015f91254a"  # Replace with your Databricks Account ID
#          }
#        }
#      }
#    ]
#  })
#}
#
#resource "aws_iam_policy" "databricks_access_policy" {
#  name = "databricks-uc-access-policy"
#
#  policy = jsonencode({
#    Version   = "2012-10-17"
#    Statement = [
#      {
#        Effect    = "Allow"
#        Principal = {
#          AWS = [
#            "arn:aws:iam::414351767826:role/unity-catalog-prod-UCMasterRole-14S5ZJVKOTYTL",
#            "arn:aws:iam::997819012307:role/${aws_iam_role.databricks_iam_role.name}"  # Self-assume role ARN
#          ]
#        }
#        Action    = "sts:AssumeRole"
#        Condition = {
#          StringEquals = {
#            "sts:ExternalId" = "0d26daa6-5e44-4c97-a497-ef015f91254a"
#          }
#        }
#      }
#    ]
#  })
#}
#
#resource "aws_iam_policy" "s3_access_policy" {
#  name = "s3-access-policy"
#
#  policy = jsonencode({
#    Version   = "2012-10-17"
#    Statement = [
#      {
#        Action = [
#          "s3:GetObject",
#          "s3:PutObject",
#          "s3:DeleteObject",
#          "s3:ListBucket",
#          "s3:GetBucketLocation"
#        ]
#        Resource = [
#          "arn:aws:s3:::akash-tf-root-s3/*", # Replace <BUCKET> with your S3 bucket name
#          "arn:aws:s3:::akash-tf-root-s3"
#        ]
#        Effect = "Allow"
#      },
#      {
#        Action = [
#          "sts:AssumeRole"
#        ]
#        Resource = [
#          "arn:aws:iam::997819012307:role/${aws_iam_role.databricks_iam_role.name}"  # Replace with AWS account ID
#        ]
#        Effect = "Allow"
#      }
#    ]
#  })
#}
#
#resource "aws_iam_role_policy_attachment" "self_assume_trust" {
#  role       = aws_iam_role.databricks_iam_role.name
#  policy_arn = aws_iam_policy.databricks_access_policy.arn
#}
#
#resource "aws_iam_role_policy_attachment" "attach_s3_access_policy" {
#  role       = aws_iam_role.databricks_iam_role.name
#  policy_arn = aws_iam_policy.s3_access_policy.arn
#}
#
## Define the IAM role for cross-account access
#resource "aws_iam_role" "cross_account_role" {
#  name               = "cross_account_role"
#  assume_role_policy = jsonencode({
#    Version   = "2012-10-17",
#    Statement = [
#      {
#        Action    = "sts:AssumeRole",
#        Effect    = "Allow",
#        Principal = {
#          AWS = "414351767826" # Databricks account ID
#        },
#        Condition = {
#          StringEquals = {
#            "sts:ExternalId" = "0d26daa6-5e44-4c97-a497-ef015f91254a"
#            # Use your Databricks account ID as the External ID
#          }
#        }
#      }
#    ]
#  })
#}
#
## Create the inline policy for the IAM role
#resource "aws_iam_role_policy" "cross_account_role_policy" {
#  name = "cross_account_role_policy"
#  role = aws_iam_role.cross_account_role.id
#
#  policy = jsonencode(
#    {
#      "Version" : "2012-10-17",
#      "Statement" : [
#        {
#          "Sid" : "NonResourceBasedPermissions",
#          "Effect" : "Allow",
#          "Action" : [
#            "ec2:AssignPrivateIpAddresses",
#            "ec2:CancelSpotInstanceRequests",
#            "ec2:DescribeAvailabilityZones",
#            "ec2:DescribeIamInstanceProfileAssociations",
#            "ec2:DescribeInstanceStatus",
#            "ec2:DescribeInstances",
#            "ec2:DescribeInternetGateways",
#            "ec2:DescribeNatGateways",
#            "ec2:DescribeNetworkAcls",
#            "ec2:DescribePrefixLists",
#            "ec2:DescribeReservedInstancesOfferings",
#            "ec2:DescribeRouteTables",
#            "ec2:DescribeSecurityGroups",
#            "ec2:DescribeSpotInstanceRequests",
#            "ec2:DescribeSpotPriceHistory",
#            "ec2:DescribeSubnets",
#            "ec2:DescribeVolumes",
#            "ec2:DescribeVpcAttribute",
#            "ec2:DescribeVpcs",
#            "ec2:CreateTags",
#            "ec2:DeleteTags",
#            "ec2:GetSpotPlacementScores",
#            "ec2:RequestSpotInstances",
#            "ec2:DescribeFleetHistory",
#            "ec2:ModifyFleet",
#            "ec2:DeleteFleets",
#            "ec2:DescribeFleetInstances",
#            "ec2:DescribeFleets",
#            "ec2:CreateFleet",
#            "ec2:DeleteLaunchTemplate",
#            "ec2:GetLaunchTemplateData",
#            "ec2:CreateLaunchTemplate",
#            "ec2:DescribeLaunchTemplates",
#            "ec2:DescribeLaunchTemplateVersions",
#            "ec2:ModifyLaunchTemplate",
#            "ec2:DeleteLaunchTemplateVersions",
#            "ec2:CreateLaunchTemplateVersion"
#          ],
#          "Resource" : [
#            "*"
#          ]
#        },
#        {
#          "Sid" : "InstancePoolsSupport",
#          "Effect" : "Allow",
#          "Action" : [
#            "ec2:AssociateIamInstanceProfile",
#            "ec2:DisassociateIamInstanceProfile",
#            "ec2:ReplaceIamInstanceProfileAssociation"
#          ],
#          "Resource" : "arn:aws:ec2:eu-west-1:997819012307:instance/*",
#          "Condition" : {
#            "StringEquals" : {
#              "ec2:ResourceTag/Vendor" : "Databricks"
#            }
#          }
#        },
#        {
#          "Sid" : "AllowEc2RunInstancePerTag",
#          "Effect" : "Allow",
#          "Action" : "ec2:RunInstances",
#          "Resource" : [
#            "arn:aws:ec2:eu-west-1:997819012307:volume/*",
#            "arn:aws:ec2:eu-west-1:997819012307:instance/*"
#          ],
#          "Condition" : {
#            "StringEquals" : {
#              "aws:RequestTag/Vendor" : "Databricks"
#            }
#          }
#        },
#        {
#          "Sid" : "AllowEc2RunInstanceImagePerTag",
#          "Effect" : "Allow",
#          "Action" : "ec2:RunInstances",
#          "Resource" : [
#            "arn:aws:ec2:eu-west-1:997819012307:image/*"
#          ],
#          "Condition" : {
#            "StringEquals" : {
#              "aws:ResourceTag/Vendor" : "Databricks"
#            }
#          }
#        },
#        {
#          "Sid" : "AllowEc2RunInstancePerVPCid",
#          "Effect" : "Allow",
#          "Action" : "ec2:RunInstances",
#          "Resource" : [
#            "arn:aws:ec2:eu-west-1:997819012307:network-interface/*",
#            "arn:aws:ec2:eu-west-1:997819012307:subnet/*",
#            "arn:aws:ec2:eu-west-1:997819012307:security-group/*"
#          ],
#          "Condition" : {
#            "StringEquals" : {
#              "ec2:vpc" : "arn:aws:ec2:eu-west-1:997819012307:vpc/${data.aws_vpc.existing_vpc.id}"
#            }
#          }
#        },
#        {
#          "Sid" : "AllowEc2RunInstanceOtherResources",
#          "Effect" : "Allow",
#          "Action" : "ec2:RunInstances",
#          "NotResource" : [
#            "arn:aws:ec2:eu-west-1:997819012307:image/*",
#            "arn:aws:ec2:eu-west-1:997819012307:network-interface/*",
#            "arn:aws:ec2:eu-west-1:997819012307:subnet/*",
#            "arn:aws:ec2:eu-west-1:997819012307:security-group/*",
#            "arn:aws:ec2:eu-west-1:997819012307:volume/*",
#            "arn:aws:ec2:eu-west-1:997819012307:instance/*"
#          ]
#        },
#        {
#          "Sid" : "EC2TerminateInstancesTag",
#          "Effect" : "Allow",
#          "Action" : [
#            "ec2:TerminateInstances"
#          ],
#          "Resource" : [
#            "arn:aws:ec2:eu-west-1:997819012307:instance/*"
#          ],
#          "Condition" : {
#            "StringEquals" : {
#              "ec2:ResourceTag/Vendor" : "Databricks"
#            }
#          }
#        },
#        {
#          "Sid" : "EC2AttachDetachVolumeTag",
#          "Effect" : "Allow",
#          "Action" : [
#            "ec2:AttachVolume",
#            "ec2:DetachVolume"
#          ],
#          "Resource" : [
#            "arn:aws:ec2:eu-west-1:997819012307:instance/*",
#            "arn:aws:ec2:eu-west-1:997819012307:volume/*"
#          ],
#          "Condition" : {
#            "StringEquals" : {
#              "ec2:ResourceTag/Vendor" : "Databricks"
#            }
#          }
#        },
#        {
#          "Sid" : "EC2CreateVolumeByTag",
#          "Effect" : "Allow",
#          "Action" : [
#            "ec2:CreateVolume"
#          ],
#          "Resource" : [
#            "arn:aws:ec2:eu-west-1:997819012307:volume/*"
#          ],
#          "Condition" : {
#            "StringEquals" : {
#              "aws:RequestTag/Vendor" : "Databricks"
#            }
#          }
#        },
#        {
#          "Sid" : "EC2DeleteVolumeByTag",
#          "Effect" : "Allow",
#          "Action" : [
#            "ec2:DeleteVolume"
#          ],
#          "Resource" : [
#            "arn:aws:ec2:eu-west-1:997819012307:volume/*"
#          ],
#          "Condition" : {
#            "StringEquals" : {
#              "ec2:ResourceTag/Vendor" : "Databricks"
#            }
#          }
#        },
#        {
#          "Effect" : "Allow",
#          "Action" : [
#            "iam:CreateServiceLinkedRole",
#            "iam:PutRolePolicy"
#          ],
#          "Resource" : "arn:aws:iam::*:role/aws-service-role/spot.amazonaws.com/AWSServiceRoleForEC2Spot",
#          "Condition" : {
#            "StringLike" : {
#              "iam:AWSServiceName" : "spot.amazonaws.com"
#            }
#          }
#        },
#        {
#          "Sid" : "VpcNonresourceSpecificActions",
#          "Effect" : "Allow",
#          "Action" : [
#            "ec2:AuthorizeSecurityGroupEgress",
#            "ec2:AuthorizeSecurityGroupIngress",
#            "ec2:RevokeSecurityGroupEgress",
#            "ec2:RevokeSecurityGroupIngress"
#          ],
#          "Resource" : "arn:aws:ec2:eu-west-1:997819012307:security-group/${aws_security_group.workspace_security_group.id}",
#          "Condition" : {
#            "StringEquals" : {
#              "ec2:vpc" : "arn:aws:ec2:eu-west-1:997819012307:vpc/${data.aws_vpc.existing_vpc.id}"
#            }
#          }
#        }
#      ]
#    }
#  )
#}

resource "databricks_mws_networks" "this" {
  provider           = databricks.mws
  account_id         = "0d26daa6-5e44-4c97-a497-ef015f91254a"
  network_name       = "akash-config-net"
  security_group_ids = [aws_security_group.workspace_security_group.id]
  subnet_ids         = [data.aws_subnet.create_private_subnet_1.id, data.aws_subnet.create_private_subnet_2.id]
  vpc_id             = data.aws_vpc.existing_vpc.id
}
resource "databricks_mws_credentials" "this" {
  provider         = databricks.mws
  account_id       = "0d26daa6-5e44-4c97-a497-ef015f91254a"
  credentials_name = "akash-config-cred"
  role_arn         = "arn:aws:iam::997819012307:role/akash-tf-crossacciam-byovpc1"
}
resource "databricks_mws_storage_configurations" "this" {
  provider                   = databricks.mws
  account_id                 = "0d26daa6-5e44-4c97-a497-ef015f91254a"
  storage_configuration_name = "akash-config-s3"
  bucket_name                = aws_s3_bucket.root_bucket.bucket
}
resource "databricks_mws_workspaces" "this" {
  provider       = databricks.mws
  account_id     = "0d26daa6-5e44-4c97-a497-ef015f91254a"
  workspace_name = "akash-test-ws-new"
  aws_region     = "eu-west-1"

  credentials_id           = databricks_mws_credentials.this.credentials_id
  storage_configuration_id = databricks_mws_storage_configurations.this.storage_configuration_id
  network_id               = databricks_mws_networks.this.network_id
}
