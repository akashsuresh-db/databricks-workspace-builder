from workspace_builder import create_full_vpc, create_partial_vpc_resources, create_dbfs_root_bucket, \
    create_cross_account_iam_role, create_databricks_network_configs, create_credential_configs, create_storage_configs, \
    create_workspace


def main():

    create_full_vpc_stack = input("Do you wish to create the VPC from scratch with all the resources required? (Y/N) : ")
    create_private = 0
    if create_full_vpc_stack == "Y":
        region = create_full_vpc()
        partial_vpc = 0
    else:
        region,create_private = create_partial_vpc_resources()
        partial_vpc = 1

    databricks_id = input("Provide the Databricks External ID : ")
    aws_id = input("Provide the AWS Account ID : ")
    create_dbfs_root_bucket(databricks_id,aws_id)
    create_cross_account_iam_role(partial_vpc,databricks_id, aws_id, region)

    #creating Databricks Network configuration
    create_databricks_network_configs(partial_vpc,databricks_id,create_private)

    # creating Databricks Credential configuration
    create_credential_configs(databricks_id)

    # creating Databricks Storage configuration
    create_storage_configs(databricks_id)

    # creating Databricks Workspace
    create_workspace(databricks_id,region)


if __name__ == '__main__':
    main()










