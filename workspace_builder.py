# test
import fnmatch

from strings import create_new_vpc_and_components, vpc_data_source, create_subnet_vpc, subnet_data_source, \
    create_pub_rt_igw_ngw, create_pvt_rt_ngw, version, provider, bucket_policy, workspace_catalog_iam_role, \
    security_group, custom_with_default_restrictions, custom_with_detailed_restrictions, cross_acc_role, \
    databricks_network_config, databricks_credential_config, databricks_storage_config, create_databricks_workspace


def create_full_vpc():
    vpc_name = input("What is your VPC name? : ")
    vpc_cidr = input("What is your VPC CIDR? : ")
    region = input("Provide your region : ")
    az_1 = input("Provide your Availability zone 1 : ")
    az_2 = input("Provide your Availability zone 2 : ")
    private_subnet_cidr_1 = input("Provide CIDR value for 1st Private Subnet : ")
    private_subnet_cidr_2 = input("Provide CIDR value for 2nd Private Subnet : ")
    public_subnet_cidr_1 = input("Provide CIDR value for 1st Public Subnet : ")
    public_subnet_cidr_2 = input("Provide CIDR value for 2nd Public Subnet : ")
    nat_number = input("Do you wish to have 1 NAT Gateway per Availability Zone (Y/N)? ")
    single_nat_gateway = "true"
    one_nat_gateway_per_az = "false"
    if nat_number=="Y":
        single_nat_gateway = "false"
        one_nat_gateway_per_az = "true"
    final_prompt = create_new_vpc_and_components.format(vpc_name,vpc_cidr,az_1,az_2,private_subnet_cidr_1,private_subnet_cidr_2,public_subnet_cidr_1,public_subnet_cidr_2,single_nat_gateway,one_nat_gateway_per_az,region)
    # print(final_prompt)

    with open("script.tf", "w") as file:
        pass
    with open("script.tf", "a") as file:
        file.write(str(final_prompt).replace("{{", "{").replace("}}", "}"))

    print("VPC Configs Added")
    return region


def create_partial_vpc_resources():
    vpc_cidr = input("Choose from the list of required resources which does not exist and has to be created\n "
                     "1. 2 Private Subnets\n"
                     "2. 2 Public Subnets\n"
                     "Enter items separated by commas: ")
    items = vpc_cidr.split(',')
    if len(items) == 0:
        print("\nNo resources selected, thus assuming all the resources need to be created")
    else:
        print("\nresources to be created are", items)
        region = input("Provide the region for deployment : ")
        vpc_id = input("What is your VPC ID? : ")
        vpc = vpc_data_source.format(vpc_id)
        provider_f = provider.format(region)
        az_1 = input("Provide your Availability zone 1 : ")
        az_2 = input("Provide your Availability zone 2 : ")

        create_eip = ''
        create_nat_gateway_1 = ''
        create_nat_gateway_2 = ''
        create_private_route_table_1 = ''
        create_private_route_table_2 = ''
        create_pvt_rt_assoc_1 = ''
        create_pvt_rt_assoc_2 = ''
        internet_gateway = ''
        public_route_table = ''
        pub_1_rt_assoc = ''
        pub_2_rt_assoc = ''
        nat_gw_1 = ''
        nat_gw_2 = ''
        create_nat_route_1 = ''
        create_nat_route_2 = ''
        security_group_1 = security_group
        create_private = 0

        for i in items:
            if fnmatch.fnmatch(i, "*Public*"):
                public_subnet_1 = input("Provide CIDR value for 1st Public Subnet : ")
                create_public_subnet_1 = create_subnet_vpc.format("pub_1", public_subnet_1, az_1)
                public_subnet_2 = input("Provide CIDR value for 2nd Public Subnet : ")
                create_public_subnet_2 = create_subnet_vpc.format("pub_2", public_subnet_2, az_2)
                pvt_rt_1 = input(f"Provide the ID of route table connected with Private Subnet 1 : ")
                pvt_rt_2 = input(f"Provide the ID of route table connected with Private Subnet 2 : ")


            if fnmatch.fnmatch(i, "*Private*"):
                create_private = 1
                private_subnet_1 = input("Provide CIDR value for 1st Private Subnet : ")
                create_private_subnet_1 = create_subnet_vpc.format("pvt_1", private_subnet_1, az_1)
                private_subnet_2 = input("Provide CIDR value for 2nd Private Subnet : ")
                create_private_subnet_2 = create_subnet_vpc.format("pvt_2", private_subnet_2, az_2)
                nat_gw = input(f"Do you have existing NAT Gateways which can be used (Y/N) : ")
                if nat_gw == 'Y':
                    nat_gw_1 = input(f"Provide the ID of NAT Gateway to be connected with Private Subnet 1 : ")
                    nat_gw_2 = input(f"Provide the ID of NAT Gateway to be connected with Private Subnet 2 : ")

        variables_to_check = ['create_public_subnet_1',
                              'create_public_subnet_2','create_private_subnet_1', 'create_private_subnet_2']

        for var in variables_to_check:
            try:
                eval(var)
            except NameError:
                name = var[7:].replace("_", " ").title()
                subnet_id = input(f"Provide ID for {name} : ")
                globals()[var] = subnet_data_source.format(var, subnet_id)
                if var=="create_public_subnet_1":
                    create_eip,create_eip2, create_nat_gateway_1, create_nat_gateway_2, create_private_route_table_1, create_private_route_table_2, create_pvt_rt_assoc_1, create_pvt_rt_assoc_2 = create_pvt_rt_ngw(nat_gw_1,nat_gw_2)
                if var=="create_private_subnet_1":
                    internet_gateway, public_route_table, pub_1_rt_assoc, pub_2_rt_assoc, create_eip, create_eip2, create_nat_gateway_1, create_nat_gateway_2, create_private_route_table_1, create_private_route_table_2 = create_pub_rt_igw_ngw(pvt_rt_1,pvt_rt_2)
                final_vars = ['version','provider_f','vpc','create_public_subnet_1',
                              'create_public_subnet_2','create_private_subnet_1', 'create_private_subnet_2',
                      'create_eip','create_eip2', 'create_nat_gateway_1', 'create_nat_gateway_2', 'create_private_route_table_1', 'create_private_route_table_2', 'create_pvt_rt_assoc_1', 'create_pvt_rt_assoc_2',
                      'internet_gateway', 'public_route_table', 'pub_1_rt_assoc', 'pub_2_rt_assoc','security_group_1'
                      ]
        with open("script.tf", "w") as file:
            pass
        for i in final_vars:
            with open("script.tf", "a") as file:
                # Write variables to the file
                file.write(str((eval(i)).replace("{{", "{").replace("}}", "}")))
        print("File Overwritten")
    return region,create_private

def create_dbfs_root_bucket(databricks_id,aws_id):
    bucket_name = input("Provide the name of S3 bucket to be created : ")
    role_name = input("Provide the name for the IAM created for Unity Catalog : ")
    create_root_bucket = bucket_policy.format(bucket_name)
    uc_role = workspace_catalog_iam_role.format(role_name,databricks_id,aws_id,bucket_name)

    with open("script.tf", "a") as file:
        file.write(str(create_root_bucket).replace("{{", "{").replace("}}", "}"))
    with open("script.tf", "a") as file:
        file.write(str(uc_role).replace("{{", "{").replace("}}", "}"))

    print("Root bucket Configs and UC Role Added")
    return create_root_bucket

def create_cross_account_iam_role(partial_vpc,databricks_id,aws_id,region):
    # Define valid options
    valid_options = [
        "Customer-managed VPC with default restrictions",
        "Customer-managed VPC with custom restrictions"
    ]

    # Loop until valid input is provided
    while True:
        policy_to_use = input("Provide the type of IAM policy to be used \n"
                              "1. Customer-managed VPC with default restrictions\n"
                              "2. Customer-managed VPC with custom restrictions\n"
                              "Please enter the full option name: ")

        # Check if the input matches one of the valid options
        if policy_to_use in valid_options:
            break  # Exit the loop if valid input is provided
        else:
            print("Invalid option. Please enter one of the specified options.")

    # Continue with the script using the valid input
    print(f"You selected: {policy_to_use}")
    if policy_to_use == "Customer-managed VPC with default restrictions":
        role = cross_acc_role.format(databricks_id,custom_with_default_restrictions)

    else:
        if partial_vpc==0:
            vpc_id = "{module.vpc.vpc_id}"
            sec_grp_id = "{aws_security_group.workspace_security_group.id}"
            custom_with_detailed_restrictions_policy = custom_with_detailed_restrictions.format(region,aws_id,vpc_id,sec_grp_id)
            role = cross_acc_role.format(databricks_id, custom_with_detailed_restrictions_policy)
        else:
            vpc_id = "{data.aws_vpc.existing_vpc.id}"
            sec_grp_id = "{aws_security_group.workspace_security_group.id}"
            custom_with_detailed_restrictions_policy = custom_with_detailed_restrictions.format(region, aws_id, vpc_id,
                                                                                                sec_grp_id)
            role = cross_acc_role.format(databricks_id, custom_with_detailed_restrictions_policy)
    with open("script.tf", "a") as file:
        file.write(str(role).replace("{{", "{").replace("}}", "}"))

    print("IAM Role Added")

def create_databricks_configs(partial_vpc,databricks_id,aws_id,region,create_private):
    if partial_vpc == 0:
        net_config_name = input("Provide a name for your Network Configuration")
        vpc_id = "{module.vpc.vpc_id}"
        sec_grp_id = "{aws_security_group.workspace_security_group.id}"
        pvt_subnets = "module.vpc.private_subnets"
        custom_with_detailed_restrictions_policy = custom_with_detailed_restrictions.format(databricks_id, net_config_name, sec_grp_id,pvt_subnets, vpc_id)
        role = cross_acc_role.format(databricks_id, custom_with_detailed_restrictions_policy)
    else:
        net_config_name = input("Provide a name for your Network Configuration")
        vpc_id = "{data.aws_vpc.existing_vpc.id}"
        sec_grp_id = "{aws_security_group.workspace_security_group.id}"
        if create_private==0:
            pvt_subnets = ["{data.aws_subnet.create_private_subnet_1.id}", "{data.aws_subnet.create_private_subnet_2.id}"]
            network_configuration = databricks_network_config.format(databricks_id, net_config_name, sec_grp_id,pvt_subnets, vpc_id)
        else:
            pvt_subnets = ["{aws_subnet.pvt_1.id}","{aws_subnet.pvt_2.id}"]
            network_configuration = databricks_network_config.format(databricks_id,net_config_name,sec_grp_id, pvt_subnets,vpc_id)

    with open("script.tf", "a") as file:
        file.write(str(network_configuration).replace("{{", "{").replace("}}", "}"))

def create_databricks_network_configs(partial_vpc,databricks_id,create_private):
    network_configuration = ''
    if partial_vpc == 0:
        net_config_name = input("Provide a name for your Network Configuration : ")
        vpc_id = "module.vpc.vpc_id"
        sec_grp_id = "aws_security_group.workspace_security_group.id"
        pvt_subnets = "module.vpc.private_subnets"
        network_configuration = databricks_network_config.format(databricks_id, net_config_name, sec_grp_id,pvt_subnets, vpc_id)
    else:
        net_config_name = input("Provide a name for your Network Configuration : ")
        vpc_id = "data.aws_vpc.existing_vpc.id"
        sec_grp_id = "aws_security_group.workspace_security_group.id"
        if create_private==0:
            pvt_subnets = ["data.aws_subnet.create_private_subnet_1.id", "data.aws_subnet.create_private_subnet_2.id"]
            network_configuration = databricks_network_config.format(databricks_id, net_config_name, sec_grp_id,pvt_subnets[0].replace('"', ''),pvt_subnets[1].replace('"', ''), vpc_id)
        else:
            pvt_subnets = ["aws_subnet.pvt_1.id","aws_subnet.pvt_2.id"]
            network_configuration = databricks_network_config.format(databricks_id,net_config_name,sec_grp_id, pvt_subnets[0].replace('"', ''),pvt_subnets[1].replace('"', ''),vpc_id)
    with open("script.tf", "a") as file:
        file.write(str(network_configuration).replace("{{", "{").replace("}}", "}"))
    return None

def create_credential_configs(account_id):

    cred_conf_name = input("Please provide a name for your Credential Configuration : ")
    final_conf = databricks_credential_config.format(account_id,cred_conf_name)
    with open("script.tf", "a") as file:
        file.write(str(final_conf).replace("{{", "{").replace("}}", "}"))
    return None

def create_storage_configs(account_id):

    cred_conf_name = input("Please provide a name for your Storage Configuration : ")
    final_conf = databricks_storage_config.format(account_id,cred_conf_name)
    with open("script.tf", "a") as file:
        file.write(str(final_conf).replace("{{", "{").replace("}}", "}"))
    return None

def create_workspace(account_id,region):

    workspace_name = input("Please provide a name for your Workspace : ")
    final_conf = create_databricks_workspace.format(account_id,workspace_name,region)
    with open("script.tf", "a") as file:
        file.write(str(final_conf).replace("{{", "{").replace("}}", "}"))
    return None


