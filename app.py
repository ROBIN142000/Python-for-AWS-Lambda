import json
import requests
import boto3
import ipaddress
from botocore.exceptions import ClientError

ec2 = boto3.client('ec2')


def lambda_handler(event, context):
    # Getting the security group ID
    # Change security group id with the id of the security group which you want to update
    security_group_id = 'sg-04b580e14e500f1e6'

    # Getting security group rules.
    #This step will store all the information related to security group rules.
    #This step is necessary as we have to delete all the previous rule since we can add limited number of rules, in security group.
    group_rules = ec2.describe_security_group_rules(Filters=[{'Name': 'group-id', 'Values': [security_group_id]}],
                                                    MaxResults=1000)

    # Every security group rule have a id of its own called security group rules id.
    # Storing security group rules id in rule_ids variable.
    # We will need these rules id to delete the rules.
    rule_ids = [rule['SecurityGroupRuleId'] for rule in group_rules['SecurityGroupRules']]

    # Deleting previous ingress or inbound rules of security group with the help of rules id.
    # When all the ingress or inbound rule will be deleted, the list will start putting egress or outbound rules id
    # in this revoke method, but there is different method to revoke inbound and outbound rule. we are only deleting
    # ingress or inbound rules, so we have put the method to revoke inbound rules in try block, when outbound rules id
    # get put in method, program will generate an error which will be handled in except block
    for rule_id in rule_ids:
        try:
            ec2.revoke_security_group_ingress(GroupId=security_group_id, SecurityGroupRuleIds=[rule_id])
        except ClientError:
            continue

    # Getting GitGub web block from the site and storing it in github_ips_web variable
    github_ips_web = requests.get('https://api.github.com/meta').json()['web']
    # Getting ip addresses from github_ips_web variable and storing it in cidr_blocks_web
    cidr_blocks_web = [f"{ip}" for ip in github_ips_web]

    # Getting GitGub api block from the site and storing it in github_ips_api variable
    github_ips_api = requests.get('https://api.github.com/meta').json()['api']
    # Getting ip addresses from github_ips_api variable and storing it in cidr_blocks_api
    cidr_blocks_api = [f"{ip}" for ip in github_ips_api]


    # Authorize inbound traffic for each IP address in web block.
    # Try block is for ipv4 cidr addresses  and except block is for ipv6 cidr addresses.
    # I have to put in try and except block because GitHub uses both ipv4 and ipv6 cidr addresses but in boto3 client
    # we have different method for adding the ipv4 and ipv6 cidr addresses so if we try to add ipv6 cidr address in the
    # method used for adding ipv4 cidr address we would get error and program will fail. So i am using a python module
    # named "ipaddress" which will take ip cidr address and give an error if its ipv6 cidr address, this error will get
    # handled in except block which has function to add ipv6 cidr address.
    # I am setting connection to ssh port 22, you can set connection as per your need.
    for cidr_block_web in cidr_blocks_web:

        try:
            ipaddress.IPv4Network(cidr_block_web)
            ip_permission = {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': cidr_block_web, 'Description': 'This ip is of github web block'}]
            }
        except ValueError:
            ip_permission = {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'Ipv6Ranges': [{'CidrIpv6': cidr_block_web, 'Description': 'This ip is of github web block'}]
            }
        ec2.authorize_security_group_ingress(GroupId=security_group_id, IpPermissions=[ip_permission])

    # Authorize inbound traffic for each IP address cidr in api block.
    # Try block is for ipv4 cidr addresses  and except block is for ipv6 cidr addresses.
    # I have to put in try and except block because GitHub uses both ipv4 and ipv6 cidr addresses but in boto3 client
    # we have different method for adding the ipv4 and ipv6 cidr addresses so if we try to add ipv6 cidr address in the
    # method used for adding ipv4 cidr address we would get error and program will fail. So i am using a python module
    # named "ipaddress" which will take ip cidr address and give an error if its ipv6 cidr address, this error will get
    # handled in except block which has function to add ipv6 cidr address.
    # I am setting connection to ssh port 22, you can set connection as per your need.
    for cidr_block_api in cidr_blocks_api:

        try:
            ipaddress.IPv4Network(cidr_block_api)
            ip_permission = {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': cidr_block_api, 'Description': 'This ip is of github api block'}]
            }
        except ValueError:
            ip_permission = {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'Ipv6Ranges': [{'CidrIpv6': cidr_block_api, 'Description': 'This ip is of github api block'}]
            }

        # Now GitHub may be using same ip address cidr in two or more service blocks, in our case there may be a case
        # where GitHub may be using same ip cidr address in web and api block. In this case a situation will arise
        # where an address is getting added again in security group rule which will generate error. So below in try and
        # except block we are handling this situation, if error arises it will be handled in except block.
        try:
            ec2.authorize_security_group_ingress(GroupId=security_group_id, IpPermissions=[ip_permission])
        except ClientError:
            continue

    # When the program gets run successfully it will return this function.
    # "The security group ingress rules has been successfully updated with latest ip addresses of github services" will
    # be displayed.
    return {
        'statusCode': 200,
        'body': json.dumps(
            'The security group ingress rules has been successfully updated with latest ip addresses of github services')
    }