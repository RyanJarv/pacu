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

from principalmapper.querying.presets.privesc import can_privesc

#import findings

from principalmapper.analysis.finding import Finding
from principalmapper.common import Graph, Node
from principalmapper.graphing import graph_actions
from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult, has_matching_statement
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


# def main(args, pacu_main):
#     session = pacu_main.get_active_session()
#
#     ###### Don't modify these. They can be removed if you are not using the function.
#     args = parser.parse_args(args)
#     print = pacu_main.print
#     input = pacu_main.input
#     key_info = pacu_main.key_info
#     fetch_data = pacu_main.fetch_data
#     ######
#
#     summary_data = {'scan_only': args.scan_only}
#
#     root = 'sessions/demo/pmmapper'
#     graph = graph_actions.get_graph_from_disk(root)
#
#     user = key_info()
#
#     if user["UserName"]:
#         source_name = 'user/{}'.format(user["UserName"])
#     elif user["RoleName"]:
#         source_name = 'role/{}'.format(user["RoleName"])
#     else:
#         raise UserWarning("No current user or role found")
#
#     #source_node = graph_obj.get_node_by_searchable_name(source_name)
#
#     privesc, edge_list = can_privesc(graph, source_node)
#     if privesc:
#         end_of_list = edge_list[-1].destination
#         # the node can access this admin node through the current edge list, print this info out
#         os.stdout.write('{} can escalate privileges by accessing the administrative principal {}:\n'.format(
#             source_node.searchable_name(), end_of_list.searchable_name()))
#         for edge in edge_list:
#             os.stdout.write('   {}\n'.format(edge.describe_edge()))
#
#     # results : List[findings.PacuFinding] = []
#     # results.extend(findings.gen_overprivileged_function_findings(current_node, graph))
#     #
#     # for result in results:
#     #     summary_data[result.title] = result.exploit(pacu_main, print, input, fetch_data)
#     #
#     # return summary_data
#
#
#
# def summary(data, pacu_main):
#     print()
#     if data['scan_only']:
#         return '  Scan Complete'
#     elif 'offline' in data and data['offline']:
#         return '  Completed offline scan of:\n    ./{}\n\n  Results stored in:\n    {}'.format(
#             data['offline']['scanned_dir'], data['offline']['output_file'])
#     else:
#         if 'success' in data and data['success']:
#             out = '  Privilege escalation was successful'
#         else:
#             out = '  Privilege escalation was not successful'
#     return out
#
