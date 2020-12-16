#!/usr/bin/env python3
import argparse
import collections
import typing
from typing import List, TypedDict
from venv import create

import boto3
import botocore.session
import botocore.client
from principalmapper.common import Node, Graph, Edge
from principalmapper.graphing import graph_actions
from principalmapper.querying.query_utils import get_search_list

# When writing a module, feel free to remove any comments, placeholders, or
# anything else that doesn't relate to your module.

module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'iam_pivot',

    # Name and any other notes about the author
    'author': 'Ryan Gerstenkorn',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ESCALATE',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Pivots current user based on IAM data.',

    # Description about what the module does and how it works
    'description': '''
Updates aws_key info based on existing data found through other modules. Currently this looks for roles that can
be assumed and allows you to pivot to them for the current user.
    '''.replace("\n", ""),

    # A list of AWS services that the module utilizes during its execution
    'services': ['IAM'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],
}

# Every module must include an ArgumentParser named "parser", even if it
# doesn't use any additional arguments.
parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])


# Main is the first function that is called when this module is executed.
def sess_from_h(user) -> boto3.session.Session:
    return boto3.session.Session(aws_access_key_id=user['AccessKeyId'], aws_secret_access_key=user['SecretAccessKey'],
                                 aws_session_token=user['SessionToken'])


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### These can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    input = pacu_main.input
    key_info = pacu_main.key_info
    fetch_data = pacu_main.fetch_data
    get_regions = pacu_main.get_regions
    install_dependencies = pacu_main.install_dependencies
    ######

    # Use the print and input functions as you normally would. They have been
    # modified to log the data to a history file as well as to the console.

    # key_info fetches information for the currently active set of keys. This
    # returns a dictionary containing information about the AWS key using the
    # session's current key_alias, which includes info like User Name,
    # User Arn, User Id, Account Id, the permissions collected so far for the
    # user, the groups they are a part of, access key id, secret access key,
    # session token, key alias, and a note.
    user = key_info()

    # fetch_data is used when there is a prerequisite module to the current
    # module. The example below shows how to fetch all EC2 security group data
    # to use in this module.
    # This check will be false if the user declines to run the pre-requisite
    # module or it fails. Depending on the module, you may still want to
    # continue execution, so building the check is on you as a developer.
    # if fetch_data(['IAM'], 'iam_enum_permissions', '') is False:
    #     print('Pre-req module not run successfully. Exiting...')
    #     return

    sess = sess_from_h(user)

    root = 'sessions/demo/pmmapper'
    try:
        graph_obj = graph_actions.get_graph_from_disk(root)
    except ValueError:
        graph_obj = graph_actions.create_new_graph(sess._session, ['iam', 'sts'])
        graph_obj.store_graph_as_json(root)

    if user["UserName"]:
        source_name = 'user/{}'.format(user["UserName"])
    elif user["RoleName"]:
        source_name = 'role/{}'.format(user["RoleName"])
    else:
        raise UserWarning("No current user or role found")

    source_node = graph_obj.get_node_by_searchable_name(source_name)

    data = connected_results(graph_obj, source_node, graph_obj.nodes)
    data = collections.OrderedDict(data)
    if not data:
        return False

    for i in range(len(data)):
        dest: Node = list(data.keys())[i]
        print("    ({}) {}\n".format(i, dest.arn))

    response = int(input("Choose role to assume: "))
    target = list(data.keys())[response]

    for role in data[target]:
        print("Assuming Role: " + role.destination.arn)
        creds = sess.client('sts').assume_role(RoleArn=role.destination.arn, RoleSessionName="pacu")['Credentials']
        sess = sess_from_h(creds)
        pacu_main.set_keys(role.destination.searchable_name(), creds['AccessKeyId'], creds['SecretAccessKey'],
                           creds['SessionToken'])

    # Make sure your main function returns whatever data you need to construct
    # a module summary string.
    return target


# The summary function will be called by Pacu after running main, and will be
# passed the data returned from main. It should return a single string
# containing a curated summary of every significant thing that the module did,
# whether successful or not; or None if the module exited early and made no
# changes that warrant a summary being displayed. The data parameter can
# contain whatever data is needed in any structure desired. A length limit of
# 1000 characters is enforced on strings returned by module summary functions.
def summary(data, pacu_main):
    return "KeyAlias: {} RoleArn: {}".format(pacu_main.key_info()["KeyAlias"], data.arn)

def connected_results(graph: Graph, source_node: Node, dest_nodes: List[Node]) -> typing.Dict[Node, List[Edge]]:
    results = {}
    """Handles a `connected` query and writes the results to output"""
    for dnode in dest_nodes:
        connection_result, path = is_connected(graph, source_node, dnode)
        if connection_result:
            # print the data
            results[dnode] = [edge for edge in path]
    return results


def is_connected(graph: Graph, source_node: Node, dest_node: Node) -> (bool, List[Edge]):
    """Method for determining if a source node can reach a destination node through edges. The return value is a
    bool, List[Edge] tuple indicating if there's a connection and the path the source node would need to take.
    """
    edge_lists = get_search_list(graph, source_node)
    for edge_list in edge_lists:
        final_node = edge_list[-1].destination
        if final_node == dest_node:
            return True, edge_list

    return False, None
