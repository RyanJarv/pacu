# Mostly copied from an example for now
from typing import List

from botocore.exceptions import ClientError
from principalmapper.analysis.finding import Finding
from principalmapper.common import Graph, Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface
from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult
from principalmapper.querying.presets import connected
from principalmapper.util import arns

class PacuFinding(Finding):
    def __init__(self, title: str, severity: str, impact: str, description: str, exploit: typing.Callable, recommendation: str):
        super()
        self.exploit = exploit

    def exploit(self):
        self.exploit()

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
