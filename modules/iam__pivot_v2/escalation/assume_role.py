from typing import Optional, Iterator

import boto3
import mypy_boto3_sts
from boto.ec2.volumestatus import Action

from modules.iam__pivot_v2.common import Escalation
from .sts_checker import StsEscalationChecker, Filter, Action, ResourceAction, PolicyAction

from principalmapper.querying import query_interface as query
from principalmapper.querying.local_policy_simulation import resource_policy_authorization as resource_policy_auth, \
    policy_has_matching_statement
from principalmapper.querying.query_interface import Node, ResourcePolicyEvalResult, \
    has_matching_statement
from principalmapper.util import arns


class AssumeRole(StsEscalationChecker):
    def run(self, pacu_main, target):
        print("Assuming Role: " + target.arn)
        sts: mypy_boto3_sts.client.STSClient = pacu_main.get_boto3_client('sts')
        creds = sts.assume_role(RoleArn=target.arn, RoleSessionName="pacu")['Credentials']
        pacu_main.set_keys(target.searchable_name(), creds['AccessKeyId'], creds['SecretAccessKey'],
                           creds['SessionToken'])

    # filter = Filter(
    #     # NO_MATCH is filtered since resource policy must match for sts:AssumeRole, even in same-account scenarios
    #     # TODO: verify this behavior
    #     ResourceAction(Action='sts:AssumeRole', FilterOn=[
    #         ResourcePolicyEvalResult.DENY_MATCH,
    #         ResourcePolicyEvalResult.NO_MATCH
    #     ]),
    #     PolicyAction(Action='sts:AssumeRole', ConditionKeys={
    #         'aws:MultiFactorAuthAge': '1',
    #         'aws:MultiFactorAuthPresent': 'true'
    #     })
    # )

    @staticmethod
    def filter_sources(node: Node) -> bool:
        return query.local_check_authorization(node, 'sts:AssumeRole', '*', {})

    @staticmethod
    def filter_dests(node: Node) -> bool:
        return query.resource_policy_authorization(node, '*', ) \
               and policy_has_matching_statement(node.trust_policy, 'sts:AssumeRole', 'Allow', '*', {})
        node.trust_policy

    @classmethod
    def escalations(cls, source: Node, dest: Node) -> Iterator[Escalation]:
        # Check against resource policy
        policy_denies_mfa = has_matching_statement(source, 'Deny', 'sts:AssumeRole', dest.arn, {
            'aws:MultiFactorAuthAge': '1',
            'aws:MultiFactorAuthPresent': 'true'
        })

        assume_auth, need_mfa = query.local_check_authorization_handling_mfa(source, 'sts:AssumeRole', dest.arn, {})
        policy_denies = has_matching_statement(source, 'Deny', 'sts:AssumeRole', dest.arn, {})
        policy_denies_mfa = has_matching_statement(source, 'Deny', 'sts:AssumeRole', dest.arn, {
            'aws:MultiFactorAuthAge': '1',
            'aws:MultiFactorAuthPresent': 'true'
        })
        if assume_auth:
            if need_mfa:
                reason = '(requires MFA) can access via sts:AssumeRole'
            else:
                reason = 'can access via sts:AssumeRole'

            new_esc = Escalation(source, dest, escalate_func=AssumeRole, reason=reason)
            print('Found new edge: {}\n'.format(new_esc.describe_edge()))
            yield new_esc
        elif not (policy_denies_mfa and policy_denies) and sim_result == ResourcePolicyEvalResult.NODE_MATCH:
            # testing same-account scenario, so NODE_MATCH will override a lack of an allow from iam policy
            new_esc = Escalation(source, dest, escalate_func=NotImplementedError,
                                 reason='can access via sts:AssumeRole')
            print('Found new edge: {}\n'.format(new_esc.describe_edge()))

            yield new_esc
