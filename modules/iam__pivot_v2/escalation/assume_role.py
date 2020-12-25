from typing import Iterator

import mypy_boto3_sts

from modules.iam__pivot_v2.common import Escalation
from .sts_checker import StsEscalationChecker

from principalmapper.querying import query_interface as query
from principalmapper.querying.local_policy_simulation import resource_policy_authorization as resource_policy_auth
from principalmapper.querying.query_interface import Node, ResourcePolicyEvalResult, has_matching_statement
from principalmapper.util import arns


class AssumeRole(StsEscalationChecker):
    def run(self, pacu_main, target):
        print("Assuming Role: " + target.arn)
        sts: mypy_boto3_sts.client.STSClient = pacu_main.get_boto3_client('sts')
        creds = sts.assume_role(RoleArn=target.arn, RoleSessionName="pacu")['Credentials']
        pacu_main.set_keys(target.searchable_name(), creds['AccessKeyId'], creds['SecretAccessKey'],
                           creds['SessionToken'])

    @classmethod
    def escalations(cls, source: Node, dest: Node) -> Iterator[Escalation]:
        # Check against resource policy
        sim_result = resource_policy_auth(source, arns.get_account_id(source.arn), dest.trust_policy, 'sts:AssumeRole', dest.arn, {})

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
