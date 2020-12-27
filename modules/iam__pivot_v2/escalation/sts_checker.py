from dataclasses import dataclass, field
from typing import Iterator, List

from principalmapper.querying.local_policy_simulation import policies_include_matching_allow_action, policy_has_matching_statement
from . import EscalationChecker

from principalmapper.common import Node, Policy
from ..common import Escalation


policy_allow_all = Policy("arn:aws:iam::922105094392:policy/policy_allow_all", "policy_allow_all", {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::*:role/*"
            },
            "Action": "sts:AssumeRole"
        }
    ]
})


class StsEscalationChecker(EscalationChecker):

    @classmethod
    def escalations(cls, source: Node, dest: Node) -> Iterator[Escalation]:
        for sub_cls in cls.__subclasses__():
            yield from sub_cls.escalations()

    @staticmethod
    def filter_sources(source: Node) -> bool:
        """ Uses the Config dataclass to filter nodes from being sent to subclasses, filtering is done in the base class
        to avoid O(N^2) processing on the size of the node list.
        """
        return policies_include_matching_allow_action(source, 'sts:AssumeRole')

    @staticmethod
    def filter_dests(dest: Node) -> bool:
        if policy_has_matching_statement(policy_allow_all, 'Allow', 'sts:AssumeRole', dest, {}) \
                and not policy_has_matching_statement(policy_allow_all, 'Deny', 'sts:AssumeRole', dest, {}) \
                and ':user/' not in dest.arn:
            return True
        else:
            return False
