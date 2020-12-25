from dataclasses import dataclass, field
from typing import Iterator, Callable, Dict, Optional, List

from principalmapper.querying import query_interface
from principalmapper.querying.local_policy_simulation import ResourcePolicyEvalResult, has_matching_statement, \
    policies_include_matching_allow_action, policy_has_matching_statement
from principalmapper.util import arns
from . import EscalationChecker, resource_policy_auth

from principalmapper.common import Node
from ..common import Escalation


@dataclass
class Config:
    """Class for keeping track of an item in inventory."""
    ResourceActions: List[str] = field(default=[])
    PolicyActions: List[str] = field(default=[])


class StsEscalationChecker(EscalationChecker):
    config = Config()

    @classmethod
    def escalations(cls, source: Node, dest: Node) -> Iterator[Escalation]:
        if ':/user' in source.arn:
            return iter([])
        for sub in cls.subclass_escalations:
            sub: StsEscalationChecker
            sub.filter

    def filter_sources(cls, source: Node) -> bool:
        """ Uses the Config dataclass to filter nodes from being sent to subclasses, filtering is done in the base class
        to avoid O(N^2) processing on the size of the node list.
        """
        for action in cls.config.ResourceActions:
            return not policies_include_matching_allow_action(source, action.Action)

    def filter_dests(cls, dest: Node) -> bool:
        if policy_has_matching_statement(cls.match_all_trust_policy, 'Allow', 'sts:AssumeRole', dest, {}) \
                and not policy_has_matching_statement(cls.match_all_trust_policy, 'Deny', 'sts:AssumeRole', dest, {}) \
                and not ':/user' in dest.arn:
            return False
