from typing import Iterator

from principalmapper.querying.local_policy_simulation import policies_include_matching_allow_action, policy_has_matching_statement

from principalmapper.common import Node, Policy
from .escalation_checker import EscalationChecker
from ..common import Escalation

# class StsEscalationChecker(EscalationChecker):
#     def escalations(self, source: Node, dest: Node) -> Iterator[Escalation]:
#         for sub_cls in self.__class__.__subclasses__():
#             sub_inst = sub_cls(self.session)
#             yield from sub_inst.escalations(source, dest)
#
    # def filter_sources(self, source: Node) -> bool:
    #     """ Uses the Config dataclass to filter nodes from being sent to subclasses, filtering is done in the base class
    #     to avoid O(N^2) processing on the size of the node list.
    #     """
    #     return policies_include_matching_allow_action(source, 'sts:AssumeRole')
    #
    # def filter_dests(self, dest: Node) -> bool:
    #     if policy_has_matching_statement(policy_allow_all, 'Allow', 'sts:AssumeRole', dest, {}) \
    #             and not policy_has_matching_statement(policy_allow_all, 'Deny', 'sts:AssumeRole', dest, {}) \
    #             and ':user/' not in dest.arn:
    #         return True
    #     else:
    #         return False
