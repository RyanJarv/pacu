import itertools

import io
import os

from typing import Dict, List, Callable, Iterator

from modules.iam__pivot_v2.common import Escalation

from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.common import Node

USER_ESCALATIONS: Dict[str, Callable] = {}
ROLE_ESCALATIONS: Dict[str, Callable] = {}


class EscalationChecker(EdgeChecker):

    @staticmethod
    def escalations(cls, source: Iterator[Node], dest: Iterator[Node]) -> Iterator[Escalation]:
        """By default we call can_escalate_to_role and can_escalate_to_user for each source/dest
        you can override this and/or ignore both can_escalate_to_role and can_escalate_to_user
        if you want.
        """

    @staticmethod
    def filter_sources(dest: Node) -> bool:
        # TODO filter self
        return True

    @staticmethod
    def filter_dests(source: Node) -> bool:
        return True

    #@staticmethod
    def subclass_escalations(self, srcs: List[Node], dsts: List[Node]) -> Iterator[Escalation]:
        for sub_cls in self.__class__.__subclasses__():
            sub_cls: EscalationChecker

            # Use sub_cls's filters before we run product to avoid O(N^2) processing on the size of the node list.
            srcs = filter(sub_cls.filter_sources, srcs)
            dsts = filter(sub_cls.filter_dests, dsts)

            for source, dest in itertools.product(srcs, dsts):
                yield from sub_cls.escalations(source, dest)

    def return_edges(self, nodes: List[Node], output: io.StringIO = os.devnull, debug: bool = False) -> List[Escalation]:
        return self.subclass_escalations(nodes.copy(), nodes.copy())

    # This can be used by filter_* methods to drop dest nodes before testing explicit source/dest combinations
