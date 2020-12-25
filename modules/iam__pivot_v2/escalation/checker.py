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
    def filter_sources(cls, dest: Node) -> bool:
        # TODO filter self
        return False

    def filter_dests(cls, source: Node) -> bool:
        return False

    @staticmethod
    def subclass_escalations(cls, srcs: List[Node], dsts: List[Node]) -> Iterator[Escalation]:
        for sub_cls in cls.__subclasses__():
            sub_cls: EscalationChecker

            # Use sub_cls's filters before we run product to avoid O(N^2) processing on the size of the node list.
            srcs = itertools.dropwhile(sub_cls.filter_sources(srcs))
            dsts = itertools.dropwhile(sub_cls.filter_dests(dsts))

            for source, dest in itertools.product(srcs, dsts):
                yield from sub_cls.escalations(source, dest)

    def return_edges(self, nodes: List[Node], output: io.StringIO = os.devnull, debug: bool = False) -> List[Escalation]:
        self.subclass_escalations(nodes.copy(), nodes.copy())

    # This can be used by filter_* methods to drop dest nodes before testing explicit source/dest combinations
    policy_allow_all = """{
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
    }"""
