import collections
import io
import os
import sys

from typing import Dict, List, Callable, Generator, Iterator
from abc import abstractmethod

from modules.iam__pivot_v2.common import Escalation
from modules.iam__pivot_v3.common.escalation import Resource

from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.common import Node

USER_ESCALATIONS: Dict[str, Callable] = {}
ROLE_ESCALATIONS: Dict[str, Callable] = {}


class EscalationChecker(Resource):

    @classmethod
    def get_role_escalations(cls):
        return {}

    @classmethod
    def get_user_escalations(cls):
        return {}

    @classmethod
    def can_escalate_to_role(self, source: Node, dest: Node) -> Iterator[Escalation]:
        """This can be overridden by the subclass to handle escalations where the destination
        is a role. If this isn't overridden we ignore all possible escalations that target
         a role.
        """
        return iter([])

    @classmethod
    def can_escalate_to_user(self, source: Node, dest: Node) -> Iterator[Escalation]:
        """Same as can_escalate_to_role but for user targets."""
        return iter([])

    @classmethod
    def can_escalate(self, source: Node, dest: Node) -> Iterator[Escalation]:
        """By default we call can_escalate_to_role and can_escalate_to_user for each source/dest
        you can override this and/or ignore both can_escalate_to_role and can_escalate_to_user
        if you want.
        """

        if ':user/' in dest.arn:
            for escalation in self.can_escalate_to_user(source, dest):
                yield escalation
        else:
            if ':role/' not in dest.arn:
                print("The ARN {} doesn't seem to be a user or a role, we'll treat it as a role though")
            for escalation in self.can_escalate_to_role(source, dest):
                yield escalation

