from typing import Iterator, Callable, Dict

from . import EscalationChecker

from principalmapper.common import Node
from ..common import Escalation


class StsEscalationChecker(EscalationChecker):
    #_user_escalations: Dict[str, Callable] = {}
    _role_escalations: Dict[str, Callable] = {}

    @classmethod
    def get_role_escalations(cls):
        return cls._role_escalations

    @classmethod
    def register_role_escalation(cls, func: Callable):
        """Register a user escalation checking function"""
        if func.__name__ in cls.get_role_escalations():
            raise UserWarning('The user function {} is registered twice'.format(func.__name__))
        cls._role_escalations[func.__name__] = func
        return func

    @classmethod
    def can_escalate_to_role(self, source: Node, dest: Node) -> Iterator[Escalation]:
        for name, func in self.get_role_escalations().items():
            escalation = func(source, dest)
            if escalation:
                yield escalation
            else:
                continue
