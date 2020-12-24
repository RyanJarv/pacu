from typing import Iterator, Dict, Callable

from . import EscalationChecker

from principalmapper.common import Node
from ..common import Escalation


class IamEscalationChecker(EscalationChecker):
    _user_escalations: Dict[str, Callable] = {}
    _role_escalations: Dict[str, Callable] = {}

    @classmethod
    def get_user_escalations(cls):
        return cls._user_escalations

    @classmethod
    def get_role_escalations(cls):
        return cls._role_escalations

    @classmethod
    def register_user_escalation(cls, func: Callable):
        """Register a user escalation checking function"""
        if func.__name__ in cls.get_user_escalations():
            raise UserWarning('The user function {} is registered twice'.format(func.__name__))
        cls._user_escalations[func.__name__] = func
        return func

    @classmethod
    def register_role_escalation(cls, func: Callable):
        """Register a user escalation checking function"""
        if func.__name__ in cls.get_role_escalations():
            raise UserWarning('The user function {} is registered twice'.format(func.__name__))
        cls._role_escalations[func.__name__] = func
        return func
