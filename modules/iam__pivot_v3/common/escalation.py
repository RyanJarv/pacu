import io
import os
from abc import abstractmethod
from typing import Callable, Iterator, List
from __future__ import annotations

import botocore

from modules.iam__pivot_v3.escalation import EscalationChecker
from principalmapper.common import Edge, Node
from principalmapper.graphing.edge_checker import EdgeChecker


# EdgeChecker represents
class Searcher(EdgeChecker, Edge):
    _registered_resources = []

    def __init__(self, session: botocore.session.Session):
        """Creating a object through the __init__ function happens in PMapper when it's using this as an EdgeChecker
        class when we register it in the edge_checker map.
        """
        super(EdgeChecker).__init__(session)
        self.num = 0

    def __next__(self):
        if self.num < len(self._registered_resources):
            cur, self.num = self._registered_resources[self.num], self.num + 1
            return cur
        raise StopIteration

    def new(self, *args, **kargs):
        super(Edge).__init__(*args, **kargs)
        # Edge refers to this as the destination, since an edge represents an escalation path this makes sense there.
        # Likewise in the context of the self.run_escalation code we'll use self.destination otherwise self.this.
        resource = self.__class__(self.session)
        self._registered_resources = resource.new(*args, **kargs)
        return resource

    def run_escalation(self, *args, **kwargs):
        self.escalate_func(*args, **kwargs)

    @classmethod
    def return_edges(self, nodes: List[Node], output: io.StringIO = io.StringIO(os.devnull), debug: bool = False) -> List[Resource]:
        """Fulfills expected method return_edges. If session object is None, runs checks in offline mode."""
        edges = []
        for resource in self._registered_resources:
            edges += resource.return_edges(nodes)
        return edges

class Escalation(Searcher):
    def __init__(self, source, dest):
        self.source = source
        self.source = dest
        self.new(source, dest)

    def run(self, *args, **kwargs):
        kwargs["source"] = self.source
        kwargs["target"] = self.destination
        self.run(*args, **kwargs)

    def return_edges(self, nodes: List[Node], output: io.StringIO = io.StringIO(os.devnull), debug: bool = False) -> List[Resource]:
        """Fulfills expected method return_edges. If session object is None, runs checks in offline mode."""
        edges = []
        for resource in self._registered_resources:
            edges += resource.return_edges(nodes)
        return edges
