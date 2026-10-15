"""Deterministic fact DAG validation and bounded-memory relevance ordering."""
from __future__ import annotations

import heapq
import math
import re
from collections import Counter
from typing import AbstractSet, Iterable, Mapping, Sequence

from .errors import ReCTMError


class FactGraph:
    def __init__(self, predecessors: Mapping[str, Iterable[str]],
                 revoked: AbstractSet[str] = frozenset()) -> None:
        self.predecessors = {key: frozenset(value) for key, value in sorted(predecessors.items())}
        self.successors: dict[str, set[str]] = {key: set() for key in self.predecessors}
        remaining = {}
        for key, values in self.predecessors.items():
            if key in revoked:
                raise _invalid("Revoked fact cannot enter an active graph.")
            for value in values:
                if value in revoked or value not in self.predecessors:
                    raise _invalid("Fact predecessor is missing or revoked.")
                self.successors[value].add(key)
            remaining[key] = len(values)
        ready = [key for key, count in remaining.items() if not count]
        heapq.heapify(ready)
        order = []
        while ready:
            key = heapq.heappop(ready)
            order.append(key)
            for child in sorted(self.successors[key]):
                remaining[child] -= 1
                if not remaining[child]:
                    heapq.heappush(ready, child)
        if len(order) != len(self.predecessors):
            raise _invalid("Fact graph contains a dependency cycle.")
        self.topological_order = tuple(order)

    def descendants(self, fact_id: str) -> set[str]:
        found: set[str] = set()
        pending = [fact_id]
        while pending:
            for child in self.successors.get(pending.pop(), ()):
                if child not in found:
                    found.add(child)
                    pending.append(child)
        return found


def _invalid(message: str) -> ReCTMError:
    return ReCTMError("FACT_GRAPH_INVALID", message, category="validation")


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in re.findall(r"[A-Za-z0-9_]+", text, flags=re.ASCII)]


def bm25_rank(query: str, documents: Sequence[str]) -> list[int]:
    """MTM BM25 k1=1.5, b=.75 with original-order tie breaking."""
    frequencies = Counter(tokenize(query))
    tokenized = [tokenize(document) for document in documents]
    document_frequency = Counter(token for tokens in tokenized for token in set(tokens))
    average = sum(map(len, tokenized)) / len(tokenized) if tokenized else 0.0
    scores = []
    for index, tokens in enumerate(tokenized):
        counts = Counter(tokens)
        norm = 1.5 * (0.25 + 0.75 * len(tokens) / average) if average > 0 else 1.5
        score = 0.0
        for token, query_tf in sorted(frequencies.items()):
            tf = counts[token]
            if tf:
                df = document_frequency[token]
                idf = math.log(1 + (len(documents) - df + 0.5) / (df + 0.5))
                score += query_tf * idf * (tf * 2.5) / (tf + norm)
        scores.append((index, score))
    return [index for index, _ in sorted(scores, key=lambda item: (-item[1], item[0]))]
