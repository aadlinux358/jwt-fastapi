"""jwt_fastapi utils module."""
from dataclasses import dataclass

from jwt.algorithms import get_default_algorithms
from jwt.algorithms import requires_cryptography

@dataclass(frozen=True)
class JFAlgorithms:
    symmetric: tuple = tuple(set(get_default_algorithms()) - requires_cryptography)
    assymetric: tuple = tuple(requires_cryptography)
