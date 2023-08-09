"""pytest conftest module."""
import pytest

from jwt_fastapi.utils import JFAlgorithms

@pytest.fixture(scope="session")
def algorithms():
    return JFAlgorithms()
