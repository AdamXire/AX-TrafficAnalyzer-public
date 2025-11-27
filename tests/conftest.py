"""
Pytest configuration and fixtures

Copyright © 2025 MMeTech (Macau) Ltd.
"""

import pytest
import tempfile
import shutil
from pathlib import Path


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    shutil.rmtree(temp_path)


@pytest.fixture
def test_data_dir():
    """Path to test fixtures directory."""
    return Path(__file__).parent / 'fixtures'


@pytest.fixture
def synthetic_fixtures_dir(test_data_dir):
    """Path to synthetic test fixtures."""
    return test_data_dir / 'synthetic'


@pytest.fixture
def golden_fixtures_dir(test_data_dir):
    """Path to golden reference fixtures."""
    return test_data_dir / 'golden'

