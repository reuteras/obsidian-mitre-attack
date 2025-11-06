# Tests for obsidian-mitre-attack

This directory contains comprehensive tests for the obsidian-mitre-attack project.

## Test Structure

```
tests/
├── conftest.py              # Pytest fixtures and configuration
├── test_models.py           # Unit tests for MITRE model classes
├── test_stix_parser.py      # Tests for STIX data parsing
├── test_markdown_generator.py  # Tests for markdown generation
├── test_integration.py      # End-to-end integration tests
└── fixtures/
    └── cache/               # Cached STIX data for tests
```

## Running Tests

### Install Test Dependencies

```bash
# Install test dependencies
uv sync --group test

# Or install all development dependencies
uv sync --group dev --group test
```

### Run All Tests

```bash
# Run all tests
uv run pytest

# Run with verbose output
uv run pytest -v

# Run with coverage report
uv run pytest --cov
```

### Run Specific Test Categories

```bash
# Run only unit tests (fast)
uv run pytest -m unit

# Run only integration tests (slow, uses real data)
uv run pytest -m integration

# Skip slow tests
uv run pytest -m "not slow"
```

### Run Specific Test Files

```bash
# Test only models
uv run pytest tests/test_models.py

# Test only STIX parser
uv run pytest tests/test_stix_parser.py

# Test only markdown generation
uv run pytest tests/test_markdown_generator.py

# Test only integration
uv run pytest tests/test_integration.py
```

### Run Specific Tests

```bash
# Run a specific test class
uv run pytest tests/test_models.py::TestMITREObject

# Run a specific test function
uv run pytest tests/test_models.py::TestMITREObject::test_initialization
```

## Test Data

Tests use real MITRE ATT&CK STIX data downloaded from the official repository. The data is cached in `tests/fixtures/cache/` to avoid repeated downloads.

### Cached Data Location

- `tests/fixtures/cache/enterprise-attack-16.1.json`
- `tests/fixtures/cache/mobile-attack-16.1.json`
- `tests/fixtures/cache/ics-attack-16.1.json`

### Refreshing Cached Data

To download fresh data, simply delete the cache directory:

```bash
rm -rf tests/fixtures/cache/
```

The next test run will download and cache fresh data.

## Test Markers

Tests are marked with the following pytest markers:

- `@pytest.mark.unit` - Fast unit tests that don't require external data
- `@pytest.mark.integration` - Integration tests that test multiple components together
- `@pytest.mark.slow` - Tests that take significant time to run (usually involving real data)

## Coverage

Test coverage reports are generated in:
- Terminal output (with `--cov`)
- HTML report in `htmlcov/` directory

To view the HTML coverage report:

```bash
uv run pytest --cov
open htmlcov/index.html  # On macOS
xdg-open htmlcov/index.html  # On Linux
```

## Continuous Integration

Tests run automatically on GitHub Actions for:
- Pull requests
- Pushes to main branch
- Manual workflow dispatch

See `.github/workflows/tests.yml` for CI configuration.

## Writing New Tests

When adding new features, please add corresponding tests:

1. **Unit tests** in the appropriate `test_*.py` file for the module
2. **Integration tests** in `test_integration.py` if testing multiple components
3. Use existing fixtures from `conftest.py` for common setup
4. Mark tests appropriately with `@pytest.mark.unit`, `@pytest.mark.integration`, or `@pytest.mark.slow`

### Example Test

```python
import pytest
from obsidian_mitre_attack.models import MITREObject

@pytest.mark.unit
class TestMyFeature:
    """Test my new feature."""

    def test_feature_works(self):
        """Test that my feature works correctly."""
        obj = MITREObject(name="Test")
        assert obj.name == "Test"
```

## Troubleshooting

### Tests Fail on First Run

First-time test runs download STIX data from MITRE's repository. If downloads fail:
1. Check internet connectivity
2. Verify the MITRE repository URL is accessible
3. Try running with `--timeout=600` to allow more time for downloads

### Cache Directory Issues

If you encounter issues with cached data:
```bash
# Clear cache and try again
rm -rf tests/fixtures/cache/
uv run pytest
```

### Import Errors

Make sure dependencies are installed:
```bash
uv sync --group test
```
