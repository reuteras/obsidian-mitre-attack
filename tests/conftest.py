"""Pytest configuration and fixtures for obsidian-mitre-attack tests."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pytest
import requests
import yaml
from stix2 import MemoryStore

from obsidian_mitre_attack.atlas_markdown_generator import AtlasMarkdownGenerator
from obsidian_mitre_attack.atlas_parser import AtlasParser
from obsidian_mitre_attack.markdown_generator import MarkdownGenerator
from obsidian_mitre_attack.stix_parser import StixParser


@pytest.fixture(scope="session")
def test_config() -> dict[str, Any]:
    """Provide test configuration."""
    return {
        "repository_url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master",
        "output_dir": "test_output",
        "version": "16.1",  # Use a stable version for testing
        "verbose": False,
    }


@pytest.fixture(scope="session")
def cache_dir() -> Path:
    """Create and return a cache directory for test data."""
    cache_path = Path(__file__).parent / "fixtures" / "cache"
    cache_path.mkdir(parents=True, exist_ok=True)
    return cache_path


@pytest.fixture(scope="session")
def download_stix_data(test_config: dict[str, Any], cache_dir: Path) -> dict[str, Any]:
    """Download and cache STIX data for all domains.

    This fixture downloads real STIX data once per test session and caches it
    to avoid repeated downloads. This allows tests to use real data without
    hitting the network every time.
    """
    domains = ["enterprise-attack", "mobile-attack", "ics-attack"]
    stix_data = {}

    for domain in domains:
        cache_file = cache_dir / f"{domain}-{test_config['version']}.json"

        if cache_file.exists():
            # Load from cache
            with open(cache_file, encoding="utf-8") as f:
                stix_data[domain] = json.load(f)
        else:
            # Download and cache
            url = f"{test_config['repository_url']}/{domain}/{domain}-{test_config['version']}.json"
            response = requests.get(url, timeout=60)
            response.raise_for_status()
            data = response.json()
            stix_data[domain] = data

            # Save to cache
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f)

    return stix_data


@pytest.fixture(scope="session")
def stix_parser(
    test_config: dict[str, Any], download_stix_data: dict[str, Any]
) -> StixParser:
    """Provide a StixParser instance with real STIX data loaded.

    This fixture creates a StixParser and loads it with cached STIX data,
    avoiding network calls during tests.
    """
    # Create parser with network disabled (we'll inject data)
    parser = StixParser.__new__(StixParser)
    parser.url = test_config["repository_url"]
    parser.version = test_config["version"]
    parser.verbose = test_config["verbose"]
    parser.techniques = []
    parser.tactics = []
    parser.mitigations = []

    # Load data from cache
    parser.enterprise_attack = MemoryStore(
        stix_data=download_stix_data["enterprise-attack"]["objects"]
    )
    parser.mobile_attack = MemoryStore(
        stix_data=download_stix_data["mobile-attack"]["objects"]
    )
    parser.ics_attack = MemoryStore(
        stix_data=download_stix_data["ics-attack"]["objects"]
    )

    return parser


@pytest.fixture
def parsed_stix_data(stix_parser: StixParser) -> StixParser:
    """Provide a fully parsed StixParser instance.

    This fixture processes all domains and CTI data, providing a complete
    dataset for testing markdown generation and other operations.
    """
    domains = ["enterprise-attack", "mobile-attack", "ics-attack"]

    # Parse all domain data
    for domain in domains:
        stix_parser.get_domain_data(domain=domain)

    # Parse CTI data
    stix_parser.get_cti_data()

    return stix_parser


@pytest.fixture(scope="session")
def atlas_test_config() -> dict[str, Any]:
    """Provide test configuration for ATLAS."""
    return {
        "atlas_repository_url": "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main",
        "atlas_version": "2026.05",  # Use a stable, fixed release for testing
        "verbose": False,
    }


@pytest.fixture(scope="session")
def download_atlas_data(
    atlas_test_config: dict[str, Any], cache_dir: Path
) -> dict[str, Any]:
    """Download and cache ATLAS data.

    This fixture downloads the real ATLAS YAML once per test session and caches
    it, avoiding repeated downloads and any manifest.yaml drift in "latest".
    """
    cache_file = cache_dir / f"atlas-{atlas_test_config['atlas_version']}.yaml"

    if cache_file.exists():
        with open(cache_file, encoding="utf-8") as f:
            return yaml.safe_load(f)

    parser = AtlasParser(
        repo_url=atlas_test_config["atlas_repository_url"],
        version=atlas_test_config["atlas_version"],
        verbose=False,
    )
    parser.get_data()

    with open(cache_file, "w", encoding="utf-8") as f:
        yaml.safe_dump(parser.data, f)

    return parser.data


@pytest.fixture(scope="session")
def atlas_parser(
    atlas_test_config: dict[str, Any], download_atlas_data: dict[str, Any]
) -> AtlasParser:
    """Provide an AtlasParser instance with real ATLAS data loaded.

    This fixture creates an AtlasParser and injects cached data directly,
    avoiding network calls during tests.
    """
    parser = AtlasParser.__new__(AtlasParser)
    parser.url = atlas_test_config["atlas_repository_url"]
    parser.version = atlas_test_config["atlas_version"]
    parser.verbose = atlas_test_config["verbose"]
    parser.tactics = []
    parser.techniques = []
    parser.mitigations = []
    parser.case_studies = []
    parser.resolved_version = atlas_test_config["atlas_version"]
    parser.data = download_atlas_data

    return parser


@pytest.fixture
def parsed_atlas_data(atlas_parser: AtlasParser) -> AtlasParser:
    """Provide a fully parsed AtlasParser instance."""
    atlas_parser.parse()
    return atlas_parser


@pytest.fixture
def atlas_markdown_generator(
    parsed_atlas_data: AtlasParser, temp_output_dir: Path
) -> AtlasMarkdownGenerator:
    """Provide an AtlasMarkdownGenerator instance with parsed data."""
    args = argparse.Namespace(
        output=str(temp_output_dir),
        tags="test/",
        verbose=False,
    )

    return AtlasMarkdownGenerator(
        output_dir=str(temp_output_dir),
        atlas_data=parsed_atlas_data,
        arguments=args,
    )


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    """Provide a temporary output directory for markdown files."""
    output_dir = tmp_path / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


@pytest.fixture
def markdown_generator(
    parsed_stix_data: StixParser, temp_output_dir: Path
) -> MarkdownGenerator:
    """Provide a MarkdownGenerator instance with parsed data."""
    args = argparse.Namespace(
        output=str(temp_output_dir),
        tags="test/",
        verbose=False,
    )

    return MarkdownGenerator(
        output_dir=str(temp_output_dir),
        stix_data=parsed_stix_data,
        arguments=args,
    )


@pytest.fixture
def sample_tactic_data() -> dict[str, Any]:
    """Provide sample tactic data for unit tests."""
    return {
        "type": "x-mitre-tactic",
        "id": "x-mitre-tactic--test-001",
        "name": "Initial Access",
        "description": "The adversary is trying to get into your network.",
        "x_mitre_version": "1.0",
        "x_mitre_shortname": "initial-access",
        "created": "2023-01-01T00:00:00.000Z",
        "modified": "2023-06-01T00:00:00.000Z",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "TA0001",
                "url": "https://attack.mitre.org/tactics/TA0001",
            }
        ],
    }


@pytest.fixture
def sample_technique_data() -> dict[str, Any]:
    """Provide sample technique data for unit tests."""
    return {
        "type": "attack-pattern",
        "id": "attack-pattern--test-001",
        "name": "Phishing",
        "description": "Adversaries may send phishing messages to gain access.",
        "x_mitre_version": "2.0",
        "x_mitre_is_subtechnique": False,
        "x_mitre_platforms": ["Linux", "Windows", "macOS"],
        "created": "2023-01-01T00:00:00.000Z",
        "modified": "2023-06-01T00:00:00.000Z",
        "kill_chain_phases": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "initial-access",
            }
        ],
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "T1566",
                "url": "https://attack.mitre.org/techniques/T1566",
            }
        ],
    }


@pytest.fixture
def sample_mitigation_data() -> dict[str, Any]:
    """Provide sample mitigation data for unit tests."""
    return {
        "type": "course-of-action",
        "id": "course-of-action--test-001",
        "name": "User Training",
        "description": "Train users to recognize phishing attempts.",
        "x_mitre_version": "1.0",
        "x_mitre_domains": ["enterprise-attack"],
        "created": "2023-01-01T00:00:00.000Z",
        "modified": "2023-06-01T00:00:00.000Z",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "M1017",
                "url": "https://attack.mitre.org/mitigations/M1017",
            }
        ],
    }


@pytest.fixture
def sample_group_data() -> dict[str, Any]:
    """Provide sample group data for unit tests."""
    return {
        "type": "intrusion-set",
        "id": "intrusion-set--test-001",
        "name": "APT28",
        "description": "APT28 is a threat group attributed to Russia.",
        "aliases": ["APT28", "Fancy Bear", "Sofacy"],
        "x_mitre_version": "2.1",
        "created": "2023-01-01T00:00:00.000Z",
        "modified": "2023-06-01T00:00:00.000Z",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "G0007",
                "url": "https://attack.mitre.org/groups/G0007",
            }
        ],
    }
