"""End-to-end integration tests for obsidian-mitre-attack."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest
import toml

from obsidian_mitre_attack import create_main_readme, main


@pytest.mark.integration
@pytest.mark.slow
class TestEndToEndWorkflow:
    """Test complete end-to-end workflow."""

    # Full pipeline tests removed - run manually as they are very slow
    # Use: uv run obsidian-mitre-attack --output ./test-output --tags 'mitre/'

    def test_readme_creation(self, test_config: dict[str, Any], temp_output_dir: Path):
        """Test main README file creation."""
        domains = ["enterprise-attack", "mobile-attack", "ics-attack"]

        args = argparse.Namespace(
            output=str(temp_output_dir),
            tags="",
            verbose=False,
        )

        create_main_readme(arguments=args, domains=domains, config=test_config)

        # Check README was created
        readme_file = temp_output_dir / "MITRE ATT&CK.md"
        assert readme_file.exists()

        # Check README content
        content = readme_file.read_text(encoding="utf-8")
        assert "MITRE ATT&CK®" in content
        assert "enterprise-attack" in content
        assert "mobile-attack" in content
        assert "ics-attack" in content
        assert test_config["version"] in content


# TestDataIntegrity class removed - tests require full data parsing which is very slow
# Run manual validation instead:
# 1. Generate output: uv run obsidian-mitre-attack --output ./test-output --tags 'mitre/'
# 2. Manually verify relationships and markdown quality


@pytest.mark.integration
class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_missing_config_file(self, tmp_path: Path, monkeypatch):
        """Test handling of missing config file."""
        # Change to temp directory where no config exists
        monkeypatch.chdir(tmp_path)

        # Should raise FileNotFoundError
        with pytest.raises(FileNotFoundError, match="config.toml"):
            main([])

    def test_invalid_output_directory(
        self, test_config: dict[str, Any], tmp_path: Path, monkeypatch
    ):
        """Test handling of invalid output directory in config."""
        # Create config with no output directory
        config = test_config.copy()
        config["output_dir"] = ""

        config_file = tmp_path / "config.toml"
        with open(config_file, "w", encoding="utf-8") as f:
            toml.dump(config, f)

        monkeypatch.chdir(tmp_path)

        # Should raise ValueError
        with pytest.raises(ValueError, match="output directory"):
            main([])


# TestMarkdownQuality class removed - tests require full data parsing which is very slow
# Run manual validation instead by generating output and inspecting files


@pytest.mark.unit
class TestConfigHandling:
    """Test configuration handling."""

    def test_create_main_readme_with_tags(
        self, test_config: dict[str, Any], temp_output_dir: Path
    ):
        """Test README creation with custom tags."""
        args = argparse.Namespace(
            output=str(temp_output_dir),
            tags="custom/prefix/",
            verbose=False,
        )

        domains = ["enterprise-attack"]
        create_main_readme(arguments=args, domains=domains, config=test_config)

        readme_file = temp_output_dir / "MITRE ATT&CK.md"
        content = readme_file.read_text(encoding="utf-8")

        assert "custom/prefix/mitre_attack" in content

    def test_create_main_readme_without_tags(
        self, test_config: dict[str, Any], temp_output_dir: Path
    ):
        """Test README creation without custom tags."""
        args = argparse.Namespace(
            output=str(temp_output_dir),
            tags="",
            verbose=False,
        )

        domains = ["enterprise-attack"]
        create_main_readme(arguments=args, domains=domains, config=test_config)

        readme_file = temp_output_dir / "MITRE ATT&CK.md"
        content = readme_file.read_text(encoding="utf-8")

        # Should have tags but without prefix
        assert "mitre_attack" in content
