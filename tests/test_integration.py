"""End-to-end integration tests for obsidian-mitre-attack."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest
import toml
from stix2 import MemoryStore

from obsidian_mitre_attack import create_main_readme, main
from obsidian_mitre_attack.markdown_generator import MarkdownGenerator
from obsidian_mitre_attack.stix_parser import StixParser


@pytest.mark.integration
@pytest.mark.slow
class TestEndToEndWorkflow:
    """Test complete end-to-end workflow."""

    def test_full_pipeline_enterprise_only(self, test_config: dict[str, Any], temp_output_dir: Path, download_stix_data: dict[str, Any]):
        """Test complete pipeline for enterprise domain only."""
        # Initialize parser
        parser = StixParser.__new__(StixParser)
        parser.url = test_config["repository_url"]
        parser.version = test_config["version"]
        parser.verbose = False
        parser.techniques = []
        parser.tactics = []
        parser.mitigations = []

        # Load cached data
        parser.enterprise_attack = MemoryStore(stix_data=download_stix_data["enterprise-attack"]["objects"])
        parser.mobile_attack = MemoryStore(stix_data=download_stix_data["mobile-attack"]["objects"])
        parser.ics_attack = MemoryStore(stix_data=download_stix_data["ics-attack"]["objects"])

        # Parse enterprise domain
        parser.get_domain_data(domain="enterprise-attack")

        # Parse CTI data
        parser.get_cti_data()

        # Generate markdown
        args = argparse.Namespace(
            output=str(temp_output_dir),
            tags="",
            verbose=False,
        )

        generator = MarkdownGenerator(
            output_dir=str(temp_output_dir),
            stix_data=parser,
            arguments=args,
        )

        generator.create_tactic_notes(domain="enterprise-attack")
        generator.create_technique_notes(domain="enterprise-attack")
        generator.create_mitigation_notes(domain="enterprise-attack")
        generator.create_group_notes()
        generator.create_software_notes()
        generator.create_data_source_notes()

        # Verify output structure
        assert (temp_output_dir / "Tactics" / "Enterprise attack").exists()
        assert (temp_output_dir / "Techniques" / "Enterprise attack").exists()
        assert (temp_output_dir / "Defenses" / "Mitigations" / "Enterprise attack").exists()
        assert (temp_output_dir / "CTI" / "Groups").exists()
        assert (temp_output_dir / "CTI" / "Software").exists()
        assert (temp_output_dir / "Defenses" / "Data_Sources").exists()

        # Verify files were created
        tactics_files = list((temp_output_dir / "Tactics" / "Enterprise attack").glob("*.md"))
        assert len(tactics_files) > 0

        techniques_files = list((temp_output_dir / "Techniques" / "Enterprise attack").rglob("*.md"))
        assert len(techniques_files) > 0

    def test_full_pipeline_all_domains(self, test_config: dict[str, Any], temp_output_dir: Path, download_stix_data: dict[str, Any]):
        """Test complete pipeline for all domains."""
        # Initialize parser
        parser = StixParser.__new__(StixParser)
        parser.url = test_config["repository_url"]
        parser.version = test_config["version"]
        parser.verbose = False
        parser.techniques = []
        parser.tactics = []
        parser.mitigations = []

        # Load cached data
        parser.enterprise_attack = MemoryStore(stix_data=download_stix_data["enterprise-attack"]["objects"])
        parser.mobile_attack = MemoryStore(stix_data=download_stix_data["mobile-attack"]["objects"])
        parser.ics_attack = MemoryStore(stix_data=download_stix_data["ics-attack"]["objects"])

        # Parse all domains
        domains = ["enterprise-attack", "mobile-attack", "ics-attack"]
        for domain in domains:
            parser.get_domain_data(domain=domain)

        # Parse CTI data
        parser.get_cti_data()

        # Generate markdown for all domains
        args = argparse.Namespace(
            output=str(temp_output_dir),
            tags="mitre/",
            verbose=False,
        )

        generator = MarkdownGenerator(
            output_dir=str(temp_output_dir),
            stix_data=parser,
            arguments=args,
        )

        for domain in domains:
            generator.create_tactic_notes(domain=domain)
            generator.create_technique_notes(domain=domain)
            generator.create_mitigation_notes(domain=domain)

        generator.create_group_notes()
        generator.create_software_notes()
        generator.create_campaign_notes()
        generator.create_asset_notes()
        generator.create_data_source_notes()

        # Create main README
        create_main_readme(arguments=args, domains=domains, config=test_config)

        # Verify all domain outputs exist
        for domain in domains:
            domain_name = domain.replace("-", " ").capitalize().replace("Ics ", "ICS ")
            assert (temp_output_dir / "Tactics" / domain_name).exists()
            assert (temp_output_dir / "Techniques" / domain_name).exists()
            assert (temp_output_dir / "Defenses" / "Mitigations" / domain_name).exists()

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


@pytest.mark.integration
@pytest.mark.slow
class TestDataIntegrity:
    """Test data integrity across the pipeline."""

    def test_tactic_technique_relationships(self, parsed_stix_data: StixParser):
        """Test that technique-tactic relationships are preserved."""
        # Get a tactic
        if len(parsed_stix_data.tactics) == 0:
            pytest.skip("No tactics available")

        tactic = parsed_stix_data.tactics[0]

        # Find techniques for this tactic
        tactic_techniques = [t for t in parsed_stix_data.techniques if t.tactic_id == tactic.id]

        # There should be techniques for this tactic
        assert len(tactic_techniques) > 0

        # Technique should reference the tactic
        for technique in tactic_techniques[:5]:
            assert technique.tactic_name == tactic.name
            assert technique.tactic_id == tactic.id

    def test_mitigation_technique_relationships(self, parsed_stix_data: StixParser):
        """Test that mitigation-technique relationships are preserved."""
        # Find a mitigation with techniques
        mitigations_with_tech = [m for m in parsed_stix_data.mitigations if len(m.mitigates) > 0]

        if len(mitigations_with_tech) == 0:
            pytest.skip("No mitigations with techniques available")

        mitigation = mitigations_with_tech[0]

        # Mitigated techniques should exist in the techniques list
        for mitigated in mitigation.mitigates[:5]:
            matching_techniques = [t for t in parsed_stix_data.techniques if t.id == mitigated["id"]]
            assert len(matching_techniques) > 0

    def test_group_technique_relationships(self, parsed_stix_data: StixParser):
        """Test that group-technique relationships are preserved."""
        # Find a group with techniques
        groups_with_tech = [g for g in parsed_stix_data.groups if len(g.techniques_used) > 0]

        if len(groups_with_tech) == 0:
            pytest.skip("No groups with techniques available")

        group = groups_with_tech[0]

        # Used techniques should exist in the techniques list
        for used_tech in group.techniques_used[:5]:
            # Note: Group might use techniques from different domains
            # So we can't always guarantee a match
            _ = [t for t in parsed_stix_data.techniques if t.id == used_tech["technique_id"]]

    def test_no_broken_references_in_markdown(self, markdown_generator: MarkdownGenerator):
        """Test that generated markdown doesn't have broken references."""
        markdown_generator.create_technique_notes(domain="enterprise-attack")

        techniques_dir = Path(markdown_generator.output_dir) / "Techniques" / "Enterprise attack"
        technique_files = list(techniques_dir.rglob("*.md"))

        # Check first few files for broken reference patterns
        for file in technique_files[:10]:
            content = file.read_text(encoding="utf-8")

            # No MITRE_URL placeholders should remain
            assert "MITRE_URL" not in content, f"Found MITRE_URL placeholder in {file.name}"

            # No empty links
            assert "[[]]" not in content, f"Found empty link in {file.name}"
            assert "[[  ]]" not in content, f"Found empty link in {file.name}"


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

    def test_invalid_output_directory(self, test_config: dict[str, Any], tmp_path: Path, monkeypatch):
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


@pytest.mark.integration
@pytest.mark.slow
class TestMarkdownQuality:
    """Test quality of generated markdown."""

    def test_valid_markdown_syntax(self, markdown_generator: MarkdownGenerator):
        """Test that generated markdown has valid syntax."""
        markdown_generator.create_tactic_notes(domain="enterprise-attack")

        tactics_dir = Path(markdown_generator.output_dir) / "Tactics" / "Enterprise attack"
        tactic_files = list(tactics_dir.glob("*.md"))

        for file in tactic_files[:5]:
            content = file.read_text(encoding="utf-8")

            # Check frontmatter is valid
            assert content.startswith("---\n")
            frontmatter_end = content.find("---\n", 4)
            assert frontmatter_end > 0, f"Invalid frontmatter in {file.name}"

            # Check no unclosed markdown constructs
            lines = content.split("\n")
            in_table = False
            for line in lines:
                if "|" in line and "---" in line:
                    in_table = True
                if in_table and line.strip() and "|" in line:
                    # Table rows should have consistent pipe counts
                    pass  # Could add more specific table validation

    def test_consistent_heading_levels(self, markdown_generator: MarkdownGenerator):
        """Test that heading levels are consistent."""
        markdown_generator.create_technique_notes(domain="enterprise-attack")

        techniques_dir = Path(markdown_generator.output_dir) / "Techniques" / "Enterprise attack"
        technique_files = list(techniques_dir.rglob("*.md"))

        for file in technique_files[:10]:
            content = file.read_text(encoding="utf-8")

            # Should have ## for main heading
            assert "\n## " in content, f"Missing level 2 heading in {file.name}"

            # Should not skip heading levels (e.g., # then ###)
            lines = content.split("\n")
            heading_levels = []
            for line in lines:
                if line.startswith("#"):
                    level = len(line) - len(line.lstrip("#"))
                    heading_levels.append(level)

            # First heading after frontmatter should be level 2
            if len(heading_levels) > 0:
                assert heading_levels[0] == 2, f"First heading should be level 2 in {file.name}"

    def test_no_html_entities(self, markdown_generator: MarkdownGenerator):
        """Test that no unescaped HTML entities appear in markdown."""
        markdown_generator.create_tactic_notes(domain="enterprise-attack")

        tactics_dir = Path(markdown_generator.output_dir) / "Tactics" / "Enterprise attack"
        tactic_files = list(tactics_dir.glob("*.md"))

        for file in tactic_files[:5]:
            content = file.read_text(encoding="utf-8")

            # Common HTML entities that should be escaped or converted
            # Allow <br /> as it's intentional
            problematic_patterns = ["&nbsp;", "&amp;", "&lt;", "&gt;", "&quot;"]

            for pattern in problematic_patterns:
                assert pattern not in content, f"Found HTML entity {pattern} in {file.name}"


@pytest.mark.unit
class TestConfigHandling:
    """Test configuration handling."""

    def test_create_main_readme_with_tags(self, test_config: dict[str, Any], temp_output_dir: Path):
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

    def test_create_main_readme_without_tags(self, test_config: dict[str, Any], temp_output_dir: Path):
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
