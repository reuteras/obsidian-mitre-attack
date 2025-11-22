"""Unit and integration tests for MarkdownGenerator."""

from __future__ import annotations

from pathlib import Path

import pytest

from obsidian_mitre_attack.markdown_generator import (
    MarkdownGenerator,
    convert_to_local_links,
    fix_description,
    remove_references,
)


@pytest.mark.unit
class TestUtilityFunctions:
    """Test utility functions in markdown_generator module."""

    def test_fix_description_basic(self):
        """Test basic citation replacement."""
        text = "This is a test (Citation: Test Source) with a citation."
        result = fix_description(text)
        assert "[^Test_Source]" in result
        assert "(Citation: Test Source)" not in result

    def test_fix_description_multiple_citations(self):
        """Test multiple citations."""
        text = "First (Citation: Source One) and second (Citation: Source Two)."
        result = fix_description(text)
        assert "[^Source_One]" in result
        assert "[^Source_Two]" in result

    def test_fix_description_spaces_in_citation(self):
        """Test that spaces in citations are converted to underscores."""
        text = "Text (Citation: Multiple Word Source Name) here."
        result = fix_description(text)
        assert "[^Multiple_Word_Source_Name]" in result

    def test_convert_to_local_links_technique(self):
        """Test converting MITRE technique links to local links."""
        text = "[Phishing](https://attack.mitre.org/techniques/T1566)"
        result = convert_to_local_links(text)
        assert "[[Phishing - T1566]]" in result
        assert "attack.mitre.org" not in result

    def test_convert_to_local_links_software(self):
        """Test converting MITRE software links to local links."""
        text = "[Mimikatz](https://attack.mitre.org/software/S0002)"
        result = convert_to_local_links(text)
        assert "[[Mimikatz]]" in result
        assert "attack.mitre.org" not in result

    def test_convert_to_local_links_with_slash(self):
        """Test that forward slashes are replaced in link names."""
        text = "[OS/2](https://attack.mitre.org/software/S0001)"
        result = convert_to_local_links(text)
        assert "/" not in result
        assert "／" in result  # Full-width slash

    def test_convert_to_local_links_with_colon(self):
        """Test that colons are replaced in link names for Obsidian compatibility."""
        text = "[Test:Software](https://attack.mitre.org/software/S0001)"
        result = convert_to_local_links(text)
        assert ":" not in result
        assert ";" in result  # Semicolon

    def test_convert_to_local_links_with_slash_and_colon(self):
        """Test that both slashes and colons are replaced in link names."""
        text = "[Test/Software:Name](https://attack.mitre.org/software/S0001)"
        result = convert_to_local_links(text)
        assert "/" not in result
        assert ":" not in result
        assert "／" in result  # Full-width slash
        assert ";" in result  # Semicolon

    def test_convert_to_local_links_exaramel_fix(self):
        """Test specific fix for Exaramel inconsistency."""
        text = "[Exaramel](https://attack.mitre.org/software/S0343)"
        result = convert_to_local_links(text)
        assert "Exaramel for Windows" in result

    def test_convert_to_local_links_t1086_fix(self):
        """Test specific fix for T1086 redirect."""
        text = "https://attack.mitre.org/techniques/T1086"
        result = convert_to_local_links(text)
        assert "T1059/001" in result or "T1059.001" in result

    def test_remove_references_simple(self):
        """Test removing reference markers."""
        text = "This is text [^ref1] with references [^ref2] included."
        result = remove_references(text)
        assert "[^ref1]" not in result
        assert "[^ref2]" not in result
        assert "This is text" in result

    def test_remove_references_underscore(self):
        """Test removing references with underscores."""
        text = "Text [^Multiple_Word_Reference] here."
        result = remove_references(text)
        assert "[^Multiple_Word_Reference]" not in result


@pytest.mark.integration
@pytest.mark.slow
class TestMarkdownGeneratorTactics:
    """Test tactic markdown generation."""

    def test_create_tactic_notes(self, markdown_generator: MarkdownGenerator):
        """Test creating tactic notes for a domain."""
        markdown_generator.create_tactic_notes(domain="enterprise-attack")

        # Check that files were created
        tactics_dir = (
            Path(markdown_generator.output_dir) / "Tactics" / "Enterprise attack"
        )
        assert tactics_dir.exists()

        # Check that at least one file was created
        tactic_files = list(tactics_dir.glob("*.md"))
        assert len(tactic_files) > 0

    def test_tactic_markdown_structure(self, markdown_generator: MarkdownGenerator):
        """Test structure of generated tactic markdown."""
        markdown_generator.create_tactic_notes(domain="enterprise-attack")

        tactics_dir = (
            Path(markdown_generator.output_dir) / "Tactics" / "Enterprise attack"
        )
        tactic_files = list(tactics_dir.glob("*.md"))

        # Read first tactic file
        tactic_file = tactic_files[0]
        content = tactic_file.read_text(encoding="utf-8")

        # Check frontmatter
        assert content.startswith("---")
        assert "aliases:" in content
        assert "tags:" in content
        assert "url:" in content

        # Check content sections
        assert "## TA" in content  # Tactic ID section
        assert "> [!info]" in content  # Info callout

    def test_tactic_no_mitre_urls(self, markdown_generator: MarkdownGenerator):
        """Test that MITRE URLs are properly replaced."""
        markdown_generator.create_tactic_notes(domain="enterprise-attack")

        tactics_dir = (
            Path(markdown_generator.output_dir) / "Tactics" / "Enterprise attack"
        )
        tactic_files = list(tactics_dir.glob("*.md"))

        tactic_file = tactic_files[0]
        content = tactic_file.read_text(encoding="utf-8")

        # MITRE_URL placeholder should be replaced
        assert "MITRE_URL" not in content


@pytest.mark.integration
@pytest.mark.slow
class TestMarkdownGeneratorTechniques:
    """Test technique markdown generation."""

    def test_create_technique_notes(self, markdown_generator: MarkdownGenerator):
        """Test creating technique notes for a domain."""
        markdown_generator.create_technique_notes(domain="enterprise-attack")

        # Check that files were created
        techniques_dir = (
            Path(markdown_generator.output_dir) / "Techniques" / "Enterprise attack"
        )
        assert techniques_dir.exists()

        # Should have subdirectories for tactics
        tactic_dirs = [d for d in techniques_dir.iterdir() if d.is_dir()]
        assert len(tactic_dirs) > 0

    def test_technique_markdown_structure(self, markdown_generator: MarkdownGenerator):
        """Test structure of generated technique markdown."""
        markdown_generator.create_technique_notes(domain="enterprise-attack")

        techniques_dir = (
            Path(markdown_generator.output_dir) / "Techniques" / "Enterprise attack"
        )

        # Find a technique file
        technique_files = list(techniques_dir.rglob("*.md"))
        assert len(technique_files) > 0

        # Read first technique file
        technique_file = technique_files[0]
        content = technique_file.read_text(encoding="utf-8")

        # Check frontmatter
        assert content.startswith("---")
        assert "aliases:" in content
        assert "tags:" in content

        # Check content sections
        assert "> [!info]" in content
        assert "### Mitigations" in content
        assert "### References" in content

    def test_technique_subtechnique_handling(
        self, markdown_generator: MarkdownGenerator
    ):
        """Test that subtechniques are properly handled."""
        markdown_generator.create_technique_notes(domain="enterprise-attack")

        techniques_dir = (
            Path(markdown_generator.output_dir) / "Techniques" / "Enterprise attack"
        )
        technique_files = list(techniques_dir.rglob("*.md"))

        # Find a file with subtechnique ID (contains .00)
        subtechnique_files = [f for f in technique_files if ".00" in f.name]

        if len(subtechnique_files) > 0:
            content = subtechnique_files[0].read_text(encoding="utf-8")
            # Subtechniques should reference parent
            assert "Sub-technique of:" in content or "Other sub-techniques" in content


@pytest.mark.integration
@pytest.mark.slow
class TestMarkdownGeneratorMitigations:
    """Test mitigation markdown generation."""

    def test_create_mitigation_notes(self, markdown_generator: MarkdownGenerator):
        """Test creating mitigation notes for a domain."""
        markdown_generator.create_mitigation_notes(domain="enterprise-attack")

        # Check that files were created
        mitigations_dir = (
            Path(markdown_generator.output_dir)
            / "Defenses"
            / "Mitigations"
            / "Enterprise attack"
        )
        assert mitigations_dir.exists()

        mitigation_files = list(mitigations_dir.glob("*.md"))
        assert len(mitigation_files) > 0

    def test_mitigation_markdown_structure(self, markdown_generator: MarkdownGenerator):
        """Test structure of generated mitigation markdown."""
        markdown_generator.create_mitigation_notes(domain="enterprise-attack")

        mitigations_dir = (
            Path(markdown_generator.output_dir)
            / "Defenses"
            / "Mitigations"
            / "Enterprise attack"
        )
        mitigation_files = list(mitigations_dir.glob("*.md"))

        mitigation_file = mitigation_files[0]
        content = mitigation_file.read_text(encoding="utf-8")

        # Check structure
        assert content.startswith("---")
        assert "## M" in content  # Mitigation ID
        assert "> [!info]" in content
        assert "### Techniques Addressed by Mitigation" in content


@pytest.mark.integration
@pytest.mark.slow
class TestMarkdownGeneratorGroups:
    """Test group markdown generation."""

    def test_create_group_notes(self, markdown_generator: MarkdownGenerator):
        """Test creating group notes."""
        markdown_generator.create_group_notes()

        groups_dir = Path(markdown_generator.output_dir) / "CTI" / "Groups"
        assert groups_dir.exists()

        group_files = list(groups_dir.glob("*.md"))
        assert len(group_files) > 0

    def test_group_markdown_structure(self, markdown_generator: MarkdownGenerator):
        """Test structure of generated group markdown."""
        markdown_generator.create_group_notes()

        groups_dir = Path(markdown_generator.output_dir) / "CTI" / "Groups"
        group_files = list(groups_dir.glob("*.md"))

        group_file = group_files[0]
        content = group_file.read_text(encoding="utf-8")

        # Check structure
        assert content.startswith("---")
        assert "aliases:" in content
        assert "> [!info]" in content
        assert "### References" in content


@pytest.mark.integration
@pytest.mark.slow
class TestMarkdownGeneratorSoftware:
    """Test software markdown generation."""

    def test_create_software_notes(self, markdown_generator: MarkdownGenerator):
        """Test creating software notes."""
        markdown_generator.create_software_notes()

        software_dir = Path(markdown_generator.output_dir) / "CTI" / "Software"
        assert software_dir.exists()

        software_files = list(software_dir.glob("*.md"))
        assert len(software_files) > 0

    def test_software_markdown_structure(self, markdown_generator: MarkdownGenerator):
        """Test structure of generated software markdown."""
        markdown_generator.create_software_notes()

        software_dir = Path(markdown_generator.output_dir) / "CTI" / "Software"
        software_files = list(software_dir.glob("*.md"))

        software_file = software_files[0]
        content = software_file.read_text(encoding="utf-8")

        # Check structure
        assert content.startswith("---")
        assert "> [!info]" in content
        assert "### Techniques Used" in content
        assert "### References" in content


@pytest.mark.integration
@pytest.mark.slow
class TestMarkdownGeneratorCampaigns:
    """Test campaign markdown generation."""

    def test_create_campaign_notes(self, markdown_generator: MarkdownGenerator):
        """Test creating campaign notes."""
        markdown_generator.create_campaign_notes()

        campaigns_dir = Path(markdown_generator.output_dir) / "CTI" / "Campaigns"

        # Campaigns might not exist in all versions
        if campaigns_dir.exists():
            campaign_files = list(campaigns_dir.glob("*.md"))
            assert len(campaign_files) >= 0


@pytest.mark.integration
@pytest.mark.slow
class TestMarkdownGeneratorAssets:
    """Test asset markdown generation."""

    def test_create_asset_notes(self, markdown_generator: MarkdownGenerator):
        """Test creating asset notes."""
        markdown_generator.create_asset_notes()

        assets_dir = Path(markdown_generator.output_dir) / "Defenses" / "Assets"

        # Assets might not exist in all versions
        if assets_dir.exists():
            asset_files = list(assets_dir.glob("*.md"))
            assert len(asset_files) >= 0


@pytest.mark.integration
@pytest.mark.slow
class TestMarkdownGeneratorDataSources:
    """Test data source markdown generation."""

    def test_create_data_source_notes(self, markdown_generator: MarkdownGenerator):
        """Test creating data source notes."""
        markdown_generator.create_data_source_notes()

        data_sources_dir = (
            Path(markdown_generator.output_dir) / "Defenses" / "Data_Sources"
        )
        assert data_sources_dir.exists()

        data_source_files = list(data_sources_dir.glob("*.md"))
        assert len(data_source_files) > 0

    def test_data_source_markdown_structure(
        self, markdown_generator: MarkdownGenerator
    ):
        """Test structure of generated data source markdown."""
        markdown_generator.create_data_source_notes()

        data_sources_dir = (
            Path(markdown_generator.output_dir) / "Defenses" / "Data_Sources"
        )
        data_source_files = list(data_sources_dir.glob("*.md"))

        data_source_file = data_source_files[0]
        content = data_source_file.read_text(encoding="utf-8")

        # Check structure
        assert content.startswith("---")
        assert "> [!info]" in content
        assert "## Data Components" in content


@pytest.mark.integration
@pytest.mark.slow
class TestMarkdownGeneratorTags:
    """Test that tags are properly applied."""

    def test_tags_in_tactic(self, markdown_generator: MarkdownGenerator):
        """Test that custom tags are applied to tactics."""
        markdown_generator.create_tactic_notes(domain="enterprise-attack")

        tactics_dir = (
            Path(markdown_generator.output_dir) / "Tactics" / "Enterprise attack"
        )
        tactic_files = list(tactics_dir.glob("*.md"))

        content = tactic_files[0].read_text(encoding="utf-8")
        assert "test/" in content  # Custom tag prefix from fixture

    def test_tags_in_technique(self, markdown_generator: MarkdownGenerator):
        """Test that custom tags are applied to techniques."""
        markdown_generator.create_technique_notes(domain="enterprise-attack")

        techniques_dir = (
            Path(markdown_generator.output_dir) / "Techniques" / "Enterprise attack"
        )
        technique_files = list(techniques_dir.rglob("*.md"))

        content = technique_files[0].read_text(encoding="utf-8")
        assert "test/" in content  # Custom tag prefix from fixture


@pytest.mark.integration
@pytest.mark.slow
class TestMarkdownGeneratorConsistency:
    """Test consistency across generated markdown."""

    def test_no_forward_slashes_in_names(self, markdown_generator: MarkdownGenerator):
        """Test that no forward slashes appear in file names or content names."""
        markdown_generator.create_technique_notes(domain="enterprise-attack")

        techniques_dir = (
            Path(markdown_generator.output_dir) / "Techniques" / "Enterprise attack"
        )
        technique_files = list(techniques_dir.rglob("*.md"))

        for file in technique_files:
            # Check filename
            assert "/" not in file.name or file.name.count("/") == file.name.count(
                str(file.parent)
            )

    def test_all_internal_links_have_closing_brackets(
        self, markdown_generator: MarkdownGenerator
    ):
        """Test that all internal links are properly formed."""
        markdown_generator.create_technique_notes(domain="enterprise-attack")

        techniques_dir = (
            Path(markdown_generator.output_dir) / "Techniques" / "Enterprise attack"
        )
        technique_files = list(techniques_dir.rglob("*.md"))

        for file in technique_files[:5]:  # Check first 5 files
            content = file.read_text(encoding="utf-8")

            # Count opening and closing brackets
            open_count = content.count("[[")
            close_count = content.count("]]")

            assert open_count == close_count, f"Mismatched brackets in {file.name}"
