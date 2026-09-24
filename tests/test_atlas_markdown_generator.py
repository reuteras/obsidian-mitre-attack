"""Unit and integration tests for AtlasMarkdownGenerator."""

from __future__ import annotations

from pathlib import Path

import pytest

from obsidian_mitre_attack.atlas_markdown_generator import (
    AtlasMarkdownGenerator,
    convert_atlas_local_links,
)


@pytest.mark.unit
class TestConvertAtlasLocalLinks:
    """Test the ATLAS-specific local link conversion helper."""

    def test_converts_technique_link(self):
        """Test converting a relative technique link to a wikilink."""
        text = "[Create Proxy AI Model](/techniques/AML.T0005)"
        result = convert_atlas_local_links(text)
        assert result == "[[Create Proxy AI Model - AML.T0005]]"

    def test_converts_tactic_link(self):
        """Test converting a relative tactic link to a wikilink."""
        text = "[Reconnaissance](/tactics/AML.TA0002)"
        result = convert_atlas_local_links(text)
        assert result == "[[Reconnaissance - AML.TA0002]]"

    def test_converts_mitigation_link(self):
        """Test converting a relative mitigation link to a wikilink."""
        text = "[Limit Model Artifact Release](/mitigations/AML.M0001)"
        result = convert_atlas_local_links(text)
        assert result == "[[Limit Model Artifact Release - AML.M0001]]"

    def test_leaves_external_links_untouched(self):
        """Test that non-ATLAS links are left alone."""
        text = "[URLNet](https://arxiv.org/abs/1802.03162)"
        result = convert_atlas_local_links(text)
        assert result == text

    def test_normalizes_slash_and_colon_in_name(self):
        """Test that slashes and colons in link text are normalized."""
        text = "[OS/2: Test](/techniques/AML.T0000)"
        result = convert_atlas_local_links(text)
        assert "/" not in result
        assert ":" not in result
        assert "／" in result  # Full-width slash  # noqa: RUF001


@pytest.mark.integration
@pytest.mark.slow
class TestAtlasMarkdownGeneratorTactics:
    """Test ATLAS tactic markdown generation."""

    def test_create_tactic_notes(
        self, atlas_markdown_generator: AtlasMarkdownGenerator
    ):
        """Test creating tactic notes."""
        atlas_markdown_generator.create_tactic_notes()

        tactics_dir = Path(atlas_markdown_generator.output_dir) / "Tactics"
        assert tactics_dir.exists()
        assert len(list(tactics_dir.glob("*.md"))) > 0

    def test_tactic_markdown_structure(
        self, atlas_markdown_generator: AtlasMarkdownGenerator
    ):
        """Test structure of generated tactic markdown."""
        atlas_markdown_generator.create_tactic_notes()

        tactics_dir = Path(atlas_markdown_generator.output_dir) / "Tactics"
        tactic_file = next(iter(tactics_dir.glob("*.md")))
        content = tactic_file.read_text(encoding="utf-8")

        assert content.startswith("---")
        assert "aliases:" in content
        assert "tags:" in content
        assert "test/atlas" in content
        assert "test/atlas_tactic" in content
        assert "> [!info]" in content
        assert "ATLAS_URL" not in content


@pytest.mark.integration
@pytest.mark.slow
class TestAtlasMarkdownGeneratorTechniques:
    """Test ATLAS technique markdown generation."""

    def test_create_technique_notes(
        self, atlas_markdown_generator: AtlasMarkdownGenerator
    ):
        """Test creating technique notes."""
        atlas_markdown_generator.create_technique_notes()

        techniques_dir = Path(atlas_markdown_generator.output_dir) / "Techniques"
        assert techniques_dir.exists()
        assert len(list(techniques_dir.glob("*.md"))) > 0

    def test_technique_markdown_structure(
        self, atlas_markdown_generator: AtlasMarkdownGenerator
    ):
        """Test structure of generated technique markdown."""
        atlas_markdown_generator.create_technique_notes()

        techniques_dir = Path(atlas_markdown_generator.output_dir) / "Techniques"
        technique_file = next(iter(techniques_dir.glob("*.md")))
        content = technique_file.read_text(encoding="utf-8")

        assert content.startswith("---")
        assert "test/atlas_technique" in content
        assert "> [!info]" in content
        assert "### Mitigations" in content
        assert "ATLAS_URL" not in content

    def test_subtechnique_references_parent(
        self, atlas_markdown_generator: AtlasMarkdownGenerator
    ):
        """Test that a subtechnique file references its parent technique."""
        atlas_markdown_generator.create_technique_notes()

        techniques_dir = Path(atlas_markdown_generator.output_dir) / "Techniques"
        # Subtechnique IDs look like "AML.T0000.000" (two dots), unlike top-level
        # technique IDs such as "AML.T0000" (one dot).
        subtechnique_files = [
            f
            for f in techniques_dir.glob("*.md")
            if f.stem.split(" - ")[-1].count(".") > 1
        ]
        assert len(subtechnique_files) > 0

        content = subtechnique_files[0].read_text(encoding="utf-8")
        assert "Sub-technique of:" in content


@pytest.mark.integration
@pytest.mark.slow
class TestAtlasMarkdownGeneratorMitigations:
    """Test ATLAS mitigation markdown generation."""

    def test_create_mitigation_notes(
        self, atlas_markdown_generator: AtlasMarkdownGenerator
    ):
        """Test creating mitigation notes."""
        atlas_markdown_generator.create_mitigation_notes()

        mitigations_dir = (
            Path(atlas_markdown_generator.output_dir) / "Defenses" / "Mitigations"
        )
        assert mitigations_dir.exists()
        assert len(list(mitigations_dir.glob("*.md"))) > 0


@pytest.mark.integration
@pytest.mark.slow
class TestAtlasMarkdownGeneratorCaseStudies:
    """Test ATLAS case study markdown generation."""

    def test_create_case_study_notes(
        self, atlas_markdown_generator: AtlasMarkdownGenerator
    ):
        """Test creating case study notes."""
        atlas_markdown_generator.create_case_study_notes()

        case_studies_dir = Path(atlas_markdown_generator.output_dir) / "Case Studies"
        assert case_studies_dir.exists()
        assert len(list(case_studies_dir.glob("*.md"))) > 0

    def test_case_study_markdown_structure(
        self, atlas_markdown_generator: AtlasMarkdownGenerator
    ):
        """Test structure of generated case study markdown, including procedure table."""
        atlas_markdown_generator.create_case_study_notes()

        case_studies_dir = Path(atlas_markdown_generator.output_dir) / "Case Studies"
        case_study_file = next(iter(case_studies_dir.glob("*.md")))
        content = case_study_file.read_text(encoding="utf-8")

        assert content.startswith("---")
        assert "test/atlas_case_study" in content
        assert "> [!info]" in content
        assert "### Procedure" in content
        assert "| Step | Tactic | Technique | Description |" in content
