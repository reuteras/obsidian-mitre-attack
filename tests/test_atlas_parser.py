"""Unit and integration tests for AtlasParser."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import yaml

from obsidian_mitre_attack.atlas_models import (
    ATLASCaseStudy,
    ATLASMitigation,
    ATLASTactic,
    ATLASTechnique,
)
from obsidian_mitre_attack.atlas_parser import AtlasParser

SAMPLE_MANIFEST = [
    {
        "release": "2026.09",
        "release-date": "2026-09-15",
        "versions": [{"format-version": "6.0.0", "path": "v6/ATLAS-2026.09.yaml"}],
    },
    {
        "release": "2026.05",
        "release-date": "2026-05-27",
        "versions": [{"format-version": "6.0.0", "path": "v6/ATLAS-2026.05.yaml"}],
    },
]


def _mock_response(text: str) -> MagicMock:
    """Build a mock requests.Response with the given body text."""
    response = MagicMock()
    response.text = text
    response.raise_for_status = MagicMock()
    return response


@pytest.mark.unit
class TestAtlasParserSourceResolution:
    """Test resolving the concrete ATLAS data URL from manifest.yaml, mocked."""

    def test_resolve_latest(self, mocker):
        """Test that "latest" picks the first (newest) manifest entry."""
        mocker.patch(
            "obsidian_mitre_attack.atlas_parser.requests.get",
            return_value=_mock_response(yaml.safe_dump(SAMPLE_MANIFEST)),
        )
        parser = AtlasParser(repo_url="https://example.test/atlas", version="latest")

        source_url = parser._resolve_source_url()

        assert source_url == "https://example.test/atlas/dist/v6/ATLAS-2026.09.yaml"
        assert parser.resolved_version == "2026.09"

    def test_resolve_pinned_version(self, mocker):
        """Test resolving a specific pinned release string."""
        mocker.patch(
            "obsidian_mitre_attack.atlas_parser.requests.get",
            return_value=_mock_response(yaml.safe_dump(SAMPLE_MANIFEST)),
        )
        parser = AtlasParser(repo_url="https://example.test/atlas", version="2026.05")

        source_url = parser._resolve_source_url()

        assert source_url == "https://example.test/atlas/dist/v6/ATLAS-2026.05.yaml"
        assert parser.resolved_version == "2026.05"

    def test_resolve_unknown_version_raises(self, mocker):
        """Test that an unknown pinned release raises a clear error."""
        mocker.patch(
            "obsidian_mitre_attack.atlas_parser.requests.get",
            return_value=_mock_response(yaml.safe_dump(SAMPLE_MANIFEST)),
        )
        parser = AtlasParser(repo_url="https://example.test/atlas", version="1999.01")

        with pytest.raises(ValueError, match="not found in manifest"):
            parser._resolve_source_url()


@pytest.mark.integration
@pytest.mark.slow
class TestAtlasParserParsing:
    """Test parsing real (cached) ATLAS data."""

    def test_parses_tactics(self, parsed_atlas_data: AtlasParser):
        """Test that tactics are parsed with required fields."""
        assert len(parsed_atlas_data.tactics) > 0
        tactic = parsed_atlas_data.tactics[0]
        assert isinstance(tactic, ATLASTactic)
        assert tactic.id.startswith("AML.TA")
        assert tactic.name != ""
        assert tactic.url != ""

    def test_tactics_ordered_by_matrix_position(self, parsed_atlas_data: AtlasParser):
        """Test that tactic positions were resolved from the "sequences" relationships."""
        positions = [tactic.position for tactic in parsed_atlas_data.tactics]
        assert any(position > 0 for position in positions)

    def test_parses_techniques(self, parsed_atlas_data: AtlasParser):
        """Test that techniques are parsed with required fields."""
        assert len(parsed_atlas_data.techniques) > 0
        technique = parsed_atlas_data.techniques[0]
        assert isinstance(technique, ATLASTechnique)
        assert technique.id.startswith("AML.T")
        assert technique.name != ""

    def test_techniques_linked_to_tactics(self, parsed_atlas_data: AtlasParser):
        """Test that techniques resolve their tactic via the "achieves" relationship."""
        linked = [t for t in parsed_atlas_data.techniques if t.tactic_id]
        assert len(linked) > 0
        for technique in linked:
            assert technique.tactic_id.startswith("AML.TA")
            assert technique.tactic_name != ""

    def test_subtechniques_linked_to_parent(self, parsed_atlas_data: AtlasParser):
        """Test that subtechniques resolve their parent via "specializes"."""
        subtechniques = [t for t in parsed_atlas_data.techniques if t.is_subtechnique]
        assert len(subtechniques) > 0
        for subtechnique in subtechniques:
            assert subtechnique.parent_id != ""
            assert subtechnique.parent_name != ""
            assert subtechnique.main_id == subtechnique.parent_id

        parents_with_subs = [t for t in parsed_atlas_data.techniques if t.subtechniques]
        assert len(parents_with_subs) > 0

    def test_parses_mitigations(self, parsed_atlas_data: AtlasParser):
        """Test that mitigations are parsed and linked to techniques."""
        assert len(parsed_atlas_data.mitigations) > 0
        mitigation = next(
            m
            for m in parsed_atlas_data.mitigations
            if isinstance(m, ATLASMitigation) and m.techniques_mitigated
        )
        assert mitigation.id.startswith("AML.M")

        technique_id = mitigation.techniques_mitigated[0]["id"]
        technique = next(
            t for t in parsed_atlas_data.techniques if t.id == technique_id
        )
        mitigation_ids = [m["id"] for m in technique.mitigations]
        assert mitigation.id in mitigation_ids

    def test_parses_case_studies(self, parsed_atlas_data: AtlasParser):
        """Test that case studies are parsed with an ordered procedure."""
        assert len(parsed_atlas_data.case_studies) > 0
        case_study = next(
            c
            for c in parsed_atlas_data.case_studies
            if isinstance(c, ATLASCaseStudy) and c.procedure
        )
        assert case_study.id.startswith("AML.CS")

        step_ids: list[str] = [step["step_id"] for step in case_study.procedure]
        assert step_ids == sorted(step_ids)

        for step in case_study.procedure:
            assert step["technique_id"] != ""

    def test_case_studies_linked_to_techniques(self, parsed_atlas_data: AtlasParser):
        """Test that techniques know which case studies employ them."""
        techniques_with_case_studies = [
            t for t in parsed_atlas_data.techniques if t.case_studies
        ]
        assert len(techniques_with_case_studies) > 0

    def test_no_forward_slashes_in_names(self, parsed_atlas_data: AtlasParser):
        """Test that object names don't contain raw forward slashes."""
        for tactic in parsed_atlas_data.tactics:
            assert "/" not in tactic.name
        for technique in parsed_atlas_data.techniques:
            assert "/" not in technique.name
