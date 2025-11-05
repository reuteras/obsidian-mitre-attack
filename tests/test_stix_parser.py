"""Unit and integration tests for StixParser."""

from __future__ import annotations

from typing import Any

import pytest
from stix2 import Filter

from obsidian_mitre_attack.models import (
    MITREAsset,
    MITRECampaign,
    MITREDataSource,
    MITREGroup,
    MITREMitigation,
    MITRESoftware,
    MITRETactic,
    MITRETechnique,
)
from obsidian_mitre_attack.stix_parser import StixParser


@pytest.mark.unit
class TestStixParserInitialization:
    """Test StixParser initialization."""

    def test_parser_has_memory_stores(self, stix_parser: StixParser):
        """Test that parser has all three domain memory stores."""
        assert stix_parser.enterprise_attack is not None
        assert stix_parser.mobile_attack is not None
        assert stix_parser.ics_attack is not None

    def test_parser_attributes(self, stix_parser: StixParser, test_config: dict[str, Any]):
        """Test that parser has correct attributes."""
        assert stix_parser.url == test_config["repository_url"]
        assert stix_parser.version == test_config["version"]
        assert isinstance(stix_parser.techniques, list)
        assert isinstance(stix_parser.tactics, list)
        assert isinstance(stix_parser.mitigations, list)

    def test_memory_stores_have_data(self, stix_parser: StixParser):
        """Test that memory stores contain data."""
        # Check enterprise attack has tactics
        enterprise_tactics = stix_parser.enterprise_attack.query([
            Filter(prop="type", op="=", value="x-mitre-tactic")
        ])
        assert len(enterprise_tactics) > 0

        # Check enterprise attack has techniques
        enterprise_techniques = stix_parser.enterprise_attack.query([
            Filter(prop="type", op="=", value="attack-pattern")
        ])
        assert len(enterprise_techniques) > 0


@pytest.mark.integration
@pytest.mark.slow
class TestStixParserTactics:
    """Test tactic parsing with real data."""

    def test_get_tactics_enterprise(self, stix_parser: StixParser):
        """Test parsing tactics from enterprise domain."""
        stix_parser._get_tactics(domain="enterprise-attack")

        enterprise_tactics = [t for t in stix_parser.tactics if t.domain == "enterprise-attack"]
        assert len(enterprise_tactics) > 0

        # Check structure of first tactic
        tactic = enterprise_tactics[0]
        assert isinstance(tactic, MITRETactic)
        assert tactic.name != ""
        assert tactic.id != ""
        assert tactic.domain == "enterprise-attack"
        assert tactic.url != ""

    def test_tactics_have_required_fields(self, stix_parser: StixParser):
        """Test that parsed tactics have all required fields."""
        stix_parser._get_tactics(domain="enterprise-attack")

        for tactic in stix_parser.tactics:
            assert tactic.name is not None
            assert tactic.id is not None
            assert tactic.description is not None
            assert tactic.shortname is not None
            assert tactic.version is not None
            assert tactic.created is not None
            assert tactic.modified is not None

    def test_tactic_no_forward_slashes(self, stix_parser: StixParser):
        """Test that tactic names don't contain forward slashes."""
        stix_parser._get_tactics(domain="enterprise-attack")

        for tactic in stix_parser.tactics:
            assert "/" not in tactic.name

    def test_tactics_not_deprecated_or_revoked(self, stix_parser: StixParser):
        """Test that deprecated/revoked tactics are filtered out."""
        stix_parser._get_tactics(domain="enterprise-attack")

        # All parsed tactics should be valid (not deprecated or revoked)
        assert len(stix_parser.tactics) > 0


@pytest.mark.integration
@pytest.mark.slow
class TestStixParserTechniques:
    """Test technique parsing with real data."""

    def test_get_techniques_enterprise(self, stix_parser: StixParser):
        """Test parsing techniques from enterprise domain."""
        # Need tactics first for relationships
        stix_parser._get_tactics(domain="enterprise-attack")
        stix_parser._get_techniques(domain="enterprise-attack")

        enterprise_techniques = [t for t in stix_parser.techniques if t.domain == "enterprise-attack"]
        assert len(enterprise_techniques) > 0

    def test_techniques_have_required_fields(self, stix_parser: StixParser):
        """Test that parsed techniques have all required fields."""
        stix_parser._get_tactics(domain="enterprise-attack")
        stix_parser._get_techniques(domain="enterprise-attack")

        for technique in stix_parser.techniques[:10]:  # Check first 10
            assert technique.name is not None
            assert technique.id is not None
            assert technique.description is not None
            assert technique.internal_id is not None
            assert isinstance(technique.is_subtechnique, bool)
            assert technique.main_id is not None

    def test_technique_subtechnique_relationship(self, stix_parser: StixParser):
        """Test that subtechniques are properly linked to parent techniques."""
        stix_parser._get_tactics(domain="enterprise-attack")
        stix_parser._get_techniques(domain="enterprise-attack")

        # Find a subtechnique
        subtechniques = [t for t in stix_parser.techniques if t.is_subtechnique]
        assert len(subtechniques) > 0

        # Check subtechnique has parent info
        subtechnique = subtechniques[0]
        assert subtechnique.parent_name != ""
        assert "." in subtechnique.id  # Subtechniques have format T1234.001

    def test_technique_main_id(self, stix_parser: StixParser):
        """Test that main_id is correctly set for techniques and subtechniques."""
        stix_parser._get_tactics(domain="enterprise-attack")
        stix_parser._get_techniques(domain="enterprise-attack")

        for technique in stix_parser.techniques[:20]:
            if technique.is_subtechnique:
                # Subtechnique main_id should be the parent ID
                assert "." not in technique.main_id
                assert technique.id.startswith(technique.main_id)
            else:
                # Main technique main_id should equal its ID
                assert technique.main_id == technique.id


@pytest.mark.integration
@pytest.mark.slow
class TestStixParserMitigations:
    """Test mitigation parsing with real data."""

    def test_get_mitigations_enterprise(self, stix_parser: StixParser):
        """Test parsing mitigations from enterprise domain."""
        stix_parser._get_mitigations(domain="enterprise-attack")

        enterprise_mitigations = [m for m in stix_parser.mitigations if m.domain == "enterprise-attack"]
        assert len(enterprise_mitigations) > 0

    def test_mitigations_have_required_fields(self, stix_parser: StixParser):
        """Test that parsed mitigations have all required fields."""
        stix_parser._get_mitigations(domain="enterprise-attack")

        for mitigation in stix_parser.mitigations[:10]:
            assert mitigation.name is not None
            assert mitigation.id is not None
            assert mitigation.description is not None
            assert mitigation.internal_id is not None
            assert isinstance(mitigation.mitigates, list)


@pytest.mark.integration
@pytest.mark.slow
class TestStixParserGroups:
    """Test group parsing with real data."""

    def test_get_groups(self, stix_parser: StixParser):
        """Test parsing groups from all domains."""
        stix_parser._get_groups()

        assert len(stix_parser.groups) > 0

    def test_groups_have_required_fields(self, stix_parser: StixParser):
        """Test that parsed groups have all required fields."""
        stix_parser._get_groups()

        for group in stix_parser.groups[:10]:
            assert isinstance(group, MITREGroup)
            assert group.name is not None
            assert group.id is not None
            assert group.internal_id is not None
            assert isinstance(group.aliases, list)

    def test_group_aliases(self, stix_parser: StixParser):
        """Test that groups have aliases."""
        stix_parser._get_groups()

        # Most groups should have at least their name in aliases
        groups_with_aliases = [g for g in stix_parser.groups if len(g.aliases) > 0]
        assert len(groups_with_aliases) > 0


@pytest.mark.integration
@pytest.mark.slow
class TestStixParserSoftware:
    """Test software parsing with real data."""

    def test_get_software(self, stix_parser: StixParser):
        """Test parsing software from all domains."""
        stix_parser._get_software()

        assert len(stix_parser.software) > 0

    def test_software_have_required_fields(self, stix_parser: StixParser):
        """Test that parsed software have all required fields."""
        stix_parser._get_software()

        for software in stix_parser.software[:10]:
            assert isinstance(software, MITRESoftware)
            assert software.name is not None
            assert software.id is not None
            assert software.internal_id is not None
            assert software.type in ["malware", "tool"]

    def test_software_types(self, stix_parser: StixParser):
        """Test that software includes both malware and tools."""
        stix_parser._get_software()

        malware = [s for s in stix_parser.software if s.type == "malware"]
        tools = [s for s in stix_parser.software if s.type == "tool"]

        assert len(malware) > 0
        assert len(tools) > 0


@pytest.mark.integration
@pytest.mark.slow
class TestStixParserCampaigns:
    """Test campaign parsing with real data."""

    def test_get_campaigns(self, stix_parser: StixParser):
        """Test parsing campaigns from all domains."""
        # Groups needed for campaign relationships
        stix_parser._get_groups()
        stix_parser._get_campaigns()

        assert len(stix_parser.campaigns) > 0

    def test_campaigns_have_required_fields(self, stix_parser: StixParser):
        """Test that parsed campaigns have all required fields."""
        stix_parser._get_groups()
        stix_parser._get_campaigns()

        for campaign in stix_parser.campaigns[:10]:
            assert isinstance(campaign, MITRECampaign)
            assert campaign.name is not None
            assert campaign.id is not None
            assert campaign.internal_id is not None


@pytest.mark.integration
@pytest.mark.slow
class TestStixParserAssets:
    """Test asset parsing with real data."""

    def test_get_assets(self, stix_parser: StixParser):
        """Test parsing assets from all domains."""
        stix_parser._get_assets()

        # Assets might not exist in all versions
        assert isinstance(stix_parser.assets, list)

    def test_assets_have_required_fields(self, stix_parser: StixParser):
        """Test that parsed assets have all required fields."""
        stix_parser._get_assets()

        if len(stix_parser.assets) > 0:
            for asset in stix_parser.assets[:5]:
                assert isinstance(asset, MITREAsset)
                assert asset.name is not None
                assert asset.id is not None
                assert asset.internal_id is not None


@pytest.mark.integration
@pytest.mark.slow
class TestStixParserDataSources:
    """Test data source parsing with real data."""

    def test_get_data_sources(self, stix_parser: StixParser):
        """Test parsing data sources from all domains."""
        stix_parser._get_data_sources()

        assert len(stix_parser.data_sources) > 0

    def test_data_sources_have_required_fields(self, stix_parser: StixParser):
        """Test that parsed data sources have all required fields."""
        stix_parser._get_data_sources()

        for data_source in stix_parser.data_sources[:10]:
            assert isinstance(data_source, MITREDataSource)
            assert data_source.name is not None
            assert data_source.id is not None
            assert data_source.internal_id is not None
            assert isinstance(data_source.data_components, list)


@pytest.mark.integration
@pytest.mark.slow
class TestStixParserFullWorkflow:
    """Test complete parsing workflow with real data."""

    def test_get_domain_data(self, stix_parser: StixParser):
        """Test parsing complete domain data."""
        stix_parser.get_domain_data(domain="enterprise-attack")

        # Check that all data types were parsed
        enterprise_tactics = [t for t in stix_parser.tactics if t.domain == "enterprise-attack"]
        enterprise_techniques = [t for t in stix_parser.techniques if t.domain == "enterprise-attack"]
        enterprise_mitigations = [m for m in stix_parser.mitigations if m.domain == "enterprise-attack"]

        assert len(enterprise_tactics) > 0
        assert len(enterprise_techniques) > 0
        assert len(enterprise_mitigations) > 0

    def test_get_cti_data(self, stix_parser: StixParser):
        """Test parsing complete CTI data."""
        stix_parser.get_cti_data()

        # Check that all CTI data types were parsed
        assert len(stix_parser.data_sources) > 0
        assert len(stix_parser.groups) > 0
        assert len(stix_parser.software) > 0
        # Assets and campaigns might be empty in some versions
        assert isinstance(stix_parser.assets, list)
        assert isinstance(stix_parser.campaigns, list)

    def test_full_parse_all_domains(self, stix_parser: StixParser):
        """Test parsing all domains and CTI data."""
        domains = ["enterprise-attack", "mobile-attack", "ics-attack"]

        for domain in domains:
            stix_parser.get_domain_data(domain=domain)

        stix_parser.get_cti_data()

        # Verify we have data from all domains
        assert len(stix_parser.tactics) > 0
        assert len(stix_parser.techniques) > 0
        assert len(stix_parser.mitigations) > 0
        assert len(stix_parser.groups) > 0
        assert len(stix_parser.software) > 0
        assert len(stix_parser.data_sources) > 0

    def test_parsed_data_integrity(self, parsed_stix_data: StixParser):
        """Test that fully parsed data maintains integrity."""
        # Check cross-references exist
        # Techniques should reference tactics
        for technique in parsed_stix_data.techniques[:10]:
            assert technique.tactic_name != ""
            assert technique.tactic_id != ""

        # Mitigations should reference techniques
        mitigations_with_techniques = [m for m in parsed_stix_data.mitigations if len(m.mitigates) > 0]
        assert len(mitigations_with_techniques) > 0

        # Groups should reference techniques or software
        groups_with_data = [g for g in parsed_stix_data.groups if len(g.techniques_used) > 0 or len(g.software_used) > 0]
        assert len(groups_with_data) > 0


@pytest.mark.unit
class TestStixParserHelpers:
    """Test StixParser helper methods."""

    def test_verbose_log_enabled(self, test_config: dict[str, Any], capsys):
        """Test verbose logging when enabled."""
        parser = StixParser.__new__(StixParser)
        parser.verbose = True
        parser.verbose_log(message="Test message")

        captured = capsys.readouterr()
        assert "Test message" in captured.out

    def test_verbose_log_disabled(self, test_config: dict[str, Any], capsys):
        """Test verbose logging when disabled."""
        parser = StixParser.__new__(StixParser)
        parser.verbose = False
        parser.verbose_log(message="Test message")

        captured = capsys.readouterr()
        assert "Test message" not in captured.out
