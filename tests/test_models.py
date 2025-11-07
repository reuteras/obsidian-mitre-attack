"""Unit tests for MITRE ATT&CK model classes."""

from __future__ import annotations

import pytest

from obsidian_mitre_attack.models import (
    MITREAsset,
    MITRECampaign,
    MITREDataSource,
    MITREGroup,
    MITREMitigation,
    MITREObject,
    MITRESoftware,
    MITRETactic,
    MITRETechnique,
)


@pytest.mark.unit
class TestMITREObject:
    """Test the base MITREObject class."""

    def test_initialization(self):
        """Test basic object initialization."""
        obj = MITREObject(name="Test Object")
        assert obj.name == "Test Object"
        assert obj._references == {}
        assert obj._internal_id == ""
        assert obj._domain == ""
        assert obj._url == ""

    def test_forward_slash_replacement(self):
        """Test that forward slashes are replaced with full-width slashes."""
        obj = MITREObject(name="Test/Object")
        assert obj.name == "Test／Object"
        assert "/" not in obj.name

    def test_name_property_setter(self):
        """Test name property setter."""
        obj = MITREObject(name="Test")
        obj.name = "New/Name"
        assert obj.name == "New／Name"

    def test_description_property(self):
        """Test description property getter and setter."""
        obj = MITREObject(name="Test")
        obj.description = "Test description"
        assert obj.description == "Test description"

    def test_id_property(self):
        """Test ID property getter and setter."""
        obj = MITREObject(name="Test")
        obj.id = "TEST-001"
        assert obj.id == "TEST-001"

    def test_references_property(self):
        """Test references property."""
        obj = MITREObject(name="Test")
        ref = {"name": "Test/Reference", "url": "https://example.com"}
        obj.references = ref
        assert "Test／Reference" in obj._references
        assert obj._references["Test／Reference"] == "https://example.com"

    def test_references_invalid_input(self):
        """Test that references setter validates input."""
        obj = MITREObject(name="Test")
        with pytest.raises(ValueError, match="not supported"):
            obj.references = {"invalid": "data"}

    def test_internal_id_property(self):
        """Test internal ID property."""
        obj = MITREObject(name="Test")
        obj.internal_id = "internal-test-001"
        assert obj.internal_id == "internal-test-001"

    def test_domain_property(self):
        """Test domain property."""
        obj = MITREObject(name="Test")
        obj.domain = "enterprise-attack"
        assert obj.domain == "enterprise-attack"

    def test_url_property(self):
        """Test URL property."""
        obj = MITREObject(name="Test")
        obj.url = "https://attack.mitre.org/test"
        assert obj.url == "https://attack.mitre.org/test"


@pytest.mark.unit
class TestMITRETactic:
    """Test the MITRETactic class."""

    def test_initialization(self):
        """Test tactic initialization."""
        tactic = MITRETactic(name="Initial Access")
        assert tactic.name == "Initial Access"
        assert tactic._version == ""
        assert tactic._created == ""
        assert tactic._modified == ""
        assert tactic._shortname == ""
        assert tactic._external_references == []
        assert tactic._techniques_used == []

    def test_version_property(self):
        """Test version property."""
        tactic = MITRETactic(name="Test")
        tactic.version = "1.0"
        assert tactic.version == "1.0"

    def test_created_property(self):
        """Test created date property."""
        tactic = MITRETactic(name="Test")
        tactic.created = "2023-01-01"
        assert tactic.created == "2023-01-01"

    def test_modified_property(self):
        """Test modified date property."""
        tactic = MITRETactic(name="Test")
        tactic.modified = "2023-06-01"
        assert tactic.modified == "2023-06-01"

    def test_shortname_property(self):
        """Test shortname property."""
        tactic = MITRETactic(name="Test")
        tactic.shortname = "initial-access"
        assert tactic.shortname == "initial-access"

    def test_external_references_append(self):
        """Test that external references are appended."""
        tactic = MITRETactic(name="Test")
        ref1 = {"name": "ref1", "url": "https://example.com/1"}
        ref2 = {"name": "ref2", "url": "https://example.com/2"}
        tactic.external_references = ref1
        tactic.external_references = ref2
        assert len(tactic.external_references) == 2

    def test_techniques_used_append(self):
        """Test that techniques used are appended."""
        tactic = MITRETactic(name="Test")
        tech1 = {"id": "T001", "name": "Technique 1"}
        tech2 = {"id": "T002", "name": "Technique 2"}
        tactic.techniques_used = tech1
        tactic.techniques_used = tech2
        assert len(tactic.techniques_used) == 2


@pytest.mark.unit
class TestMITRETechnique:
    """Test the MITRETechnique class."""

    def test_initialization(self):
        """Test technique initialization."""
        technique = MITRETechnique(name="Phishing")
        assert technique.name == "Phishing"
        assert technique._mitigations == []
        assert technique._groups == []
        assert technique._is_subtechnique is False
        assert technique._subtechniques == []

    def test_is_subtechnique_property(self):
        """Test is_subtechnique property."""
        technique = MITRETechnique(name="Test")
        technique.is_subtechnique = True
        assert technique.is_subtechnique is True

    def test_platforms_property(self):
        """Test platforms property."""
        technique = MITRETechnique(name="Test")
        platforms = ["Windows", "Linux", "macOS"]
        technique.platforms = platforms
        assert technique.platforms == platforms

    def test_main_id_for_technique(self):
        """Test main_id for a main technique."""
        technique = MITRETechnique(name="Test")
        technique.id = "T1234"
        technique.is_subtechnique = False
        technique.main_id = "T1234"
        assert technique.main_id == "T1234"

    def test_main_id_for_subtechnique(self):
        """Test main_id for a subtechnique."""
        technique = MITRETechnique(name="Test")
        technique.id = "T1234.001"
        technique.is_subtechnique = True
        technique.main_id = "T1234"
        assert technique.main_id == "T1234"

    def test_parent_name_slash_replacement(self):
        """Test that parent name replaces forward slashes."""
        technique = MITRETechnique(name="Test")
        technique.parent_name = "Parent/Name"
        assert technique.parent_name == "Parent／Name"

    def test_mitigations_append(self):
        """Test that mitigations are appended."""
        technique = MITRETechnique(name="Test")
        mit1 = {"id": "M001", "name": "Mitigation 1"}
        mit2 = {"id": "M002", "name": "Mitigation 2"}
        technique.mitigations = mit1
        technique.mitigations = mit2
        assert len(technique.mitigations) == 2

    def test_subtechniques_append(self):
        """Test that subtechniques are appended."""
        technique = MITRETechnique(name="Test")
        sub1 = {"id": "T1234.001", "name": "Sub 1"}
        sub2 = {"id": "T1234.002", "name": "Sub 2"}
        technique.subtechniques = sub1
        technique.subtechniques = sub2
        assert len(technique.subtechniques) == 2


@pytest.mark.unit
class TestMITREMitigation:
    """Test the MITREMitigation class."""

    def test_initialization(self):
        """Test mitigation initialization."""
        mitigation = MITREMitigation(name="User Training")
        assert mitigation.name == "User Training"
        assert mitigation._mitigates == []

    def test_mitigates_append(self):
        """Test that mitigated techniques are appended."""
        mitigation = MITREMitigation(name="Test")
        tech1 = {"id": "T001", "name": "Technique 1"}
        tech2 = {"id": "T002", "name": "Technique 2"}
        mitigation.mitigates = tech1
        mitigation.mitigates = tech2
        assert len(mitigation.mitigates) == 2


@pytest.mark.unit
class TestMITREGroup:
    """Test the MITREGroup class."""

    def test_initialization(self):
        """Test group initialization."""
        group = MITREGroup(name="APT28")
        assert group.name == "APT28"
        assert group._aliases == []
        assert group._software_used == []
        assert group._techniques_used == []

    def test_aliases_property(self):
        """Test aliases property."""
        group = MITREGroup(name="Test")
        aliases = ["Alias1", "Alias2", "Alias3"]
        group.aliases = aliases
        assert group.aliases == aliases

    def test_software_used_append(self):
        """Test that software used is appended."""
        group = MITREGroup(name="Test")
        soft1 = {"id": "S001", "name": "Software 1"}
        soft2 = {"id": "S002", "name": "Software 2"}
        group.software_used = soft1
        group.software_used = soft2
        assert len(group.software_used) == 2


@pytest.mark.unit
class TestMITRESoftware:
    """Test the MITRESoftware class."""

    def test_initialization(self):
        """Test software initialization."""
        software = MITRESoftware(name="Mimikatz")
        assert software.name == "Mimikatz"
        assert software._platforms == []
        assert software._groups_using == []
        assert software._techniques_used == []

    def test_type_property(self):
        """Test type property."""
        software = MITRESoftware(name="Test")
        software.type = "malware"
        assert software.type == "malware"

    def test_platforms_append(self):
        """Test that platforms are appended."""
        software = MITRESoftware(name="Test")
        software.platforms = "Windows"
        software.platforms = "Linux"
        assert len(software._platforms) == 2


@pytest.mark.unit
class TestMITRECampaign:
    """Test the MITRECampaign class."""

    def test_initialization(self):
        """Test campaign initialization."""
        campaign = MITRECampaign(name="Operation X")
        assert campaign.name == "Operation X"
        assert campaign._aliases == []
        assert campaign._groups == []
        assert campaign._software_used == []
        assert campaign._techniques_used == []

    def test_first_seen_property(self):
        """Test first_seen property."""
        campaign = MITRECampaign(name="Test")
        campaign.first_seen = "2023-01-01"
        assert campaign.first_seen == "2023-01-01"

    def test_last_seen_property(self):
        """Test last_seen property."""
        campaign = MITRECampaign(name="Test")
        campaign.last_seen = "2023-12-31"
        assert campaign.last_seen == "2023-12-31"


@pytest.mark.unit
class TestMITREAsset:
    """Test the MITREAsset class."""

    def test_initialization(self):
        """Test asset initialization."""
        asset = MITREAsset(name="Network")
        assert asset.name == "Network"
        assert asset._related_assets == []
        assert asset._techniques_used == []
        assert asset._platforms == []
        assert asset._sectors == []

    def test_platforms_append(self):
        """Test that platforms are appended."""
        asset = MITREAsset(name="Test")
        asset.platforms = "Windows"
        asset.platforms = "Linux"
        assert len(asset.platforms) == 2

    def test_sectors_append(self):
        """Test that sectors are appended."""
        asset = MITREAsset(name="Test")
        asset.sectors = "Financial"
        asset.sectors = "Healthcare"
        assert len(asset.sectors) == 2


@pytest.mark.unit
class TestMITREDataSource:
    """Test the MITREDataSource class."""

    def test_initialization(self):
        """Test data source initialization."""
        data_source = MITREDataSource(name="Process Monitoring")
        assert data_source.name == "Process Monitoring"
        assert data_source._techniques_used == []
        assert data_source._data_components == []
        assert data_source._platforms == []

    def test_data_components_append(self):
        """Test that data components are appended."""
        data_source = MITREDataSource(name="Test")
        comp1 = {"name": "Component 1"}
        comp2 = {"name": "Component 2"}
        data_source.data_components = comp1
        data_source.data_components = comp2
        assert len(data_source.data_components) == 2

    def test_collection_layers_append(self):
        """Test that collection layers are appended."""
        data_source = MITREDataSource(name="Test")
        layer1 = {"name": "Layer 1"}
        layer2 = {"name": "Layer 2"}
        data_source.collection_layers = layer1
        data_source.collection_layers = layer2
        assert len(data_source.collection_layers) == 2
