"""MITRE ATT&CK Framework Models."""

class MITREObject:
    """Define a tactic (x-mitre-tactic)."""

    def __init__(self, name) -> None:
        """Initialize the MITREObject class."""
        self._name: str = name.replace('/', '／')    # Name of the object  # noqa: RUF001
        self._references = dict()
        self._internal_id: str = ""                # Internal ID from MITRE ATT&CK
        self._domain: str = ""                     # ATT&CK Domain (enterprise, mobile or ICS)
        self._url: str = ""                  # URL to page on MITRE

    @property
    def name(self) -> str:
        """Return the name of the object."""
        return self._name

    @name.setter
    def name(self, name) -> None:
        """Set the name of the object."""
        self._name = name.replace('/', '／')  # noqa: RUF001

    @property
    def description(self) -> str:
        """Return the description of the object."""
        return self._description

    @description.setter
    def description(self, description) -> None:
        """Set the description of the object."""
        self._description: str = description

    @property
    def id(self) -> str:
        """Return the ID of the object."""
        return self._id

    @id.setter
    def id(self, id) -> None:
        """Set the ID of the object."""
        self._id: str = id

    @property
    def references(self):
        """Return the references of the object."""
        return self._references

    @references.setter
    def references(self, reference:dict) -> None:
        """Set the references of the object."""
        if 'name' not in reference or 'url' not in reference:
            raise ValueError("The parameter provided is not supported")

        self._references[reference['name'].replace('/', '／')] = reference['url']  # noqa: RUF001

    @property
    def internal_id(self) -> str:
        """Return the internal ID of the object."""
        return self._internal_id

    @internal_id.setter
    def internal_id(self, internal_id: str) -> None:
        """Set the internal ID of the object."""
        self._internal_id: str = internal_id

    @property
    def domain(self) -> str:
        """Return the domain of the object."""
        return self._domain

    @domain.setter
    def domain(self, domain) -> None:
        self._domain: str = domain

    @property
    def url(self) -> str:
        """Return the URL of the object."""
        return self._url

    @url.setter
    def url(self, url: str) -> None:
        """Set the URL of the object."""
        self._url: str = url


class MITRETactic(MITREObject):
    """Define a tactic (x-mitre-tactic)."""

    def __init__(self, name) -> None:
        """Initialize the MITRETactic class."""
        MITREObject.__init__(self=self, name=name)
        self._version = ""
        self._created = ""
        self._modified = ""
        self._shortname = ""
        self._external_references = list()
        self._techniques_used = list()

    @property
    def version(self) -> str:
        """Return the version of the object."""
        return self._version

    @version.setter
    def version(self, version: str) -> None:
        self._version: str = version

    @property
    def created(self) -> str:
        """Return the created date of the object."""
        return self._created

    @created.setter
    def created(self, created: str) -> None:
        """Set the created date of the object."""
        self._created: str = created

    @property
    def modified(self) -> str:
        """Return the modified date of the object."""
        return self._modified

    @modified.setter
    def modified(self, modified: str) -> None:
        """Set the modified date of the object."""
        self._modified: str = modified

    @property
    def shortname(self) -> str:
        """Return the shortname of the object."""
        return self._shortname

    @shortname.setter
    def shortname(self, shortname: str) -> None:
        """Set the shortname of the object."""
        self._shortname: str = shortname

    @property
    def external_references(self):
        """Return the external references of the object."""
        return self._external_references

    @external_references.setter
    def external_references(self, reference:dict) -> None:
        """Set the external references of the object."""
        self._external_references.append(reference)

    @property
    def techniques_used(self):
        """Return the techniques used by the object."""
        return self._techniques_used

    @techniques_used.setter
    def techniques_used(self, technique_used:dict) -> None:
        """Set the techniques used by the object."""
        self._techniques_used.append(technique_used)


class MITRETechnique(MITREObject):
    """Define a technique (attack-pattern)."""

    def __init__(self, name) -> None:
        """Initialize the MITRETechnique class."""
        MITREObject.__init__(self=self, name=name)
        self._mitigations = list()
        self._groups = list()
        self._version: str = ""                    # Version of the object, e.g. 1.0
        self._created: str = ""                    # Date of creation, datetime object
        self._modified: str = ""                   # Date of last modification, datetime object
        self._shortname: str = ""
        self._external_references = list()         # External references, list of dictionaries
        self._description: str = ""                # Description of the object, string
        self._parent_name: str = ""                # Parent technique name, string
        self._is_subtechnique: bool = False        # Boolean value to indicate if the object is a subtechnique
        self._subtechniques = list()               # List of subtechniques
        self._main_id: str = ""                    # Main technique ID. Same as id for techniques, and parent id for subtechniques
        self._platforms = list()
        self._permissions_required = list()
        self._effective_permissions = list()
        self._defense_bypassed = list()
        self._techniques_used = list()
        self._tactic: str = ""
        self._data_sources = list()
        self._detection: str = ""
        self._tactic_name = ""
        self._tactic_id: str = ""
        self._supports_remote = False
        self._system_requirements = list()
        self._contributors = list()
        self._procedure_examples = list()
        self._detections = list()
        self._targeted_assets = list()

    @property
    def version(self) -> str:
        """Return the version of the object."""
        return self._version

    @version.setter
    def version(self, version: str) -> None:
        """Set the version of the object."""
        self._version: str = version

    @property
    def created(self) -> str:
        """Return the created date of the object."""
        return self._created

    @created.setter
    def created(self, created: str) -> None:
        """Set the created date of the object."""
        self._created: str = created

    @property
    def modified(self) -> str:
        """Return the modified date of the object."""
        return self._modified

    @modified.setter
    def modified(self, modified) -> None:
        """Set the modified date of the object."""
        self._modified: str = modified

    @property
    def shortname(self) -> str:
        """Return the shortname of the object."""
        return self._shortname

    @shortname.setter
    def shortname(self, shortname) -> None:
        """Set the shortname of the object."""
        self._shortname: str = shortname.replace('/', '／')  # noqa: RUF001

    @property
    def external_references(self):
        """Return the external references of the object."""
        return self._external_references

    @external_references.setter
    def external_references(self, reference:dict) -> None:
        """Set the external references of the object."""
        self._external_references.append(reference)

    @property
    def techniques_used(self):
        """Return the techniques used by the object."""
        return self._techniques_used

    @techniques_used.setter
    def techniques_used(self, technique_used:dict) -> None:
        """Set the techniques used by the object."""
        self._techniques_used.append(technique_used)

    @property
    def is_subtechnique(self) -> bool:
        """Return the subtechnique status of the object."""
        return self._is_subtechnique

    @is_subtechnique.setter
    def is_subtechnique(self, is_subtechnique:bool) -> None:
        """Set the subtechnique status of the object."""
        self._is_subtechnique: bool = is_subtechnique

    @property
    def platforms(self):
        """Return the platforms of the object."""
        return self._platforms

    @platforms.setter
    def platforms(self, platforms) -> None:
        """Set the platforms of the object."""
        self._platforms = platforms

    @property
    def permissions_required(self):
        """Return the permissions required by the object."""
        return self._permissions_required

    @permissions_required.setter
    def permissions_required(self, permissions_required) -> None:
        """Set the permissions required by the object."""
        self._permissions_required = permissions_required

    @property
    def groups(self):
        """Return the groups of the object."""
        return self._groups

    @groups.setter
    def groups(self, group:dict) -> None:
        """Set the groups of the object."""
        self._groups.append(group)

    @property
    def tactic(self) -> str:
        """Return the tactic of the object."""
        return self._tactic

    @tactic.setter
    def tactic(self, tactic) -> None:
        """Set the tactic of the object."""
        self._tactic: str = tactic

    @property
    def data_sources(self):
        """Return the data sources of the object."""
        return self._data_sources

    @data_sources.setter
    def data_sources(self, data_source) -> None:
        """Set the data sources of the object."""
        self._data_sources = data_source

    @property
    def description(self) -> str:
        """Return the description of the object."""
        return self._description

    @description.setter
    def description(self, description) -> None:
        """Set the description of the object."""
        self._description = description

    @property
    def tactic_name(self) -> str:
        """Return the tactic name of the object."""
        return self._tactic_name

    @tactic_name.setter
    def tactic_name(self, tactic_name) -> None:
        """Set the tactic name of the object."""
        self._tactic_name: str = tactic_name.replace('/', '／')  # noqa: RUF001

    @property
    def tactic_id(self):
        """Return the tactic ID of the object."""
        return self._tactic_id

    @tactic_id.setter
    def tactic_id(self, tactic_id) -> None:
        """Set the tactic ID of the object."""
        self._tactic_id = tactic_id

    @property
    def defense_bypassed(self):
        """Return the defense bypassed by the object."""
        return self._defense_bypassed

    @defense_bypassed.setter
    def defense_bypassed(self, defense_bypassed) -> None:
        """Set the defense bypassed by the object."""
        self._defense_bypassed = defense_bypassed

    @property
    def effective_permissions(self):
        """Return the effective permissions of the object."""
        return self._effective_permissions

    @effective_permissions.setter
    def effective_permissions(self, effective_permissions) -> None:
        """Set the effective permissions of the object."""
        self._effective_permissions = effective_permissions

    @property
    def supports_remote(self):
        """Return the supports remote status of the object."""
        return self._supports_remote

    @supports_remote.setter
    def supports_remote(self, supports_remote: bool) -> None:
        self._supports_remote: bool = supports_remote

    @property
    def system_requirements(self):
        """Return the system requirements of the object."""
        return self._system_requirements

    @system_requirements.setter
    def system_requirements(self, system_requirements: str) -> None:
        """Set the system requirements of the object."""
        self._system_requirements.append(system_requirements)

    @property
    def contributors(self):
        """Return the contributors of the object."""
        return self._contributors

    @contributors.setter
    def contributors(self, contributors) -> None:
        """Set the contributors of the object."""
        self._contributors.append(contributors)

    @property
    def procedure_examples(self):
        """Return the procedure examples of the object."""
        return self._procedure_examples

    @procedure_examples.setter
    def procedure_examples(self, procedure_examples) -> None:
        """Set the procedure examples of the object."""
        self._procedure_examples.append(procedure_examples)

    @property
    def detection(self):
        """Return the detection of the object."""
        return self._detection

    @detection.setter
    def detection(self, detection) -> None:
        """Set the detection of the object."""
        self._detection = detection

    @property
    def mitigations(self):
        """Return the mitigations of the object."""
        return self._mitigations

    @mitigations.setter
    def mitigations(self, mitigation:dict) -> None:
        """Set the mitigations of the object."""
        self._mitigations.append(mitigation)

    @property
    def detections(self):
        """Return the detections of the object."""
        return self._detections

    @detections.setter
    def detections(self, detection:dict) -> None:
        """Set the detections of the object."""
        self._detections.append(detection)

    @property
    def subtechniques(self):
        """Return the subtechniques of the object."""
        return self._subtechniques

    @subtechniques.setter
    def subtechniques(self, subtechnique) -> None:
        """Set the subtechniques of the object."""
        self._subtechniques.append(subtechnique)

    @property
    def main_id(self):
        """Return the main ID of the object."""
        return self._main_id

    @main_id.setter
    def main_id(self, main_id) -> None:
        self._main_id = main_id

    @property
    def parent_name(self):
        """Return the parent name of the object."""
        return self._parent_name

    @parent_name.setter
    def parent_name(self, parent_name) -> None:
        self._parent_name = parent_name.replace('/', '／')  # noqa: RUF001

    @property
    def targeted_assets(self):
        """Return the targeted assets of the object."""
        return self._targeted_assets

    @targeted_assets.setter
    def targeted_assets(self, targeted_asset) -> None:
        self._targeted_assets.append(targeted_asset)


class MITREMitigation(MITREObject):
    """Define a mitigation (course-of-action)."""

    def __init__(self, name) -> None:
        """Initialize the MITREMitigation class."""
        MITREObject.__init__(self=self, name=name)
        self._mitigates = list()
        self._version: str = ""
        self._created: str = ""
        self._modified: str = ""
        self._external_references = list()

    @property
    def is_deprecated(self) -> bool:
        """Return the deprecated status of the object."""
        return self._is_deprecated

    @is_deprecated.setter
    def is_deprecated(self, is_deprecated: bool) -> None:
        """Set the deprecated status of the object."""
        self._is_deprecated: bool = is_deprecated

    @property
    def mitigates(self):
        """Return the mitigates of the object."""
        return self._mitigates

    @mitigates.setter
    def mitigates(self, mitigated_technique:dict) -> None:
        """Set the mitigates of the object."""
        self._mitigates.append(mitigated_technique)

    @property
    def version(self) -> str:
        """Return the version of the object."""
        return self._version

    @version.setter
    def version(self, version: str) -> None:
        """Set the version of the object."""
        self._version: str = version

    @property
    def created(self) -> str:
        """Return the created date of the object."""
        return self._created

    @created.setter
    def created(self, created: str) -> None:
        """Set the created date of the object."""
        self._created: str = created

    @property
    def modified(self):
        """Return the modified date of the object."""
        return self._modified

    @modified.setter
    def modified(self, modified: str) -> None:
        """Set the modified date of the object."""
        self._modified: str = modified

    @property
    def external_references(self):
        """Return the external references of the object."""
        return self._external_references

    @external_references.setter
    def external_references(self, external_reference:dict):
        self._external_references.append(external_reference)


class MITREGroup(MITREObject):
    """Define a MITRE group (intrusion-set)."""

    def __init__(self, name) -> None:
        """Initialize the MITREGroup class."""
        MITREObject.__init__(self=self, name=name)
        self._aliases = list()
        self._aliases_references = list()
        self._external_references = list()
        self._software_used = list()
        self._techniques_used = list()
        self._contributors = None # Not implemented yet
        self._version: str = ""
        self._created: str = ""
        self._modified: str = ""

    @property
    def aliases(self):
        """Return the aliases of the object."""
        return self._aliases

    @aliases.setter
    def aliases(self, alias) -> None:
        """Set the aliases of the object."""
        self._aliases = alias

    @property
    def aliases_references(self):
        """Return the aliases references of the object."""
        return self._aliases_references

    @aliases_references.setter
    def aliases_references(self, alias_reference:dict) -> None:
        """Set the aliases references of the object."""
        self._aliases_references.append(alias_reference)

    @property
    def external_references(self):
        """Return the external references of the object."""
        return self._external_references

    @external_references.setter
    def external_references(self, external_reference:dict) -> None:
        """Set the external references of the object."""
        self._external_references.append(external_reference)

    @property
    def software_used(self):
        """Return the software used by the object."""
        return self._software_used

    @software_used.setter
    def software_used(self, software:dict) -> None:
        """Set the software used by the object."""
        self._software_used.append(software)

    @property
    def techniques_used(self):
        """Return the techniques used by the object."""
        return self._techniques_used

    @techniques_used.setter
    def techniques_used(self, technique_used:dict) -> None:
        """Set the techniques used by the object."""
        self._techniques_used.append(technique_used)

    @property
    def contributors(self):
        """Return the contributors of the object."""
        return self._contributors

    @contributors.setter
    def contributors(self, contributors) -> None:
        self._contributors = contributors

    @property
    def version(self) -> str:
        """Return the version of the object."""
        return self._version

    @version.setter
    def version(self, version: str) -> None:
        """Set the version of the object."""
        self._version: str = version

    @property
    def created(self) -> str:
        """Return the created date of the object."""
        return self._created

    @created.setter
    def created(self, created: str) -> None:
        """Set the created date of the object."""
        self._created: str = created

    @property
    def modified(self) -> str:
        """Return the modified date of the object."""
        return self._modified

    @modified.setter
    def modified(self, modified: str) -> None:
        """Set the modified date of the object."""
        self._modified: str = modified


class MITRESoftware(MITREObject):
    """Define a software (malware)."""

    def __init__(self, name) -> None:
        """Initialize the MITRESoftware class."""
        MITREObject.__init__(self=self, name=name)
        self._platforms = list()
        self._aliases = list()
        self._groups_using = list()
        self._type = None
        self._contributors = list()
        self._version = ""
        self._created = ""
        self._modified = ""
        self._techniques_used = list()
        self._external_references = list()
        self._campaigns_using = list()

    @property
    def platforms(self):
        """Return the platforms of the object."""
        return self._platforms

    @platforms.setter
    def platforms(self, platform) -> None:
        """Set the platforms of the object."""
        self._platforms.append(platform)

    @property
    def aliases(self):
        """Return the aliases of the object."""
        return self._aliases

    @aliases.setter
    def aliases(self, alias) -> None:
        """Set the aliases of the object."""
        self._aliases = alias

    @property
    def techniques_used(self):
        """Return the techniques used by the object."""
        return self._techniques_used

    @techniques_used.setter
    def techniques_used(self, technique_used:dict) -> None:
        """Set the techniques used by the object."""
        self._techniques_used.append(technique_used)

    @property
    def groups_using(self):
        """Return the groups using the object."""
        return self._groups_using

    @groups_using.setter
    def groups_using(self, group:dict) -> None:
        """Set the groups using the object."""
        self._groups_using.append(group)

    @property
    def type(self):
        """Return the type of the object."""
        return self._type

    @type.setter
    def type(self, type) -> None:
        """Set the type of the object."""
        self._type = type

    @property
    def contributors(self):
        """Return the contributors of the object."""
        return self._contributors

    @contributors.setter
    def contributors(self, contributors) -> None:
        """Set the contributors of the object."""
        self._contributors = contributors

    @property
    def version(self):
        """Return the version of the object."""
        return self._version

    @version.setter
    def version(self, version: str) -> None:
        """Set the version of the object."""
        self._version: str = version

    @property
    def created(self) -> str:
        """Return the created date of the object."""
        return self._created

    @created.setter
    def created(self, created: str) -> None:
        """Set the created date of the object."""
        self._created: str = created

    @property
    def modified(self):
        """Return the modified date of the object."""
        return self._modified

    @modified.setter
    def modified(self, modified: str) -> None:
        """Set the modified date of the object."""
        self._modified: str = modified

    @property
    def external_references(self):
        """Return the external references of the object."""
        return self._external_references

    @external_references.setter
    def external_references(self, reference) -> None:
        """Set the external references of the object."""
        self._external_references.append(reference)

    @property
    def campaigns_using(self):
        """Return the campaigns using the object."""
        return self._campaigns_using

    @campaigns_using.setter
    def campaigns_using(self, campaign:dict) -> None:
        self._campaigns_using.append(campaign)


class MITRECampaign(MITREObject):
    """Define a campaign."""

    def __init__(self, name) -> None:
        """Initialize the MITRECampaign class."""
        MITREObject.__init__(self=self, name=name)
        self._aliases = list()
        self._groups = list()
        self._external_references = list()
        self._software_used = list()
        self._techniques_used = list()
        self._first_seen = None
        self._last_seen = None
        self._created = ""
        self._modified = ""
        self._version = ""
        self._contributors = list()
        self._groups = list()

    @property
    def aliases(self):
        """Return the aliases of the object."""
        return self._aliases

    @aliases.setter
    def aliases(self, alias) -> None:
        """Set the aliases of the object."""
        self._aliases = alias

    @property
    def first_seen(self):
        """Return the first seen date of the object."""
        return self._first_seen

    @first_seen.setter
    def first_seen(self, first_seen) -> None:
        """Set the first seen date of the object."""
        self._first_seen = first_seen

    @property
    def last_seen(self):
        """Return the last seen date of the object."""
        return self._last_seen

    @last_seen.setter
    def last_seen(self, last_seen) -> None:
        """Set the last seen date of the object."""
        self._last_seen = last_seen

    @property
    def version(self):
        """Return the version of the object."""
        return self._version

    @version.setter
    def version(self, version: str) -> None:
        """Set the version of the object."""
        self._version: str = version

    @property
    def created(self):
        """Return the created date of the object."""
        return self._created

    @created.setter
    def created(self, created: str) -> None:
        self._created: str = created

    @property
    def modified(self):
        """Return the modified date of the object."""
        return self._modified

    @modified.setter
    def modified(self, modified) -> None:
        self._modified: str = modified

    @property
    def groups(self):
        """Return the groups of the object."""
        return self._groups

    @groups.setter
    def groups(self, group) -> None:
        """Set the groups of the object."""
        self._groups.append(group)

    @property
    def external_references(self):
        """Return the external references of the object."""
        return self._external_references

    @external_references.setter
    def external_references(self, external_reference:dict) -> None:
        """Set the external references of the object."""
        self._external_references.append(external_reference)

    @property
    def software_used(self):
        """Return the software used by the object."""
        return self._software_used

    @software_used.setter
    def software_used(self, software) -> None:
        """Set the software used by the object."""
        self._software_used.append(software)

    @property
    def techniques_used(self):
        """Return the techniques used by the object."""
        return self._techniques_used

    @techniques_used.setter
    def techniques_used(self, technique_used:dict) -> None:
        """Set the techniques used by the object."""
        self._techniques_used.append(technique_used)

    @property
    def contributors(self):
        """Return the contributors of the object."""
        return self._contributors

    @contributors.setter
    def contributors(self, contributors) -> None:
        """Set the contributors of the object."""
        self._contributors = contributors

class MITREAsset(MITREObject):
    """Define a asset."""

    def __init__(self, name) -> None:
        """Initialize the MITREAsset class."""
        MITREObject.__init__(self=self, name=name)
        self._external_references = list()
        self._related_assets = list()
        self._techniques_used = list()
        self._created = ""
        self._modified = ""
        self._version = ""
        self._platforms = list()
        self._sectors = list()

    @property
    def version(self) -> str:
        """Return the version of the object."""
        return self._version

    @version.setter
    def version(self, version: str) -> None:
        self._version: str = version

    @property
    def created(self) -> str:
        """Return the created date of the object."""
        return self._created

    @created.setter
    def created(self, created: str) -> None:
        self._created: str = created

    @property
    def modified(self) -> str:
        """Return the modified date of the object."""
        return self._modified

    @modified.setter
    def modified(self, modified: str) -> None:
        """Set the modified date of the object."""
        self._modified: str = modified

    @property
    def external_references(self):
        """Return the external references of the object."""
        return self._external_references

    @external_references.setter
    def external_references(self, external_reference) -> None:
        """Set the external references of the object."""
        self._external_references.append(external_reference)

    @property
    def related_assets(self):
        """Return the related assets of the object."""
        return self._related_assets

    @related_assets.setter
    def related_assets(self, related_asset) -> None:
        """Set the related assets of the object."""
        self._related_assets.append(related_asset)

    @property
    def techniques_used(self):
        """Return the techniques used by the object."""
        return self._techniques_used

    @techniques_used.setter
    def techniques_used(self, technique_used:dict) -> None:
        self._techniques_used.append(technique_used)

    @property
    def platforms(self):
        """Return the platforms of the object."""
        return self._platforms

    @platforms.setter
    def platforms(self, platform: str) -> None:
        self._platforms.append(platform)

    @property
    def sectors(self):
        """Return the sectors of the object."""
        return self._sectors

    @sectors.setter
    def sectors(self, sector: str) -> None:
        self._sectors.append(sector)


class MITREDataSource(MITREObject):
    """Define a data source."""

    def __init__(self, name) -> None:
        """Initialize the MITREDataSource class."""
        MITREObject.__init__(self=self, name=name)
        self._external_references = list()
        self._description: str = ""
        self._version: str = ""
        self._created: str = ""
        self._modified: str = ""
        self._external_references = list()
        self._techniques_used = list()
        self._contributors = list()
        self._data_components = list()
        self._platforms = list()
        self._collection_layers = list()

    @property
    def description(self) -> str:
        """Return the description of the object."""
        return self._description

    @description.setter
    def description(self, description) -> None:
        """Set the description of the object."""
        self._description = description

    @property
    def version(self) -> str:
        """Return the version of the object."""
        return self._version

    @version.setter
    def version(self, version) -> None:
        """Set the version of the object."""
        self._version = version

    @property
    def created(self) -> str:
        """Return the created date of the object."""
        return self._created

    @created.setter
    def created(self, created) -> None:
        """Set the created date of the object."""
        self._created = created

    @property
    def modified(self) -> str:
        """Return the modified date of the object."""
        return self._modified

    @modified.setter
    def modified(self, modified) -> None:
        """Set the modified date of the object."""
        self._modified = modified

    @property
    def external_references(self):
        """Return the external references of the object."""
        return self._external_references

    @external_references.setter
    def external_references(self, external_reference:dict) -> None:
        """Set the external references of the object."""
        self._external_references.append(external_reference)

    @property
    def techniques_used(self):
        """Return the techniques used by the object."""
        return self._techniques_used

    @techniques_used.setter
    def techniques_used(self, technique_used:dict) -> None:
        """Set the techniques used by the object."""
        self._techniques_used.append(technique_used)

    @property
    def contributors(self):
        """Return the contributors of the object."""
        return self._contributors

    @contributors.setter
    def contributors(self, contributors) -> None:

        self._contributors.append(contributors)

    @property
    def data_components(self):
        """Return the data components of the object."""
        return self._data_components

    @data_components.setter
    def data_components(self, data_component) -> None:
        """Set the data components of the object."""
        self._data_components.append(data_component)

    @property
    def platforms(self):
        """Return the platforms of the object."""
        return self._platforms

    @platforms.setter
    def platforms(self, platform) -> None:
        """Set the platforms of the object."""
        self._platforms.append(platform)

    @property
    def collection_layers(self):
        """Return the collection layers of the object."""
        return self._collection_layers

    @collection_layers.setter
    def collection_layers(self, collection_layer:dict) -> None:
        """Set the collection layers of the object."""
        self._collection_layers.append(collection_layer)
