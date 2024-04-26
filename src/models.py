
class MITREObject():
    """
    Define a tactic (x-mitre-tactic)
    """

    def __init__(self, name):
        self._name = name.replace('/', '／')
        self._references = dict()
        self._internal_id = None

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name.replace('/', '／')

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, description):
        self._description = description

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, id):
        self._id = id

    @property
    def references(self):
        return self._references

    @references.setter
    def references(self, reference:dict):
        if 'name' not in reference or 'url' not in reference:
            raise ValueError("The parameter provided is not supported")

        self._references[reference['name']] = reference['url']

    @property
    def internal_id(self):
        return self._internal_id

    @internal_id.setter
    def internal_id(self, internal_id):
        self._internal_id = internal_id


class MITRETactic(MITREObject):
    """
    Define a tactic (x-mitre-tactic)
    """

    def __init__(self, name):
        MITREObject.__init__(self, name)
        self._version = None
        self._created = None
        self._modified = None
        self._shortname = None
        self._external_references = list()
        self._techniques_used = list()
    
    @property
    def version(self):
        return self._version
    
    @version.setter
    def version(self, version):
        self._version = version
    
    @property
    def created(self):
        return self._created
    
    @created.setter
    def created(self, created):
        self._created = created
    
    @property
    def modified(self):
        return self._modified
    
    @modified.setter
    def modified(self, modified):
        self._modified = modified
    
    @property
    def shortname(self):
        return self._shortname
    
    @shortname.setter
    def shortname(self, shortname):
        self._shortname = shortname

    @property
    def external_references(self):
        return self._external_references
    
    @external_references.setter
    def external_references(self, reference:dict):
        self._external_references.append(reference)

    @property
    def techniques_used(self):
        return self._techniques_used
    
    @techniques_used.setter
    def techniques_used(self, technique_used:dict):
        self._techniques_used.append(technique_used)


class MITRETechnique(MITREObject):
    """
    Define a technique (attack-pattern)
    """

    def __init__(self, name):
        MITREObject.__init__(self, name)
        self._kill_chain_phases = list()
        self._mitigations = list()
        self._groups = list()
        self._version = None
        self._created = None
        self._modified = None
        self._shortname = None
        self._external_references = list()
        self._description = None
        self._is_subtechnique = False
        self._platforms = list()
        self._permissions_required = list()
        self._techniques_used = list()
        self._tactic = None
        self._data_sources = list()
        self._detection = None
        self._tactic_name = None
    
    @property
    def version(self):
        return self._version
    
    @version.setter
    def version(self, version):
        self._version = version
    
    @property
    def created(self):
        return self._created
    
    @created.setter
    def created(self, created):
        self._created = created
    
    @property
    def modified(self):
        return self._modified
    
    @modified.setter
    def modified(self, modified):
        self._modified = modified
    
    @property
    def shortname(self):
        return self._shortname
    
    @shortname.setter
    def shortname(self, shortname):
        self._shortname = shortname

    @property
    def external_references(self):
        return self._external_references
    
    @external_references.setter
    def external_references(self, reference:dict):
        self._external_references.append(reference)

    @property
    def techniques_used(self):
        return self._techniques_used
    
    @techniques_used.setter
    def techniques_used(self, technique_used:dict):
        self._techniques_used.append(technique_used)

    @property
    def kill_chain_phases(self):
        return self._kill_chain_phases

    @kill_chain_phases.setter
    def kill_chain_phases(self, kill_chain_phase:dict):
        if 'kill_chain_name' not in kill_chain_phase or 'phase_name' not in kill_chain_phase:
            raise ValueError("The parameter provided is not supported")

        self._kill_chain_phases.append(kill_chain_phase)

    @property
    def is_subtechnique(self):
        return self._is_subtechnique

    @is_subtechnique.setter
    def is_subtechnique(self, is_subtechnique:bool):
        self._is_subtechnique = is_subtechnique

    @property
    def platforms(self):
        return self._platforms

    @platforms.setter
    def platforms(self, platforms):
        self._platforms = platforms

    @property
    def permissions_required(self):
        return self._permissions_required

    @permissions_required.setter
    def permissions_required(self, permissions_required):
        self._permissions_required = permissions_required

    @property
    def mitigations(self):
        return self._mitigations

    @mitigations.setter
    def mitigations(self, mitigation:dict):
        self._mitigations.append(mitigation)

    @property
    def groups(self):
        return self._groups

    @groups.setter
    def groups(self, group:dict):
        self._groups.append(group)

    @property
    def tactic(self):
        return self._tactic
    
    @tactic.setter
    def tactic(self, tactic):
        self._tactic = tactic
    
    @property
    def data_sources(self):
        return self._data_sources
    
    @data_sources.setter
    def data_sources(self, data_source):
        self._data_sources = data_source
    
    @property
    def detection(self):
        return self._detection
    
    @detection.setter
    def detection(self, detection):
        self._detection = detection
    
    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, description):
        self._description = description
    
    @property
    def tactic_name(self):
        return self._tactic_name
    
    @tactic_name.setter
    def tactic_name(self, tactic_name):
        self._tactic_name = tactic_name


class MITREMitigation(MITREObject):
    """
    Define a mitigation (course-of-action)
    """

    def __init__(self, name):
        MITREObject.__init__(self, name)
        self._mitigates = list()
        self._version = None
        self._created = None
        self._modified = None
        self._external_references = list()

    @property
    def is_deprecated(self):
        return self._is_deprecated

    @is_deprecated.setter
    def is_deprecated(self, is_deprecated):
        self._is_deprecated = is_deprecated

    @property
    def mitigates(self):
        return self._mitigates

    @mitigates.setter
    def mitigates(self, mitigated_technique:dict):
        self._mitigates.append(mitigated_technique)

    @property
    def version(self):
        return self._version
    
    @version.setter
    def version(self, version):
        self._version = version
    
    @property
    def created(self):
        return self._created
    
    @created.setter
    def created(self, created):
        self._created = created
    
    @property
    def modified(self):
        return self._modified
    
    @modified.setter
    def modified(self, modified):
        self._modified = modified

    @property
    def external_references(self):
        return self._external_references
    
    @external_references.setter
    def external_references(self, external_reference:dict):
        self._external_references.append(external_reference)


class MITREGroup(MITREObject):
    """
    Define a group
    """

    def __init__(self, name):
        MITREObject.__init__(self, name)
        self._aliases = list()
        self._aliases_references = list()
        self._external_references = list()
        self._software_used = list()
        self._techniques_used = list()

    @property
    def aliases(self):
        return self._aliases

    @aliases.setter
    def aliases(self, alias):
        self._aliases = alias

    @property
    def aliases_references(self):
        return self._aliases_references
    
    @aliases_references.setter
    def aliases_references(self, alias_reference:dict):
        self._aliases_references.append(alias_reference)

    @property
    def external_references(self):
        return self._external_references
    
    @external_references.setter
    def external_references(self, external_reference:dict):
        self._external_references.append(external_reference)

    @property
    def software_used(self):
        return self._software_used
    
    @software_used.setter
    def software_used(self, software:dict):
        self._software_used.append(software)

    @property
    def techniques_used(self):
        return self._techniques_used

    @techniques_used.setter
    def techniques_used(self, technique_used:dict):
        self._techniques_used.append(technique_used)


class MITRESoftware(MITREObject):
    """
    Define a software
    """

    def __init__(self, name):
        MITREObject.__init__(self, name)
        self._platforms = list()
        self._aliases = list()
        self._groups_using = list()
        self._type = None
        self._contributors = list()
        self._version = None
        self._created = None
        self._modified = None
        self._techniques_used = list()
        self._external_references = list()
        self._campaigns_using = list()

    @property
    def platforms(self):
        return self._platforms

    @platforms.setter
    def platforms(self, platform):
        self._platforms.append(platform)

    @property
    def aliases(self):
        return self._aliases

    @aliases.setter
    def aliases(self, alias):
        self._aliases = alias

    @property
    def techniques_used(self):
        return self._techniques_used
    
    @techniques_used.setter
    def techniques_used(self, technique_used:dict):
        self._techniques_used.append(technique_used)

    @property
    def groups_using(self):
        return self._groups_using

    @groups_using.setter
    def groups_using(self, group:dict):
        self._groups_using.append(group)
        
    @property
    def type(self):
        return self._type
    
    @type.setter
    def type(self, type):
        self._type = type

    @property
    def contributors(self):
        return self._contributors
    
    @contributors.setter
    def contributors(self, contributors):
        self._contributors = contributors

    @property
    def version(self):
        return self._version
    
    @version.setter
    def version(self, version):
        self._version = version
    
    @property
    def created(self):
        return self._created
    
    @created.setter
    def created(self, created):
        self._created = created
    
    @property
    def modified(self):
        return self._modified
    
    @modified.setter
    def modified(self, modified):
        self._modified = modified

    @property
    def external_references(self):
        return self._external_references
    
    @external_references.setter
    def external_references(self, reference:dict):
        self._external_references.append(reference)

    @property
    def campaigns_using(self):
        return self._campaigns_using
    
    @campaigns_using.setter
    def campaigns_using(self, campaign:dict):
        self._campaigns_using.append(campaign)


class MITRECampaign(MITREObject):
    """
    Define a campaign
    """

    def __init__(self, name):
        MITREObject.__init__(self, name)
        self._aliases = list()
        self._groups = list()
        self._external_references = list()
        self._software_used = list()
        self._techniques_used = list()
        self._first_seen = None
        self._last_seen = None
        self._created = None
        self._modified = None
        self._version = None

    @property
    def aliases(self):
        return self._aliases
    
    @aliases.setter
    def aliases(self, alias):
        self._aliases = alias

    @property
    def first_seen(self):
        return self._first_seen
    
    @first_seen.setter
    def first_seen(self, first_seen):
        self._first_seen = first_seen

    @property
    def last_seen(self):
        return self._last_seen
    
    @last_seen.setter
    def last_seen(self, last_seen):
        self._last_seen = last_seen
    
    @property
    def version(self):
        return self._version
    
    @version.setter
    def version(self, version):
        self._version = version
    
    @property
    def created(self):
        return self._created
    
    @created.setter
    def created(self, created):
        self._created = created
    
    @property
    def modified(self):
        return self._modified
    
    @modified.setter
    def modified(self, modified):
        self._modified = modified

    @property
    def groups(self):
        return self._groups
    
    @groups.setter
    def groups(self, group:dict):
        self._groups.append(group)

    @property
    def external_references(self):
        return self._external_references
    
    @external_references.setter
    def external_references(self, external_reference:dict):
        self._external_references.append(external_reference)

    @property
    def software_used(self):
        return self._software_used
    
    @software_used.setter
    def software_used(self, software:dict):
        self._software_used.append(software)

    @property
    def techniques_used(self):
        return self._techniques_used

    @techniques_used.setter
    def techniques_used(self, technique_used:dict):
        self._techniques_used.append(technique_used)