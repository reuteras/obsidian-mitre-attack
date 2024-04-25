from stix2 import Filter
from stix2 import MemoryStore
import requests
from .models import MITRETactic, MITRETechnique, MITREMitigation, MITREGroup, MITRESoftware


class StixParser():
    """
    Get and parse STIX data creating Tactics and Techniques objects
    Get the ATT&CK STIX data from MITRE/CTI GitHub repository. 
    Domain should be 'enterprise-attack', 'mobile-attack', or 'ics-attack'. Branch should typically be master.
    """

    def __init__(self, repo_url, domain):
        self.url = repo_url
        self.domain = domain

        stix_json = requests.get(f"{self.url}/{domain}/{domain}.json").json()

        self.src = MemoryStore(stix_data=stix_json['objects'])

    
    def get_data(self):
        self._get_tactics()
        self._get_techniques()
        self._get_mitigations()
        self._get_groups()
        self._get_software()


    def _get_tactics(self):
        """
        Get and parse tactics from STIX data
        """

        # Extract tactics
        tactics_stix = self.src.query([ Filter('type', '=', 'x-mitre-tactic') ])

        self.tactics = list()

        for tactic in tactics_stix:
            tactic_obj = MITRETactic(tactic['name'])
            # Extract external references, including the link to mitre
            ext_refs = tactic.get('external_references', [])

            for ext_ref in ext_refs:
                if ext_ref['source_name'] == 'mitre-attack':
                    tactic_obj.id = ext_ref['external_id']
                
                tactic_obj.references = {'name': ext_ref['source_name'], 'url': ext_ref['url']}

            tactic_obj.description = tactic['description']
            tactic_obj.created = tactic.get('created', '')
            tactic_obj.modified = tactic.get('modified', '')
            tactic_obj.version = tactic.get('x_mitre_version', [])
            tactic_obj.shortname = tactic.get('x_mitre_shortname', '')

            source_relationships = self.src.query([ Filter('type', '=', 'attack-pattern')])

            added = []
            for relationship in source_relationships:
                ext_refs = relationship.get('external_references', [])
                kill_chain_phase = relationship.get('kill_chain_phases', [])
                for ext_ref in ext_refs:
                    if ext_ref['source_name'] == 'mitre-attack':
                        id = ext_ref['external_id']
                    elif 'url' in ext_ref and 'description' in ext_ref:
                        item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                        if item not in added:
                            tactic_obj.external_references = item
                            added.append(item)
                for phase in kill_chain_phase:
                    if phase['phase_name'] == tactic_obj.shortname:
                        tactic_obj.techniques_used = {'id': id, 'name': relationship['name'], 'description': relationship['description'] }

            self.tactics.append(tactic_obj)


    def _get_techniques(self):
        """
        Get and parse techniques from STIX data
        """

        # Extract techniques
        tech_stix = self.src.query([ Filter('type', '=', 'attack-pattern') ])

        self.techniques = list()

        for tech in tech_stix:
            if 'x_mitre_deprecated' not in tech or not tech['x_mitre_deprecated']:
                technique_obj = MITRETechnique(tech['name'])

                technique_obj.internal_id = tech['id']

                # Extract external references, including the link to mitre
                ext_refs = tech.get('external_references', [])

                added = []
                for ext_ref in ext_refs:
                    if ext_ref['source_name'] == 'mitre-attack':
                        technique_obj.id = ext_ref['external_id']
                    elif 'url' in ext_ref and 'description' in ext_ref:
                        item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                        if item not in added:
                            technique_obj.external_references = item
                            added.append(item)

                kill_chain = tech.get('kill_chain_phases', [])

                for kill_phase in kill_chain:
                    technique_obj.kill_chain_phases = kill_phase

                technique_obj.is_subtechnique = tech['x_mitre_is_subtechnique']
                technique_obj.platforms = tech.get('x_mitre_platforms', [])
                technique_obj.permissions_required = tech.get('x_mitre_permissions_required', [])
                technique_obj.description = tech['description']
                technique_obj.data_sources = tech.get('x_mitre_data_sources', [])
                technique_obj.created = tech.get('created', '')
                technique_obj.modified = tech.get('modified', '')
                technique_obj.version = tech.get('x_mitre_version', [])
                technique_obj.tactic = tech['kill_chain_phases'][0]['phase_name']
                technique_obj.type = tech['type']
                technique_obj.detection = tech.get('x_mitre_detection', '')

                self.techniques.append(technique_obj)


    def _get_mitigations(self):
        """
        Get and parse techniques from STIX data
        """

        # Extract mitigations
        mitigations_stix = self.src.query([ Filter('type', '=', 'course-of-action') ])

        # Extract mitigates relationships
        mitigates_stix = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'mitigates') ])

        mitigates_list = list()

        for mitigate in mitigates_stix:
            mitigates_list.append(mitigate)

        self.mitigations = list()

        for mitigation in mitigations_stix:
            if not mitigation.get('x_mitre_deprecated', False): 
                mitigation_obj = MITREMitigation(mitigation['name'])
                
                mitigation_obj.internal_id = mitigation['id']
                mitigation_obj.description = mitigation['description']
                mitigation_obj.created = mitigation.get('created', '')
                mitigation_obj.modified = mitigation.get('modified', '')
                mitigation_obj.version = mitigation.get('x_mitre_version', [])

                ext_refs = mitigation.get('external_references', [])

                for ext_ref in ext_refs:
                    if ext_ref['source_name'] == 'mitre-attack':
                        mitigation_obj.id = ext_ref['external_id']
                        
                mitigation_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'mitigates'), Filter('source_ref', '=', mitigation_obj.internal_id) ])

                added = []

                for relationship in mitigation_relationships:
                    for technique in self.techniques:
                        if technique.internal_id == relationship['target_ref']:
                            mitigation_obj.mitigates = {'technique': technique, 'description': relationship.get('description', '') }

                        if 'external_references' in relationship:
                            ext_refs = relationship.get('external_references', [])
                            for ext_ref in ext_refs:
                                if 'url' in ext_ref and 'description' in ext_ref:
                                    item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                                    if item not in added:
                                        mitigation_obj.external_references = item
                                        added.append(item)

                    for mitigate in mitigates_list:
                        if mitigate['id'] == relationship['target_ref']:
                            external_id = ''
                            ext_refs = mitigate.get('external_references', [])

                            for ext_ref in ext_refs:
                                if ext_ref['source_name'] == 'mitre-attack':
                                    external_id = ext_ref['external_id']

                            item = {'name': mitigate['name'], 'id': external_id}
                            if item not in added:
                                mitigation_obj.external_references = item
                                added.append(item)


                self.mitigations.append(mitigation_obj)


    def _get_groups(self):
        """
        Get and parse groups from STIX data
        """

        # Extract groups
        groups_stix = self.src.query([ Filter('type', '=', 'intrusion-set') ])

        # Extract software
        software_stix = self.src.query([ Filter('type', '=', 'malware')])

        software_list = list()

        for software in software_stix:
            software_list.append(software)

        self.groups = list()

        for group in groups_stix:
            if group.get('x_mitre_deprecated', False) != 'true':
                group_obj = MITREGroup(group['name'])

                group_obj.internal_id = group['id']
                group_obj.aliases = group.get('aliases', [])
                group_obj.contributors = group.get('x_mitre_contributors', [])
                group_obj.description = group.get('description', '')
                group_obj.version = group.get('x_mitre_version', [])
                group_obj.created = group.get('created', '')
                group_obj.modified = group.get('modified', '')

                # Extract external references, including the link to mitre
                ext_refs = group.get('external_references', [])

                for ext_ref in ext_refs:
                    if ext_ref['source_name'] == 'mitre-attack':
                        group_obj.id = ext_ref['external_id']
                    elif 'url' in ext_ref:
                        group_obj.aliases_references = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                    else:
                        if ext_ref['source_name'] != group_obj.name:
                            group_obj.aliases_references = {'name': ext_ref['source_name'], 'description': ext_ref['description']}

                source_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', group_obj.internal_id) ])

                added = []
                for relationship in source_relationships:
                    for technique in self.techniques:
                        if technique.internal_id == relationship['target_ref']:
                            group_obj.techniques_used = {'technique': technique, 'description': relationship.get('description', '') }

                    if 'external_references' in relationship:
                        ext_refs = relationship.get('external_references', [])
                        for ext_ref in ext_refs:
                            if 'url' in ext_ref and 'description' in ext_ref:
                                item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                                if item not in added:
                                    group_obj.external_references = item
                                    added.append(item)

                malware_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', group_obj.internal_id) ], Filter('target_ref', 'contains', 'malware--'))
                tool_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', group_obj.internal_id) ], Filter('target_ref', 'contains', 'tool--'))
                software_relationships = malware_relationships + tool_relationships

                added = []

                for relationship in software_relationships:
                    for software in software_list:
                        if software['id'] == relationship['target_ref']:
                            external_id = ''
                            ext_refs = group.get('external_references', [])

                            for ext_ref in ext_refs:
                                if ext_ref['source_name'] == 'mitre-attack':
                                    external_id = ext_ref['external_id']

                            item = {'name': software['name'], 'id': external_id}
                            if item not in added:
                                group_obj.software_used = {'name': software['name'], 'id': external_id}
                                added.append(item)

                self.groups.append(group_obj)


    def _get_software(self):
        """
        Get and parse software from STIX data
        """

        # Extract software
        software_stix_malware = self.src.query([ Filter('type', '=', 'malware')])
        software_stix_tool = self.src.query([ Filter('type', '=', 'tool')])

        software_stix = software_stix_malware + software_stix_tool

        self.software = list()

        for software in software_stix:
            if software.get('x_mitre_deprecated', False) != 'true':
                software_obj = MITRESoftware(software['name'])
                added = []

                software_obj.internal_id = software['id']
                software_obj.type = software['type']
                software_obj.platforms = software.get('x_mitre_platforms', [])
                software_obj.contributors = software.get('x_mitre_contributors', [])
                software_obj.version = software.get('x_mitre_version', [])
                software_obj.description = software.get('description', '')
                software_obj.created = software.get('created', '')
                software_obj.modified = software.get('modified', '')

                # Extract external references, including the link to mitre
                ext_refs = software.get('external_references', [])

                for ext_ref in ext_refs:
                    if ext_ref['source_name'] == 'mitre-attack':
                        software_obj.id = ext_ref['external_id']
                    elif 'url' in ext_ref:
                        item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                        if item not in added:
                            software_obj.external_references = item
                            added.append(item)

                source_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', software_obj.internal_id) ])

                for relationship in source_relationships:
                    for technique in self.techniques:
                        if technique.internal_id == relationship['target_ref']:
                            software_obj.techniques_used = {'technique': technique, 'description': relationship.get('description', '') }


                    if 'external_references' in relationship:
                        ext_refs = relationship.get('external_references', [])
                        for ext_ref in ext_refs:
                            if 'url' in ext_ref and 'description' in ext_ref:
                                item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                                if item not in added:
                                    software_obj.external_references = item
                                    added.append(item)

                target_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('target_ref', '=', software_obj.internal_id) ])

                for relationship in target_relationships:
                    for group in self.groups:
                        if group.internal_id == relationship['source_ref']:
                            software_obj.groups_using = {'group': group, 'description': relationship.get('description', '') }

                    if 'external_references' in relationship:
                        ext_refs = relationship.get('external_references', [])
                        for ext_ref in ext_refs:
                            if 'url' in ext_ref and 'description' in ext_ref:
                                item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                                if item not in added:
                                    software_obj.external_references = item
                                    added.append(item)

                self.software.append(software_obj)