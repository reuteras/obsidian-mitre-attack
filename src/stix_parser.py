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

                for ext_ref in ext_refs:
                    if ext_ref['source_name'] == 'mitre-attack':
                        technique_obj.id = ext_ref['external_id']
                        
                    if 'url' in ext_ref:
                        technique_obj.references = {'name': ext_ref['source_name'], 'url': ext_ref['url']}

                kill_chain = tech.get('kill_chain_phases', [])

                for kill_phase in kill_chain:
                    technique_obj.kill_chain_phases = kill_phase

                technique_obj.is_subtechnique = tech['x_mitre_is_subtechnique']

                technique_obj.platforms = tech.get('x_mitre_platforms', [])
                technique_obj.permissions_required = tech.get('x_mitre_permissions_required', [])
                technique_obj.description = tech['description']

                self.techniques.append(technique_obj)


    def _get_mitigations(self):
        """
        Get and parse techniques from STIX data
        """

        # Extract mitigations
        mitigations_stix = self.src.query([ Filter('type', '=', 'course-of-action') ])

        self.mitigations = list()

        for mitigation in mitigations_stix:
            if not mitigation.get('x_mitre_deprecated', False): 
                mitigation_obj = MITREMitigation(mitigation['name'])
                
                mitigation_obj.internal_id = mitigation['id']
                mitigation_obj.description = mitigation['description']

                ext_refs = mitigation.get('external_references', [])

                for ext_ref in ext_refs:
                    if ext_ref['source_name'] == 'mitre-attack':
                        mitigation_obj.id = ext_ref['external_id']
                        
                mitigation_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'mitigates'), Filter('source_ref', '=', mitigation_obj.internal_id) ])

                for relationship in mitigation_relationships:
                    for technique in self.techniques:
                        if technique.internal_id == relationship['target_ref']:
                            mitigation_obj.mitigates = {'technique': technique, 'description': relationship.get('description', '') }
#                            technique.mitigations = {'mitigation': mitigation_obj, 'description': relationship.get('description', '') }

                self.mitigations.append(mitigation_obj)


    def _get_groups(self):
        """
        Get and parse groups from STIX data
        """

        # Extract groups
        groups_stix = self.src.query([ Filter('type', '=', 'intrusion-set') ])

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
                        
                    if 'url' in ext_ref:
                        group_obj.references = {'name': ext_ref['source_name'], 'url': ext_ref['url']}

                group_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', group_obj.internal_id) ])

                for relationship in group_relationships:
                    for technique in self.techniques:
                        if technique.internal_id == relationship['target_ref']:
                            group_obj.techniques_used = {'technique': technique, 'description': relationship.get('description', '') }

                self.groups.append(group_obj)


    def _get_software(self):
        """
        Get and parse software from STIX data
        """

        # Extract software
        software_stix = self.src.query([ Filter('type', '=', 'malware') ])

        self.software = list()

        for software in software_stix:
            if software.get('x_mitre_deprecated', False) != 'true':
                software_obj = MITRESoftware(software['name'])

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
                
                    if 'description' in ext_ref:
                        description = ext_ref['description']
                    else:
                        description = ''

                    if 'url' in ext_ref:
                        url = ext_ref['url']
                        software_obj.references = {'name': ext_ref['source_name'], 'url': url, 'description': description}

                software_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', software_obj.internal_id) ])

                for relationship in software_relationships:
                    for technique in self.techniques:
                        if technique.internal_id == relationship['target_ref']:
                            software_obj.techniques_used = {'technique': technique, 'description': relationship.get('description', '') }
    #                        technique.software = {'software': software_obj, 'description': relationship.get('description', '') }

                group_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('target_ref', '=', software_obj.internal_id) ])
                
                for relationship in group_relationships:
                    for group in self.groups:
                        if group.internal_id == relationship['source_ref']:
                            software_obj.groups_using = {'group': group, 'description': relationship.get('description', '') }
    #                        group.software = {'software': software_obj, 'description': relationship.get('description', '') }

                self.software.append(software_obj)