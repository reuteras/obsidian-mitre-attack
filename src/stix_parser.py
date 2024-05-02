from stix2 import Filter
from stix2 import MemoryStore
import requests
from .models import MITRETactic, MITRETechnique, MITREMitigation, MITREGroup, MITRESoftware, MITRECampaign


class StixParser():
    """
    Get and parse STIX data creating Tactics and Techniques objects
    Get the ATT&CK STIX data from MITRE/CTI GitHub repository.
    Domain should be 'enterprise-attack', 'mobile-attack', or 'ics-attack'. Branch should typically be master.
    """

    def __init__(self, repo_url, version='15.0'):
        self.url = repo_url
        self.version = version

        stix_json = requests.get(f"{self.url}/enterprise-attack/enterprise-attack-{version}.json").json()
        self.enterprise_attack = MemoryStore(stix_data=stix_json['objects'])
        
        stix_json = requests.get(f"{self.url}/mobile-attack/mobile-attack-{version}.json").json()
        self.mobile_attack = MemoryStore(stix_data=stix_json['objects'])

        stix_json = requests.get(f"{self.url}/ics-attack/ics-attack-{version}.json").json()
        self.ics_attack = MemoryStore(stix_data=stix_json['objects'])


    # Build data structures from STIX data
    def get_domain_data(self, domain):
        self.domain = domain

        if domain == 'enterprise-attack':
            self.src = self.enterprise_attack
        elif domain == 'mobile-attack':
            self.src = self.mobile_attack
        elif domain == 'ics-attack':
            self.src = self.ics_attack

        self._get_tactics()
        self._get_techniques()
        self._get_mitigations()


    def get_cti_data(self):
        self._get_groups()
        self._get_campaigns()
        self._get_software()


    def _get_tactics(self):
        """
        Get and parse tactics from STIX data
        """

        # Extract tactics
        tactics_stix = self.src.query([ Filter('type', '=', 'x-mitre-tactic') ])
        self.tactics = list()

        for tactic in tactics_stix:
            if ('x_mitre_deprecated' not in tactic or not tactic['x_mitre_deprecated']) and ('revoked' not in tactic or not tactic['revoked']):
                tactic_obj = MITRETactic(tactic['name'])
                added = []

                # Add attributes to the tactic object
                tactic_obj.description = tactic['description']
                tactic_obj.created = tactic.get('created', '')
                tactic_obj.modified = tactic.get('modified', '')
                tactic_obj.version = tactic.get('x_mitre_version', [])
                tactic_obj.shortname = tactic.get('x_mitre_shortname', '')

                # Get external references
                ext_refs = tactic.get('external_references', [])
                for ext_ref in ext_refs:
                    if ext_ref['source_name'] == 'mitre-attack':
                        tactic_obj.id = ext_ref['external_id']
                    elif 'url' in ext_ref and 'description' in ext_ref:
                        item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                        if item not in added:
                            tactic_obj.external_references = item
                            added.append(item)

                # Extract external references from relationships
                source_relationships = self.src.query([ Filter('type', '=', 'attack-pattern')])

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
        techniques_stix = self.src.query([ Filter('type', '=', 'attack-pattern') ])
        added = []

        self.techniques = list()

        # Extract tactics to build relationship between techniques and tactics
        tactics_stix = self.src.query([ Filter('type', '=', 'x-mitre-tactic') ])

        shortname_name = dict()

        for tactic in tactics_stix:
            shortname_name[tactic['x_mitre_shortname']] = tactic['name']

        for tech in techniques_stix:
            if ('x_mitre_deprecated' not in tech or not tech['x_mitre_deprecated']) and ('revoked' not in tech or not tech['revoked']):
                technique_obj = MITRETechnique(tech['name'])
                added = []

                # Add attributes to the technique object
                technique_obj.internal_id = tech['id']
                technique_obj.is_subtechnique = tech['x_mitre_is_subtechnique']
                technique_obj.platforms = tech.get('x_mitre_platforms', [])
                technique_obj.effective_permissions = tech.get('x_mitre_effective_permissions', [])
                technique_obj.permissions_required = tech.get('x_mitre_permissions_required', [])
                technique_obj.description = tech['description']
                technique_obj.defense_bypassed = tech.get('x_mitre_defense_bypassed', [])
                technique_obj.data_sources = tech.get('x_mitre_data_sources', [])
                technique_obj.created = tech.get('created', '')
                technique_obj.modified = tech.get('modified', '')
                technique_obj.version = tech.get('x_mitre_version', [])
                technique_obj.tactic = tech['kill_chain_phases'][0]['phase_name']
                technique_obj.detection = tech.get('x_mitre_detection', '')
                technique_obj.tactic_name = shortname_name[technique_obj.tactic]
                technique_obj.supports_remote = tech.get('x_mitre_remote_support', False)

                kill_chain = tech.get('kill_chain_phases', [])
                for kill_phase in kill_chain:
                    technique_obj.kill_chain_phases = kill_phase

                # Get external references
                ext_refs = tech.get('external_references', [])
                for ext_ref in ext_refs:
                    if ext_ref['source_name'] == 'mitre-attack':
                        technique_obj.id = ext_ref['external_id']
                    elif 'url' in ext_ref and 'description' in ext_ref:
                        item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                        if item not in added:
                            technique_obj.external_references = item
                            added.append(item)

                # Procedure examples
                procedure_examples = self.src.query([ Filter('type', '=', 'course-of-action'), Filter('id', '=', technique_obj.internal_id) ])

                # Mitigations
                mitigations_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'mitigates'), Filter('target_ref', '=', technique_obj.internal_id) ])

                for relation in mitigations_relationships:
                    ext_refs = relation.get('external_references', [])
                    for ext_ref in ext_refs:
                        if 'url' in ext_ref and 'description' in ext_ref:
                            item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                            if item not in added:
                                technique_obj.external_references = item
                                added.append(item)
                    mitigation = self.src.query([ Filter('type', '=', 'course-of-action'), Filter('id', '=', relation['source_ref']) ])[0]
                    ext_refs = mitigation.get('external_references', [])
                    for ext_ref in ext_refs:
                        if ext_ref['source_name'] == 'mitre-attack':
                            mitigation_id = ext_ref['external_id']
                    description = relation.get('description', '')
                    item = {'name': mitigation.get('name') , 'description': description, 'id': mitigation_id,}
                    if item not in added:
                        technique_obj.mitigations = item
                        added.append(item)

                ### Detection
                detections_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'detects'), Filter('target_ref', '=', technique_obj.internal_id) ])

                for relation in detections_relationships:
                    data_component = self.src.query([ Filter('type', '=', 'x-mitre-data-component'), Filter('id', '=', relation['source_ref']) ])[0]
                    data_component_name = data_component.get('name', '')
                    data_component_source_ref = data_component.get('x_mitre_data_source_ref', '')
                    data_source = self.src.query([ Filter('type', '=', 'x-mitre-data-source'), Filter('id', '=', data_component_source_ref) ])[0]
                    data_source_name = data_source.get('name', '')
                    ext_refs = data_source.get('external_references', [])
                    for ext_ref in ext_refs:
                        if ext_ref['source_name'] == 'mitre-attack':
                            data_source_id = ext_ref['external_id']
                        if 'url' in ext_ref and 'description' in ext_ref:
                            item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                            if item not in added:
                                technique_obj.external_references = item
                                added.append(item)
                    item = {'name': data_component_name, 'data_source': data_source_name, 'id': data_source_id, 'description': relation.get('description', '')}
                    if item not in added:
                        technique_obj.detections = item
                        added.append(item)

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
            if ('x_mitre_deprecated' not in mitigation or not mitigation['x_mitre_deprecated']) and \
                ('revoked' not in mitigation or not mitigation['revoked']) and \
                (self.domain in mitigation['x_mitre_domains']):
                mitigation_obj = MITREMitigation(mitigation['name'])
                added = []

                # Add attributes to the mitigation object
                mitigation_obj.internal_id = mitigation['id']
                mitigation_obj.description = mitigation['description']
                mitigation_obj.created = mitigation.get('created', '')
                mitigation_obj.modified = mitigation.get('modified', '')
                mitigation_obj.version = mitigation.get('x_mitre_version', [])

                # Get external references
                ext_refs = mitigation.get('external_references', [])
                for ext_ref in ext_refs:
                    if ext_ref['source_name'] == 'mitre-attack':
                        mitigation_obj.id = ext_ref['external_id']
                    elif 'url' in ext_ref and 'description' in ext_ref:
                        item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                        if item not in added:
                            mitigation_obj.external_references = item
                            added.append(item)

                mitigation_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'mitigates'), Filter('source_ref', '=', mitigation_obj.internal_id) ])

                for relationship in mitigation_relationships:
                    for technique in self.techniques:
                        if technique.internal_id == relationship['target_ref']:
                            mitigation_obj.mitigates = {'technique': technique, 'description': relationship.get('description', ''), 'domain': relationship.get('x_mitre_domains', '')}

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
        groups_enterprise_stix = self.enterprise_attack.query([ Filter('type', '=', 'intrusion-set') ])
        groups_mobile_stix = self.mobile_attack.query([ Filter('type', '=', 'intrusion-set') ])
        groups_ics_stix = self.ics_attack.query([ Filter('type', '=', 'intrusion-set') ])
        groups_stix = groups_enterprise_stix + groups_mobile_stix + groups_ics_stix

        # Extract software
        software_enterprise_malware_stix = self.enterprise_attack.query([ Filter('type', '=', 'malware')])
        software_enterprise_tool_stix = self.enterprise_attack.query([ Filter('type', '=', 'tool')])
        software_mobile_malware_stix = self.mobile_attack.query([ Filter('type', '=', 'malware')])
        software_mobile_tool_stix = self.mobile_attack.query([ Filter('type', '=', 'tool')])
        software_ics_malware_stix = self.ics_attack.query([ Filter('type', '=', 'malware')])
        software_ics_tool_stix = self.ics_attack.query([ Filter('type', '=', 'tool')])

        software_stix = software_enterprise_malware_stix + software_enterprise_tool_stix + software_mobile_malware_stix + software_mobile_tool_stix + software_ics_malware_stix + software_ics_tool_stix
        software_list = list()

        for software in software_stix:
            software_list.append(software)

        self.groups = list()

        for group in groups_stix:
            if ('x_mitre_deprecated' not in group or not group['x_mitre_deprecated']) and ('revoked' not in group or not group['revoked']):
                group_obj = MITREGroup(group['name'])
                added = []

                # Add attributes to the group object
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
                        item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                        if item not in added:
                            group_obj.external_references = item
                            added.append(item)
                    else:
                        if ext_ref['source_name'] != group_obj.name:
                            group_obj.aliases_references = {'name': ext_ref['source_name'], 'description': ext_ref['description']}

                source_enterprise_relationships = self.enterprise_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', group_obj.internal_id) ])
                source_mobile_relationships = self.mobile_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', group_obj.internal_id) ])
                source_ics_relationships = self.ics_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', group_obj.internal_id) ])

                source_relationships = source_enterprise_relationships + source_mobile_relationships + source_ics_relationships

                for relationship in source_relationships:
                    for technique in self.techniques:
                        if technique.internal_id == relationship['target_ref']:
                            group_obj.techniques_used = {'technique': technique, 'description': relationship.get('description', ''), 'domain': relationship.get('x_mitre_domains', [])}

                    if 'external_references' in relationship:
                        ext_refs = relationship.get('external_references', [])
                        for ext_ref in ext_refs:
                            if 'url' in ext_ref and 'description' in ext_ref:
                                item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                                if item not in added:
                                    group_obj.external_references = item
                                    added.append(item)

                software_enterprise_relationships = self.enterprise_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', group_obj.internal_id) ])
                software_mobile_relationships = self.mobile_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', group_obj.internal_id) ])
                software_ics_relationships = self.ics_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', group_obj.internal_id) ])

                software_relationships = software_enterprise_relationships + software_mobile_relationships + software_ics_relationships

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
                                group_obj.software_used = {'name': software['name'], 'id': external_id, 'description': relationship.get('description', '') }
                                added.append(item)

                self.groups.append(group_obj)


    def _get_software(self):
        """
        Get and parse software from STIX data
        """

        # Extract software
        software_enterprise_malware_stix = self.enterprise_attack.query([ Filter('type', '=', 'malware')])
        software_enterprise_tool_stix = self.enterprise_attack.query([ Filter('type', '=', 'tool')])
        software_mobile_malware_stix = self.mobile_attack.query([ Filter('type', '=', 'malware')])
        software_mobile_tool_stix = self.mobile_attack.query([ Filter('type', '=', 'tool')])
        software_ics_malware_stix = self.ics_attack.query([ Filter('type', '=', 'malware')])
        software_ics_tool_stix = self.ics_attack.query([ Filter('type', '=', 'tool')])

        software_stix = software_enterprise_malware_stix + software_enterprise_tool_stix + software_mobile_malware_stix + software_mobile_tool_stix + software_ics_malware_stix + software_ics_tool_stix

        self.software = list()

        for software in software_stix:
            if ('x_mitre_deprecated' not in software or not software['x_mitre_deprecated']) and ('revoked' not in software or not software['revoked']):
                software_obj = MITRESoftware(software['name'])
                added = []

                # Add attributes to the software object
                software_obj.internal_id = software['id']
                software_obj.type = software['type']
                software_obj.platforms = software.get('x_mitre_platforms', [])
                software_obj.contributors = software.get('x_mitre_contributors', [])
                software_obj.version = software.get('x_mitre_version', [])
                software_obj.description = software.get('description', '')
                software_obj.created = software.get('created', '')
                software_obj.modified = software.get('modified', '')
                software_obj.aliases = software.get('aliases', [])

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

                source_relationships_enterprise = self.enterprise_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', software_obj.internal_id) ])
                source_relationships_mobile = self.mobile_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', software_obj.internal_id) ])
                source_relationships_ics = self.ics_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', software_obj.internal_id) ])

                techniques_enterprise_stix = self.enterprise_attack.query([ Filter('type', '=', 'attack-pattern') ])
                techniques_mobile_stix = self.mobile_attack.query([ Filter('type', '=', 'attack-pattern') ])
                techniques_ics_stix = self.ics_attack.query([ Filter('type', '=', 'attack-pattern') ])

                techniques_stix = techniques_enterprise_stix + techniques_mobile_stix + techniques_ics_stix

                source_relationships = source_relationships_enterprise + source_relationships_mobile + source_relationships_ics
                for relationship in source_relationships:
                    for technique in techniques_stix:
                        if technique['id'] == relationship['target_ref']:
                            if 'x_mitre_deprecated' not in technique or not technique['x_mitre_deprecated']:
                                software_obj.techniques_used = {'technique': technique, 'description': relationship.get('description', ''), 'domain': technique.get('x_mitre_domains', [])}

                    if 'external_references' in relationship:
                        ext_refs = relationship.get('external_references', [])
                        for ext_ref in ext_refs:
                            if 'url' in ext_ref and 'description' in ext_ref:
                                item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                                if item not in added:
                                    software_obj.external_references = item
                                    added.append(item)

                target_relationships_enterprise = self.enterprise_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('target_ref', '=', software_obj.internal_id) ])
                target_relationships_mobile = self.mobile_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('target_ref', '=', software_obj.internal_id) ])
                target_relationships_ics = self.ics_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('target_ref', '=', software_obj.internal_id) ])

                target_relationships = target_relationships_enterprise + target_relationships_mobile + target_relationships_ics

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

                # Used in campaigns
                source_relationships_enterprise = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', software_obj.internal_id) ])
                source_relationships_mobile = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', software_obj.internal_id) ])
                source_relationships_ics = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', software_obj.internal_id) ])

                source_relationships = source_relationships_enterprise + source_relationships_mobile + source_relationships_ics

                for relationship in source_relationships:
                    for campaign in self.campaigns:
                        if campaign.internal_id == relationship['target_ref']:
                            software_obj.campaigns_using = {'campaign': campaign, 'description': relationship.get('description', '') }

                    if 'external_references' in relationship:
                        ext_refs = relationship.get('external_references', [])
                        for ext_ref in ext_refs:
                            if 'url' in ext_ref and 'description' in ext_ref:
                                item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                                if item not in added:
                                    software_obj.external_references = item
                                    added.append(item)

                self.software.append(software_obj)


    def _get_campaigns(self):
        """
        Get and parse campaigns from STIX data
        """

        # Extract campaigns
        enterprise_stix = self.enterprise_attack.query([ Filter('type', '=', 'campaign') ])
        mobile_stix = self.mobile_attack.query([ Filter('type', '=', 'campaign') ])
        ics_stix = self.ics_attack.query([ Filter('type', '=', 'campaign') ])

        campaigns_stix = enterprise_stix + mobile_stix + ics_stix

        self.campaigns = list()

        for campaign in campaigns_stix:
            if ('x_mitre_deprecated' not in campaign or not campaign['x_mitre_deprecated']) and ('revoked' not in campaign or not campaign['revoked']):
                campaign_obj = MITRECampaign(campaign['name'])
                added = []
                groups_added = []

                # Add attributes to the campaign object
                campaign_obj.internal_id = campaign['id']
                campaign_obj.aliases = campaign.get('aliases', [])
                campaign_obj.description = campaign.get('description', '')
                campaign_obj.version = campaign.get('x_mitre_version', [])
                campaign_obj.created = campaign.get('created', '')
                campaign_obj.modified = campaign.get('modified', '')
                campaign_obj.first_seen = campaign.get('first_seen', '')
                campaign_obj.last_seen = campaign.get('last_seen', '')

                # Get external references
                ext_refs = campaign.get('external_references', [])

                for ext_ref in ext_refs:
                    if ext_ref['source_name'] == 'mitre-attack':
                        campaign_obj.id = ext_ref['external_id']
                    elif 'url' in ext_ref and 'description' in ext_ref:
                        item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                        if item not in added:
                            campaign_obj.external_references = item
                            added.append(item)

                # Get group(s) associated with the campaign
                group_relationships_enterprise = self.enterprise_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'attributed-to'), Filter('source_ref', '=', campaign_obj.internal_id) ])
                group_relationships_mobile = self.mobile_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'attributed-to'), Filter('source_ref', '=', campaign_obj.internal_id) ])
                group_relationships_ics = self.ics_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'attributed-to'), Filter('source_ref', '=', campaign_obj.internal_id) ])

                group_relationships = group_relationships_enterprise + group_relationships_mobile + group_relationships_ics

                for relationship in group_relationships:
                    for group in self.groups:
                        if group.internal_id == relationship['target_ref']:
                            if group.internal_id not in groups_added:
                                campaign_obj.groups = {'group': group, 'description': relationship.get('description', '')}
                                groups_added.append(group.internal_id)

                # Get software used in the campaign
                software_relationships_enterprise = self.enterprise_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', campaign_obj.internal_id) ])
                software_relationships_mobile = self.mobile_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', campaign_obj.internal_id) ])
                software_relationships_ics = self.ics_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', campaign_obj.internal_id) ])
                
                software_relationships = software_relationships_enterprise + software_relationships_mobile + software_relationships_ics

                software_malware_enterprise = self.enterprise_attack.query([ Filter('type', '=', 'malware')])
                software_malware_mobile = self.mobile_attack.query([ Filter('type', '=', 'malware')])
                software_malware_ics = self.ics_attack.query([ Filter('type', '=', 'malware')])
    
                software_malware = software_malware_enterprise + software_malware_mobile + software_malware_ics
                
                software_tool_enterprise = self.enterprise_attack.query([ Filter('type', '=', 'tool')])
                software_tool_mobile = self.mobile_attack.query([ Filter('type', '=', 'tool')])
                software_tool_ics = self.ics_attack.query([ Filter('type', '=', 'tool')])

                software_tool = software_tool_enterprise + software_tool_mobile + software_tool_ics
                softwares = software_malware + software_tool

                software_added = []
                for relationship in software_relationships:
                    if campaign_obj.internal_id == relationship['source_ref']:
                        for software in softwares:
                            if software['id'] == relationship['target_ref']:
                                item = {'software': software, 'description': relationship.get('description', '')}
                                if item not in software_added:
                                    campaign_obj.software_used = item
                                    software_added.append(item)

                source_relationships_enterprise = self.enterprise_attack.query([ Filter('type', '=', 'relationship'), Filter('source_ref', '=', campaign_obj.internal_id) ])
                source_relationships_mobile = self.mobile_attack.query([ Filter('type', '=', 'relationship'), Filter('source_ref', '=', campaign_obj.internal_id) ])
                source_relationships_ics = self.ics_attack.query([ Filter('type', '=', 'relationship'), Filter('source_ref', '=', campaign_obj.internal_id) ])

                source_relationships = source_relationships_enterprise + source_relationships_mobile + source_relationships_ics

                for relationship in source_relationships:
                    for technique in self.techniques:
                        if technique.internal_id == relationship['target_ref']:
                            campaign_obj.techniques_used = {'technique': technique, 'description': relationship.get('description', ''), 'domain': relationship.get('x_mitre_domains', [])}

                    if 'external_references' in relationship:
                        ext_refs = relationship.get('external_references', [])
                        for ext_ref in ext_refs:
                            if 'url' in ext_ref and 'description' in ext_ref:
                                item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                                if item not in added:
                                    campaign_obj.external_references = item
                                    added.append(item)

                self.campaigns.append(campaign_obj)
