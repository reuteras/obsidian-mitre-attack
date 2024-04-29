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

    def __init__(self, repo_url, domain, version='15.0', campaigns=False):
        self.url = repo_url
        self.domain = domain
        self.version = version
        self.generate_campaigns = campaigns

        stix_json = requests.get(f"{self.url}/{domain}/{domain}-{version}.json").json()

        self.src = MemoryStore(stix_data=stix_json['objects'])

        self.enterprise_attack = None
        self.mobile_attack = None
        self.ics_attack = None

        if self.generate_campaigns:
            if domain == 'enterprise-attack':
                self.enterprise_attack = MemoryStore(stix_data=stix_json['objects'])
            elif domain == 'mobile-attack':
                self.mobile_attack = MemoryStore(stix_data=stix_json['objects'])
            elif domain == 'ics-attack':
                self.ics_attack = MemoryStore(stix_data=stix_json['objects'])
        
        if not self.enterprise_attack:
            stix_json = requests.get(f"{self.url}/enterprise-attack/enterprise-attack-{version}.json").json()
            self.enterprise_attack = MemoryStore(stix_data=stix_json['objects'])
        
        if not self.mobile_attack:
            stix_json = requests.get(f"{self.url}/mobile-attack/mobile-attack-{version}.json").json()
            self.mobile_attack = MemoryStore(stix_data=stix_json['objects'])

        if not self.ics_attack:
            stix_json = requests.get(f"{self.url}/ics-attack/ics-attack-{version}.json").json()
            self.ics_attack = MemoryStore(stix_data=stix_json['objects'])


    def get_data(self):
        self._get_tactics()
        self._get_techniques()
        self._get_mitigations()
        self._get_groups()
        if self.generate_campaigns:
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
            tactic_obj = MITRETactic(tactic['name'])

            tactic_obj.description = tactic['description']
            tactic_obj.created = tactic.get('created', '')
            tactic_obj.modified = tactic.get('modified', '')
            tactic_obj.version = tactic.get('x_mitre_version', [])
            tactic_obj.shortname = tactic.get('x_mitre_shortname', '')

            # Extract external references, including the link to mitre
            ext_refs = tactic.get('external_references', [])

            for ext_ref in ext_refs:
                if ext_ref['source_name'] == 'mitre-attack':
                    tactic_obj.id = ext_ref['external_id']
                elif 'url' in ext_ref and 'description' in ext_ref:
                    tactic_obj.references = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}

            # Extract external references from relationships
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

        # Extract tactics to build relationship between techniques and tactics
        tactics_stix = self.src.query([ Filter('type', '=', 'x-mitre-tactic') ])

        shortname_name = dict()

        for tactic in tactics_stix:
            shortname_name[tactic['x_mitre_shortname']] = tactic['name']

        # Extract techniques
        techniques_stix = self.src.query([ Filter('type', '=', 'attack-pattern') ])

        self.techniques = list()

        for tech in techniques_stix:
            if 'x_mitre_deprecated' not in tech or not tech['x_mitre_deprecated']:
                technique_obj = MITRETechnique(tech['name'])

                technique_obj.internal_id = tech['id']

                # Use added to track added external references
                added = []

                # Get external references
                ext_refs = tech.get('external_references', [])

                # Extract external references and set the technique id
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
                technique_obj.detection = tech.get('x_mitre_detection', '')
                technique_obj.tactic_name = shortname_name[technique_obj.tactic]

                # Extract external references from relationships
                source_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', technique_obj.internal_id) ])

                added = []
                for relationship in source_relationships:
                    if 'external_references' in relationship:
                        ext_refs = relationship.get('external_references', [])
                        for ext_ref in ext_refs:
                            if 'url' in ext_ref and 'description' in ext_ref:
                                item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                                if item not in added:
                                    technique_obj.external_references = item
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

                # Used in campaigns
                source_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', software_obj.internal_id) ])

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
            if campaign.get('x_mitre_deprecated', False) != 'true':
                campaign_obj = MITRECampaign(campaign['name'])

                campaign_obj.internal_id = campaign['id']
                campaign_obj.aliases = campaign.get('aliases', [])
                campaign_obj.description = campaign.get('description', '')
                campaign_obj.version = campaign.get('x_mitre_version', [])
                campaign_obj.created = campaign.get('created', '')
                campaign_obj.modified = campaign.get('modified', '')
                campaign_obj.first_seen = campaign.get('first_seen', '')
                campaign_obj.last_seen = campaign.get('last_seen', '')

                # Get group(s) associated with the campaign
                group_relationships_enterprise = self.enterprise_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'attributed-to'), Filter('source_ref', '=', campaign_obj.internal_id) ])
                group_relationships_mobile = self.mobile_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'attributed-to'), Filter('source_ref', '=', campaign_obj.internal_id) ])
                group_relationships_ics = self.ics_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'attributed-to'), Filter('source_ref', '=', campaign_obj.internal_id) ])

                group_relationships = group_relationships_enterprise + group_relationships_mobile + group_relationships_ics

                for relationship in group_relationships:
                    for group in self.groups:
                        if group.internal_id == relationship['target_ref']:
                            campaign_obj.groups = {'group': group, 'description': relationship.get('description', '') }

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

                for relationship in software_relationships:
                    if campaign_obj.internal_id == relationship['source_ref']:
                        for software in softwares:
                            if software['id'] == relationship['target_ref']:
                                campaign_obj.software_used = {'software': software, 'description': relationship.get('description', '') }

                # Extract external references, including the link to mitre
                ext_refs = campaign.get('external_references', [])

                for ext_ref in ext_refs:
                    if ext_ref['source_name'] == 'mitre-attack':
                        campaign_obj.id = ext_ref['external_id']
                    elif 'url' in ext_ref:
                        campaign_obj.aliases_references = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                    else:
                        if ext_ref['source_name'] != campaign_obj.name:
                            campaign_obj.aliases_references = {'name': ext_ref['source_name'], 'description': ext_ref['description']}

                source_relationships_enterprise = self.enterprise_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', campaign_obj.internal_id) ])
                source_relationships_mobile = self.mobile_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', campaign_obj.internal_id) ])
                source_relationships_ics = self.ics_attack.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', campaign_obj.internal_id) ])

                source_relationships = source_relationships_enterprise + source_relationships_mobile + source_relationships_ics
                added = []
                for relationship in source_relationships:
                    for technique in self.techniques:
                        if technique.internal_id == relationship['target_ref']:
                            campaign_obj.techniques_used = {'technique': technique, 'description': relationship.get('description', '') }

                    if 'external_references' in relationship:
                        ext_refs = relationship.get('external_references', [])
                        for ext_ref in ext_refs:
                            if 'url' in ext_ref and 'description' in ext_ref:
                                item = {'name': ext_ref['source_name'], 'url': ext_ref['url'], 'description': ext_ref['description']}
                                if item not in added:
                                    campaign_obj.external_references = item
                                    added.append(item)

                self.campaigns.append(campaign_obj)
