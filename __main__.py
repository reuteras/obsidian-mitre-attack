from src.stix_parser import StixParser
from src.markdown_generator import MarkdownGenerator
import argparse
import datetime
import os
import yaml

if __name__ == '__main__':
    domains = ['enterprise-attack', 'mobile-attack', 'ics-attack']
    parser = argparse.ArgumentParser(description='Download MITRE ATT&CK STIX data and parse it to Obsidian markdown notes')

    parser.add_argument('--path', help="Filepath to the markdown note file")
    parser.add_argument('-o', '--output', help="Output directory in which the notes will be saved. It should be placed inside a Obsidian vault.")

    args = parser.parse_args()

    with open('config.yml', 'r') as fd:
        config = yaml.safe_load(fd)

    if not args.output:
        raise ValueError("You need to provide an output directory")
    
    # Main functionality
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    stix_data = StixParser(config['repository_url'], version=config['version'], verbose=config['verbose'])

    for domain in domains:
        stix_data.get_domain_data(domain)
        # Only run one time. Could be for any domain
        if domain == 'enterprise-attack':
            stix_data.get_cti_data()

        output_dir = args.output
        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        markdown_generator = MarkdownGenerator(output_dir, stix_data.techniques, stix_data.groups, stix_data.tactics, stix_data.mitigations, stix_data.software, stix_data.campaigns)
        markdown_generator.create_tactic_notes(domain.replace('-', ' ').capitalize().replace('Ics ', 'ICS '))
        markdown_generator.create_technique_notes(domain.replace('-', ' ').capitalize().replace('Ics ', 'ICS '))
        markdown_generator.create_mitigation_notes(domain.replace('-', ' ').capitalize().replace('Ics ', 'ICS '))

        # Only run one time. Could be for any domain
        if domain == 'enterprise-attack':
            markdown_generator.create_software_notes()
            markdown_generator.create_group_notes()
            markdown_generator.create_campaign_notes()

    # Generate Main README file
    attack_file = os.path.join(args.output, "MITRE ATT&CK.md")
    with open(attack_file, 'w') as fd:
        content = "---\n"
        content += "alias:\n"
        content += "  - MITRE ATT&CK®\n"
        content += "tags:\n"
        content += "  - mitre_attack\n"
        content += "---\n\n"

        content += "# MITRE ATT&CK®\n\n"
        content += "This is a collection of of the MITRE ATT&CK®[^mitre] framework for Obsidian.\n\n"
        content += "Generated by obsidian-mitre-attack[^obsidian-mitre-attack] on " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ".\n\n"
        content += "This collection is based on the following ATT&CK domains:\n\n" 
        for domain in domains:
            content += "- " + domain + " version " + str(config['version']) + ".\n"  
        content += "\n[^obsidian-mitre-attack](https://github.com/reuteras/obsidian-mitre-attack))\n"
        content += "[^mitre]: [MITRE ATT&CK®](https://attack.mitre.org/)\n"
        fd.write(content) 
