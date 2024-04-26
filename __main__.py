from src.stix_parser import StixParser
from src.markdown_generator import MarkdownGenerator
from src.view import create_graph_json
from src.markdown_reader import MarkdownReader
import argparse
import os
import yaml
import re

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Download MITRE ATT&CK STIX data and parse it to Obsidian markdown notes')

    parser.add_argument('-d', '--domain', help="Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'", default='enterprise-attack')
    parser.add_argument('-o', '--output', help="Output directory in which the notes will be saved. It should be placed inside a Obsidian vault.")
    parser.add_argument('--generate-hyperlinks', help="Generate techniques hyperlinks in a markdown note file", action="store_true")
    parser.add_argument('--generate-matrix', help="Create ATT&CK matrix starting from a markdown note file", action="store_true")
    parser.add_argument('--path', help="Filepath to the markdown note file")

    args = parser.parse_args()

    with open('config.yml', 'r') as fd:
        config = yaml.safe_load(fd)

    if args.domain:
        domain = args.domain
    else:
        domain = config['domain']
    if domain not in ('enterprise-attack', 'mobile-attack', 'ics-attack'):
        raise ValueError("The domain provided is not supported")

    stix_data = StixParser(config['repository_url'], domain, version=config['version'])

    stix_data.get_data()

    if args.output:
        output_dir = args.output + '/' + domain.replace('-', ' ').capitalize()
        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
    else:
        print("Provide an output directory via the -o flag (e.g. -o /path/to/your/vault/notes)")
        exit()

    if args.generate_hyperlinks:
        if args.path:
            if os.path.isfile(args.path) and args.path.endswith('.md'):
                markdown_reader = MarkdownReader(args.path)
                markdown_reader.create_hyperlinks(stix_data.techniques)
            else:
                print("You have not provided a valid markdown file path")
        else:
            print("Provide a file path")
    elif args.generate_matrix:
        if args.path:
            if os.path.isfile(args.path) and args.path.endswith('.md'):
                markdown_reader = MarkdownReader(args.path)
                found_techniques = markdown_reader.find_techniques()
                markdown_generator = MarkdownGenerator(output_dir, stix_data.techniques, stix_data.groups, stix_data.tactics, stix_data.mitigations, stix_data.software, stix_data.campaigns)
                markdown_generator.create_canvas(re.sub('.md$',"",args.path), found_techniques)
            else:
                print("You have not provided a valid markdown file path")
        else:
            print("Provide a file path")
    else:
        # Main functionality
        os.chdir(os.path.dirname(os.path.abspath(__file__)))

        markdown_generator = MarkdownGenerator(output_dir, stix_data.techniques, stix_data.groups, stix_data.tactics, stix_data.mitigations, stix_data.software, stix_data.campaigns)
        markdown_generator.create_software_notes()
        markdown_generator.create_tactic_notes()
        markdown_generator.create_technique_notes()
        markdown_generator.create_mitigation_notes()
        markdown_generator.create_group_notes()
        markdown_generator.create_campaign_notes()

        create_graph_json(output_dir)
