"""Init file for project."""
import argparse
import datetime
from pathlib import Path
from typing import Any

import toml

from .markdown_generator import MarkdownGenerator
from .stix_parser import StixParser


def create_main_readme(arguments, domains, config) -> None:
    """Create the main README file for the MITRE ATT&CK collection."""
    attack_file = Path(arguments.output, "MITRE ATT&CK.md")
    with open(file=attack_file, mode='w') as fd:
        content: str = "---\n"
        content += "alias:\n"
        content += "  - MITRE ATT&CK®\n"
        content += "tags:\n"
        content += f"  - {arguments.tags}mitre_attack\n"
        content += "---\n\n"

        content += "# MITRE ATT&CK®\n\n"
        content += "This is a collection of of the MITRE ATT&CK®[^mitre] framework for Obsidian.\n\n"
        current_date: str = datetime.datetime.now().strftime(format="%Y-%m-%d %H:%M:%S")
        content += "Generated by obsidian-mitre-attack[^obsidian-mitre-attack] on " + current_date + ".\n\n"
        content += "This collection is based on the following ATT&CK domains:\n\n"
        for domain in domains:
            content += "- " + domain + " version " + str(object=config['version']) + ".\n"
        content += "\n[^obsidian-mitre-attack]: [https://github.com/reuteras/obsidian-mitre-attack](https://github.com/reuteras/obsidian-mitre-attack)\n"
        content += "[^mitre]: [MITRE ATT&CK®](https://attack.mitre.org/)\n"
        fd.write(content)

def main() -> None:
    """Main function for obsidian-mitre-attack."""
    domains: list[str] = [
        'enterprise-attack',
        'mobile-attack',
        'ics-attack'
    ]
    parser = argparse.ArgumentParser(
        description='Download MITRE ATT&CK STIX data and parse it to Obsidian markdown notes.'
    )

    parser.add_argument('-o', '--output', dest='output',
                        help="Output directory in which the notes will be saved."
    )
    parser.add_argument('-t', '--tags', dest='tags',
                        help="Prepend this string to tags in the markdown files."
    )
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        help="Print verbose output."
    )

    args: argparse.Namespace = parser.parse_args()

    try:
        with open(file='config.toml', encoding="utf8") as fd:
            config: dict[str, Any] = toml.load(f=fd)
    except FileNotFoundError as error:
        raise FileNotFoundError("You need to create a 'config.toml' file.") from error

    if not args.output and not config['output_dir']:
        raise ValueError("You need to provide an output directory")

    if not args.output:
        args.output = config['output_dir']

    if not args.tags:
        args.tags = ""

    if not args.verbose:
        args.verbose = config['verbose']

    stix_data = StixParser(
        repo_url=config['repository_url'],
        version=config['version'],
        verbose=args.verbose
    )

    output_dir: str = args.output
    Path(output_dir).mkdir(exist_ok=True, parents=True)

    for domain in domains:
        stix_data.get_domain_data(domain=domain)

    stix_data.get_cti_data()
    markdown_generator = MarkdownGenerator(
        output_dir=output_dir,
        stix_data=stix_data,
        arguments=args,
    )

    for domain in domains:
        markdown_generator.create_tactic_notes(domain=domain)
        markdown_generator.create_technique_notes(domain=domain)
        markdown_generator.create_mitigation_notes(domain=domain)

    markdown_generator.create_software_notes()
    markdown_generator.create_group_notes()
    markdown_generator.create_campaign_notes()
    markdown_generator.create_asset_notes()
    markdown_generator.create_data_source_notes()

    # Generate Main README file
    create_main_readme(arguments=args, domains=domains, config=config)
