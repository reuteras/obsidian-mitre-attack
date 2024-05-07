# obsidian-mitre-attack

This is a changed version of the original repository [vincenzocaputo/obsidian-mitre-attack](https://github.com/vincenzocaputo/obsidian-mitre-attack). Some functions have been removed (create canvas) and some have been added (generating software and campaigns).

## TODO

- Add more relevant tags and consider prepending tags with **attack** or use **attack/<tag>**.
- Add other metadata? Att&ck ID, etc.
- Add [Data sources](https://attack.mitre.org/datasources/)
- Add [Assets](https://attack.mitre.org/assets/)
- Should top level pages be added to each category or are they not needed when ATT&CK is used in Obsidian?
- Check for unused code and remove it. Since speed is not the main concern (runs one time) it has not been top priority.

Missing in the current implementation:

- Groups
  - First version done.
- Mitigations
  - First version done.
- Campaigns
  - First version done.
- Software
  - First version done.
- Tactics
  - First version done.
- Techniques
  - No links to data sources since they are not implemented yet.

Current time to run the scripts and the different parts in verbose mode:

```bash
2024-05-07 09:16:29 - Getting STIX data from https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master for version 15.1
2024-05-07 09:17:48 - STIX data loaded successfully
2024-05-07 09:17:48 - Getting tactics data for enterprise-attack domain
2024-05-07 09:17:48 - Getting techniques data for enterprise-attack domain
2024-05-07 09:21:48 - Getting mitigations data for enterprise-attack domain
2024-05-07 09:21:50 - Getting groups data
2024-05-07 09:33:20 - Getting campaigns data
2024-05-07 09:33:27 - Getting software data
2024-05-07 09:37:52 - Getting tactics data for mobile-attack domain
2024-05-07 09:37:52 - Getting techniques data for mobile-attack domain
2024-05-07 09:37:56 - Getting mitigations data for mobile-attack domain
2024-05-07 09:37:56 - Getting tactics data for ics-attack domain
2024-05-07 09:37:56 - Getting techniques data for ics-attack domain
2024-05-07 09:37:59 - Getting mitigations data for ics-attack domain
```

## Original README.md

Below is a slightly updated version of the original README.md file. Updates are relating to changed functionality. Original README.md can be found [here](https://github.com/vincenzocaputo/obsidian-mitre-attack).

This repository implements a Python script that parses the MITRE ATT&CK knowledge base into a Markdown format, making it readable and browsable using the Obsidian note-taking app.
The ATT&CK data is retrieved from the MITRE GitHub repository ([https://github.com/mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)) that contains the dataset represented in STIX 2.1 JSON collection.
The main idea behind this project is to make the MITRE ATT&CK knowledge base easily accessible and seamlessly integrable into Obsidian, along with reports or your personal notes. Utilizing Obsidian's features such as hyperlinks, tags, graph view, and more can greatly support threat intelligence analysis and investigations.

## Quick Start

### Installation

Clone this repository

```bash
git clone https://github.com/vincenzocaputo/obsidian-mitre-attack.git
```
Create a Python virtual environment

```bash
cd obsidian-mitre-attack
python3 -m venv venv
source venv/bin/activate
```

Install Python module dependencies
```bash
python3 -m pip install -r requirements.txt
```

### Run

Run the application specifying the output directory path (i.e.: your obsidian vault)

```bash
python3 . -o obsidian_vault_path
```

### Options

```bash
usage: . [-h] [--path PATH] [-o OUTPUT]

Download MITRE ATT&CK STIX data and parse it to Obsidian markdown notes

options:
  -h, --help            show this help message and exit
  --path PATH           Filepath to the markdown note file
  -o OUTPUT, --output OUTPUT
                        Output directory in which the notes will be saved. It should be placed inside a Obsidian vault.

```

