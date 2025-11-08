# obsidian-mitre-attack

This is a modified and extended version of the original version that can be found here [vincenzocaputo/obsidian-mitre-attack](https://github.com/vincenzocaputo/obsidian-mitre-attack). Some functions have been removed (create canvas) and some have been added such as always generating the full MITRE ATT&CK (enterprise-attack, ics-attack and mobile-attack) as well as adding some missing parts for the original repository.

Python code is used to parse the MITRE ATT&CK knowledge base into Markdown format, making it readable and browsable using the Obsidian note-taking application.
MITRE ATT&CK data is retrieved from the MITRE GitHub repository ([https://github.com/mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)) in STIX 2.1 JSON format.

The main idea behind this project is to make the MITRE ATT&CK knowledge base easily accessible and seamlessly integrable into Obsidian, along with reports or your personal notes. Utilizing Obsidian's features such as hyperlinks, tags, graph view, and more can greatly support threat intelligence analysis and investigations.

## Quick start from release

Generating the files takes a long time at the moment and it is recommended that you download the release zip-file that contains the result of running the code. After downloading it unzip it and place the content of the _MITRE_ folder in your Obsidian vault.

## Example usage

With the [Dataview](https://github.com/blacksmithgu/obsidian-dataview) plugin for Obsidian installed you can get a list of f MITRE ATT&CK _techniques_ or _software_ (or something else) for the current note with the following code.

~~~markdown
## Techniques

```dataview
list from #technique
WHERE contains(file.inlinks, this.file.link)
```

## Tools and malware

```dataview
list from #tool or #malware
WHERE contains(file.inlinks, this.file.link)
```
~~~

The image below shows the source of a simple investigation of a made up attack by [APT28](https://attack.mitre.org/groups/G0007/).

![Markdown example in Obsidian](https://raw.githubusercontent.com/reuteras/obsidian-mitre-attack/main/resources/text.png)

Result is shown below.

![Result in Obsidian with lists generated](https://raw.githubusercontent.com/reuteras/obsidian-mitre-attack/main/resources/text.png)

Locking at the graph it is also easy to see that [T1548.004](https://attack.mitre.org/techniques/T1548/004/) is not associated with APT28 by MITRE ATT&CK.

![Result in Obsidian with lists generated](https://raw.githubusercontent.com/reuteras/obsidian-mitre-attack/main/resources/graph.png)

The Markdown shown above is available [here](./sample.md).


## Development

### Installation

Clone this repository

```bash
git clone https://github.com/vincenzocaputo/obsidian-mitre-attack.git
```

Use `uv`.

```bash
cd obsidian-mitre-attack
uv sync --frozen
```

### Run

Run the application specifying the output directory path (i.e.: your obsidian vault) with a full path

```bash
uv run obsidian-mitre-attack --output $(pwd)/output --tags 'mitre/'
```

### Options

```bash
usage: obsidian-mitre-attack [-h] [-o OUTPUT] [-t TAGS] [-v]

Download MITRE ATT&CK STIX data and parse it to Obsidian markdown notes.

options:
  -h, --help           show this help message and exit
  -o, --output OUTPUT  Output directory in which the notes will be saved.
  -t, --tags TAGS      Prepend this string to tags in the markdown files.
  -v, --verbose        Print verbose output.
```

### Configuration

Create a `config.toml` file in the root directory based on `default-config.toml`. Available configuration options:

```toml
repository_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
output_dir = "output"
version = "18.0"
verbose = true
# Embed Analytics within Detection Strategies using tab-panels plugin syntax
# When true, Analytics are included as tabs in Detection Strategy files
# Requires: https://github.com/GnoxNahte/obsidian-tab-panels
embed_analytics_in_detection_strategies = false
```

#### Embedding Analytics in Detection Strategies

By default, Detection Strategies link to separate Analytics files. Setting `embed_analytics_in_detection_strategies = true` will embed the full Analytics content within Detection Strategy files using tab-panels syntax, similar to how they appear on the [MITRE ATT&CK website](https://attack.mitre.org/detectionstrategies/DET0119/).

**Requirements:**
- Install the [obsidian-tab-panels](https://github.com/GnoxNahte/obsidian-tab-panels) plugin in Obsidian
- This feature is useful for viewing all related analytics in one place without navigating between files

**Example output:**
When enabled, each Detection Strategy file will include tabs for each associated analytic:

```tabs
--- ANO001 (Windows, macOS)
[Analytic content here...]

--- ANO002 (Linux)
[Analytic content here...]
```
