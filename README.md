# obsidian-mitre-attack

Convert MITRE ATT&CK® knowledge base to Obsidian-compatible Markdown notes with advanced cross-linking and detection strategies for ATT&CK v18.0.

[![Tests](https://github.com/reuteras/obsidian-mitre-attack/actions/workflows/tests.yml/badge.svg)](https://github.com/reuteras/obsidian-mitre-attack/actions/workflows/tests.yml)
[![Linter](https://github.com/reuteras/obsidian-mitre-attack/actions/workflows/linter.yml/badge.svg)](https://github.com/reuteras/obsidian-mitre-attack/actions/workflows/linter.yml)

## Overview

This project parses MITRE ATT&CK® STIX 2.1 data and converts it into beautifully structured Markdown files optimized for [Obsidian](https://obsidian.md/). The generated notes include cross-references, tags, and metadata that leverage Obsidian's powerful linking, graph view, and query capabilities.

**What's included:**
- ✅ All three ATT&CK domains: Enterprise, Mobile, and ICS
- ✅ Comprehensive coverage: Tactics, Techniques, Mitigations, Groups, Software, Campaigns, Assets, Data Sources
- ✅ NEW in v18: Detection Strategies and Analytics with full cross-linking
- ✅ Automatic internal linking using Obsidian's `[[wikilinks]]` syntax
- ✅ YAML frontmatter with aliases and tags for advanced querying
- ✅ Two output modes: standard (separate files) or embedded (requires plugin)

This is an extended fork of [vincenzocaputo/obsidian-mitre-attack](https://github.com/vincenzocaputo/obsidian-mitre-attack) with significant enhancements including support for ATT&CK v18.0 detection strategies and analytics.

## Quick Start

### Option 1: Download Pre-Generated Files (Recommended)

Download the latest release from the [Releases page](https://github.com/reuteras/obsidian-mitre-attack/releases):

1. **Standard version** (`mitre-attack-obsidian-standard.zip`):
   - Works with vanilla Obsidian
   - Analytics are separate files linked from Detection Strategies

2. **Embedded version** (`mitre-attack-obsidian-embedded.zip`):
   - Requires [obsidian-tab-panels](https://github.com/GnoxNahte/obsidian-tab-panels) plugin
   - Analytics embedded as tabs within Detection Strategy files
   - Matches MITRE ATT&CK website layout

Extract the ZIP file and copy the `MITRE` folder into your Obsidian vault.

### Option 2: Generate Fresh Files

```bash
# Clone the repository
git clone https://github.com/reuteras/obsidian-mitre-attack.git
cd obsidian-mitre-attack

# Install dependencies using uv
uv sync

# Create configuration file
cp default-config.toml config.toml

# Generate files (output to ./output directory)
uv run obsidian-mitre-attack --output $(pwd)/output --tags 'mitre/'
```

## Features

### Detection Strategies (NEW in v18.0)

Techniques now include a **Detection Strategy** section that links to analytics with detailed detection guidance:

| ID | Name | Analytic ID | Analytic Description |
| --- | --- | --- | --- |
| [[Detection Strategy for X]] | Detection Strategy for X | [[AN0001]] | Detects behavior Y using... |

Each Detection Strategy includes:
- Links to all techniques it detects
- Associated analytics with log sources and mutable elements
- Platform-specific detection approaches (Windows, Linux, macOS)

### Comprehensive Cross-Linking

All entities are automatically linked:
- Techniques → Tactics, Mitigations, Detection Strategies, Groups, Software
- Groups → Techniques, Software, Campaigns
- Software → Techniques, Groups, Campaigns
- Detection Strategies → Techniques, Analytics

### Obsidian Integration

Generated notes include:
- **YAML frontmatter** with aliases and tags
- **Callouts** for metadata and summaries
- **Tables** for procedures, mitigations, and detections
- **Footnotes** for references
- **Wikilinks** for seamless navigation

## Usage Examples

### With Dataview Plugin

Query techniques used by a specific group:

```dataview
TABLE
  file.link AS Technique,
  Tactic AS "Tactic"
FROM #mitre/technique
WHERE contains(file.inlinks, this.file.link)
SORT Tactic ASC
```

Query all software used by groups in your notes:

```dataview
TABLE
  file.link AS Software,
  Type
FROM #mitre/software
WHERE contains(file.inlinks, this.file.link)
```

### Graph View Navigation

The interconnected structure creates a rich graph visualization:
- See relationships between groups, techniques, and mitigations
- Identify coverage gaps in detection strategies
- Explore campaign attribution paths

![Graph View Example](https://raw.githubusercontent.com/reuteras/obsidian-mitre-attack/main/resources/graph.png)

## Configuration

Create a `config.toml` file (copy from `default-config.toml`):

```toml
repository_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
output_dir = "output"
version = "18.0"
verbose = true

# Embed Analytics within Detection Strategies
# When true: Analytics embedded as tabs (requires obsidian-tab-panels plugin)
# When false: Analytics as separate linked files (default)
embed_analytics_in_detection_strategies = false
```

### Embedded Analytics Mode

When `embed_analytics_in_detection_strategies = true`:

**Pros:**
- View all analytics in one file (like MITRE website)
- Reduced file count
- Better for overview and comparison

**Cons:**
- Requires [obsidian-tab-panels](https://github.com/GnoxNahte/obsidian-tab-panels) plugin
- Larger individual files
- Less modular

**Technique files link to sections:**
```markdown
| [[Detection Strategy - DET0324#Analytic 0919 | AN0919]] | Identifies self-modifying executables... |
```

**Detection Strategy files contain:**
```markdown
### Associated Analytics

\```tabs
--- AN0919 (Windows)
## Analytic 0919
[Full analytic content with log sources and mutable elements]

--- AN0920 (Linux)
## Analytic 0920
[Full analytic content]
\```
```

## Command-Line Options

```bash
usage: obsidian-mitre-attack [-h] [-o OUTPUT] [-t TAGS] [-v]

options:
  -h, --help            show this help message and exit
  -o, --output OUTPUT   Output directory for generated notes
  -t, --tags TAGS       Tag prefix (e.g., 'mitre/' creates #mitre/technique tags)
  -v, --verbose         Enable verbose logging
```

## Project Structure

```
output/
├── Tactics/
│   ├── Enterprise attack/
│   ├── Mobile attack/
│   └── ICS attack/
├── Techniques/
│   ├── Enterprise attack/
│   ├── Mobile attack/
│   └── ICS attack/
├── Defenses/
│   ├── Mitigations/
│   ├── Assets/
│   ├── Data_Sources/
│   ├── Detection_Strategies/  # NEW in v18
│   └── Analytics/             # Separate files when embed=false
└── CTI/
    ├── Groups/
    ├── Software/
    └── Campaigns/
```

## Development

### Requirements

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) package manager

### Setup

```bash
# Clone repository
git clone https://github.com/reuteras/obsidian-mitre-attack.git
cd obsidian-mitre-attack

# Install dependencies
uv sync

# Run tests
uv run pytest tests/

# Run linting
uv run ruff check src/
uv run ruff format src/
```

### Code Quality

This project uses:
- **Ruff** for linting and formatting
- **Pylint** for additional checks
- **pytest** for testing
- **GitHub Actions** for CI/CD

## Version History

### v18.0 (Current)
- ✅ Support for MITRE ATT&CK v18.0
- ✅ Detection Strategies with full analytics integration
- ✅ Embedded analytics mode with tab-panels support
- ✅ Optimized STIX parsing with caching
- ✅ Improved cross-linking between all entity types

### Earlier Versions
See [CHANGELOG.md](./CHANGELOG.md) for complete history.

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Ensure all tests pass (`uv run pytest`)
5. Run linting (`uv run ruff check src/`)
6. Submit a pull request

## License

MIT License - see [LICENSE](./LICENSE) file.

## Acknowledgments

- Original project by [Vincenzo Caputo](https://github.com/vincenzocaputo/obsidian-mitre-attack)
- MITRE ATT&CK® framework by [MITRE Corporation](https://attack.mitre.org/)
- STIX data from [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)

## Resources

- [MITRE ATT&CK®](https://attack.mitre.org/)
- [Obsidian](https://obsidian.md/)
- [Dataview Plugin](https://github.com/blacksmithgu/obsidian-dataview)
- [Tab Panels Plugin](https://github.com/GnoxNahte/obsidian-tab-panels)

---

MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
