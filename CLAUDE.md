# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Python tool that parses MITRE ATT&CK STIX data and converts it into Obsidian-compatible Markdown files. The project downloads STIX 2.1 JSON data from the MITRE ATT&CK GitHub repository and generates structured markdown notes for use in Obsidian with proper linking, tags, and metadata.

## Key Commands

### Development Environment
```bash
# Setup virtual environment using uv
uv venv
source .venv/bin/activate

# Install dependencies
uv sync
```

### Running the Application
```bash
# Basic run with default config
uv run obsidian-mitre-attack

# Custom output directory and tags
uv run obsidian-mitre-attack --output $(pwd)/output --tags 'mitre/'

# Verbose mode
uv run obsidian-mitre-attack --verbose
```

### Code Quality
```bash
# Format and lint code
uv run ruff format src/
uv run ruff check src/
uv run ruff check --fix src/

# Run pylint
uv run pylint src/
```

## Architecture

### Core Components

1. **StixParser** (`stix_parser.py`): Downloads and parses STIX 2.1 JSON data from MITRE's GitHub repository for all three ATT&CK domains (enterprise, mobile, ICS). Converts STIX objects into custom Python model instances.

2. **MarkdownGenerator** (`markdown_generator.py`): Converts parsed STIX data into Obsidian-compatible Markdown files with proper frontmatter, tags, and internal linking. Handles text processing for MITRE references and creates cross-links between entities.

3. **Models** (`models.py`): Defines Python classes for MITRE ATT&CK entities (Tactics, Techniques, Mitigations, Groups, Software, Campaigns, Assets, Data Sources) with proper attribute handling and reference management.

4. **Main Module** (`__init__.py`): Entry point that orchestrates the entire process - argument parsing, configuration loading, data retrieval, and markdown generation.

### Data Flow

1. Load configuration from `config.toml`
2. Initialize StixParser to download STIX data for all three domains
3. Parse domain-specific data (tactics, techniques, mitigations)
4. Parse cross-domain data (groups, software, campaigns, assets, data sources)
5. Generate markdown files for each entity type
6. Create main README with metadata

### ATT&CK Domains Processed

- **enterprise-attack**: Standard enterprise techniques and tactics
- **mobile-attack**: Mobile-specific attack patterns
- **ics-attack**: Industrial Control Systems attack patterns

## Configuration

The `config.toml` file contains:
- `repository_url`: MITRE STIX data repository URL
- `output_dir`: Default output directory
- `version`: ATT&CK version to download (currently 16.1)
- `verbose`: Enable verbose logging

## Code Quality Standards

- Uses Ruff for formatting and linting with Pylint-style rules
- Follows Google docstring conventions
- Python 3.11+ required
- All dependencies managed through `pyproject.toml`
- Uses type hints throughout codebase

## Output Structure

Generated markdown files include:
- Proper YAML frontmatter with aliases and tags
- Cross-referenced internal links using Obsidian `[[link]]` syntax
- MITRE ATT&CK ID references and external URLs
- Structured metadata for Obsidian's Dataview plugin compatibility

## Special Handling

- Forward slashes in names are replaced with full-width slashes (／) for filesystem compatibility
- MITRE citation references are converted to footnote format
- External MITRE links are converted to internal Obsidian links
- Inconsistent MITRE references are normalized during processing