# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Python tool that parses MITRE ATT&CK STIX data and converts it into Obsidian-compatible Markdown files. The project downloads STIX 2.1 JSON data from the MITRE ATT&CK GitHub repository and generates structured Markdown notes for use in Obsidian with proper linking, tags, and metadata.

## Key Commands

Setup, running, and code-quality commands are in [README.md](README.md) ("Quick Start" and "Development"); test commands are in [tests/README.md](tests/README.md). This section only covers what's specific to working on the codebase itself.

## Architecture

### Core Components

1. **StixParser** (`stix_parser.py`): Downloads and parses STIX 2.1 JSON data from MITRE's GitHub repository for all three ATT&CK domains (enterprise, mobile, ICS). Converts STIX objects into custom Python model instances.

2. **MarkdownGenerator** (`markdown_generator.py`): Converts parsed STIX data into Obsidian-compatible Markdown files with proper frontmatter, tags, and internal linking. Handles text processing for MITRE references and creates cross-links between entities.

3. **Models** (`models.py`): Defines Python classes for MITRE ATT&CK entities (Tactics, Techniques, Mitigations, Groups, Software, Campaigns, Assets, Data Sources) with proper attribute handling and reference management.

4. **Main Module** (`__init__.py`): Entry point that orchestrates the entire process - argument parsing, configuration loading, data retrieval, and Markdown generation.

### Data Flow

1. Load configuration from `config.toml`
2. Initialize StixParser to download STIX data for all three domains
3. Parse domain-specific data (tactics, techniques, mitigations)
4. Parse cross-domain data (groups, software, campaigns, assets, data sources)
5. Generate Markdown files for each entity type
6. Create main README with metadata

### ATT&CK Domains Processed

- **enterprise-attack**: Standard enterprise techniques and tactics
- **mobile-attack**: Mobile-specific attack patterns
- **ics-attack**: Industrial Control Systems attack patterns

## Configuration

The `config.toml` file contains:

- `repository_url`: MITRE STIX data repository URL
- `output_dir`: Default output directory
- `version`: ATT&CK version to download (see `default-config.toml` for the current default)
- `verbose`: Enable verbose logging

## Code Quality Standards

- Uses Ruff for formatting and linting with Pylint-style rules
- Follows Google docstring conventions
- Python 3.11+ required
- All dependencies managed through `pyproject.toml`
- Uses type hints throughout codebase

## Output Structure

Generated Markdown files include:

- Proper YAML frontmatter with aliases and tags
- Cross-referenced internal links using Obsidian `[[link]]` syntax
- MITRE ATT&CK ID references and external URLs
- Structured metadata for Obsidian's Dataview plugin compatibility

## Special Handling

- Forward slashes in names are replaced with full-width slashes (／) for filesystem compatibility
- Colons in names are replaced with semicolons (;) for Obsidian compatibility
- MITRE citation references are converted to footnote format
- External MITRE links are converted to internal Obsidian links
- Inconsistent MITRE references are normalized during processing
