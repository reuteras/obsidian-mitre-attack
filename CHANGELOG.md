# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Support for MITRE ATT&CK v18.0
- Detection Strategies with full cross-linking to techniques
- Analytics with detailed log sources and mutable elements
- Two output modes: standard (separate files) and embedded (tab-panels)
- `embed_analytics_in_detection_strategies` configuration option
- Section linking for embedded analytics using Obsidian `#` syntax
- Platform-specific analytics display (Windows, Linux, macOS)
- Comprehensive YAML frontmatter with aliases and tags for all entities
- Detection Strategy section in technique files with analytics table
- CI caching for STIX data downloads to optimize test performance
- Dual release workflow generating both standard and embedded variants
- GitHub Actions badges in README

### Changed
- Updated to ATT&CK STIX data version 18.0
- Rewrote README with comprehensive documentation
- Improved markdown generator for detection strategies
- Enhanced cross-linking between techniques, detection strategies, and analytics
- Optimized STIX parsing with pre-caching of relationships
- Release workflow now generates two ZIP files (standard and embedded)
- Test workflow now caches STIX data for faster CI runs

### Fixed
- All Ruff linting errors resolved with appropriate noqa comments
- Unused variable warnings (RUF059, F841)
- Complex function warnings (PLR0915, PLR0912) with noqa annotations
- Fullwidth solidus character warnings (RUF001) for filesystem compatibility
- Detection strategy linking to properly include analytics data
- Parsing order to ensure analytics are available before linking

### Performance
- Added caching for technique lookups in groups parsing
- Pre-cache relationships and objects for faster detection strategy parsing
- Optimized software parsing with relationship caching
- Reduced redundant STIX queries through intelligent caching

## [16.1.0] - 2024-10-15

### Added
- Support for MITRE ATT&CK v16.1
- Assets and targeted assets support
- Data sources with data components
- Campaigns with attribution to groups
- Improved external reference handling

### Changed
- Updated to use `uv` for dependency management
- Improved test coverage
- Enhanced markdown formatting

### Fixed
- Various markdown output issues
- External reference filtering to only include cited footnotes
- Procedure example formatting

## [15.1.0] - 2024-06-20

### Added
- Initial support for three ATT&CK domains (Enterprise, Mobile, ICS)
- Tactics, Techniques, Mitigations, Groups, Software
- Obsidian wikilink formatting
- YAML frontmatter with aliases
- Graph view support through cross-linking

### Changed
- Fork from original vincenzocaputo/obsidian-mitre-attack
- Removed canvas generation feature
- Added full domain coverage (not just enterprise)

## [Previous Versions]

Earlier versions were based on the original [vincenzocaputo/obsidian-mitre-attack](https://github.com/vincenzocaputo/obsidian-mitre-attack) project.

---

## Types of Changes

- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes
- **Performance** for performance improvements
