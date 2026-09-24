"""MITRE ATLAS Framework Models."""

from __future__ import annotations

from typing import Any


class ATLASObject:
    """Base class for MITRE ATLAS objects (tactic, technique, mitigation, case study)."""

    def __init__(self, name: str) -> None:
        """Initialize the ATLASObject class."""
        self._name: str = name.replace("/", "／").replace(  # noqa: RUF001
            ":", ";"
        )  # Name of the object
        self._id: str = ""  # ATLAS ID, e.g. AML.T0000
        self._description: str = ""
        self._url: str = ""  # URL to the page on atlas.mitre.org
        self._created: str = ""
        self._modified: str = ""

    @property
    def name(self) -> str:
        """Return the name of the object."""
        return self._name

    @name.setter
    def name(self, name: str) -> None:
        """Set the name of the object."""
        self._name = name.replace("/", "／").replace(":", ";")  # noqa: RUF001

    @property
    def id(self) -> str:
        """Return the ATLAS ID of the object."""
        return self._id

    @id.setter
    def id(self, id: str) -> None:
        """Set the ATLAS ID of the object."""
        self._id = id

    @property
    def description(self) -> str:
        """Return the description of the object."""
        return self._description

    @description.setter
    def description(self, description: str) -> None:
        """Set the description of the object."""
        self._description = description

    @property
    def url(self) -> str:
        """Return the URL of the object."""
        return self._url

    @url.setter
    def url(self, url: str) -> None:
        """Set the URL of the object."""
        self._url = url

    @property
    def created(self) -> str:
        """Return the created date of the object."""
        return self._created

    @created.setter
    def created(self, created: str) -> None:
        """Set the created date of the object."""
        self._created = created

    @property
    def modified(self) -> str:
        """Return the modified date of the object."""
        return self._modified

    @modified.setter
    def modified(self, modified: str) -> None:
        """Set the modified date of the object."""
        self._modified = modified


class ATLASTactic(ATLASObject):
    """Define an ATLAS tactic."""

    def __init__(self, name: str) -> None:
        """Initialize the ATLASTactic class."""
        ATLASObject.__init__(self=self, name=name)
        self._position: int = 0  # Order of the tactic on the ATLAS matrix
        self._techniques_used: list[dict[str, Any]] = []

    @property
    def position(self) -> int:
        """Return the position of the tactic on the ATLAS matrix."""
        return self._position

    @position.setter
    def position(self, position: int) -> None:
        """Set the position of the tactic on the ATLAS matrix."""
        self._position = position

    @property
    def techniques_used(self) -> list[dict[str, Any]]:
        """Return the techniques that achieve this tactic."""
        return self._techniques_used

    @techniques_used.setter
    def techniques_used(self, technique_used: dict[str, Any]) -> None:
        """Add a technique that achieves this tactic."""
        self._techniques_used.append(technique_used)


class ATLASTechnique(ATLASObject):
    """Define an ATLAS technique."""

    def __init__(self, name: str) -> None:
        """Initialize the ATLASTechnique class."""
        ATLASObject.__init__(self=self, name=name)
        self._platforms: list[str] = []
        self._maturity: str = ""
        self._attack_reference: dict[str, str] = {}  # {"id": ..., "url": ...}
        self._tactic_id: str = ""
        self._tactic_name: str = ""
        self._is_subtechnique: bool = False
        self._main_id: str = (
            ""  # Same as id for techniques, parent id for subtechniques
        )
        self._parent_id: str = ""
        self._parent_name: str = ""
        self._subtechniques: list[dict[str, Any]] = []
        self._mitigations: list[dict[str, Any]] = []
        self._case_studies: list[dict[str, Any]] = []

    @property
    def platforms(self) -> list[str]:
        """Return the platforms of the object."""
        return self._platforms

    @platforms.setter
    def platforms(self, platforms: list[str]) -> None:
        """Set the platforms of the object."""
        self._platforms = platforms

    @property
    def maturity(self) -> str:
        """Return the maturity level of the technique."""
        return self._maturity

    @maturity.setter
    def maturity(self, maturity: str) -> None:
        """Set the maturity level of the technique."""
        self._maturity = maturity

    @property
    def attack_reference(self) -> dict[str, str]:
        """Return the corresponding MITRE ATT&CK reference, if any."""
        return self._attack_reference

    @attack_reference.setter
    def attack_reference(self, attack_reference: dict[str, str]) -> None:
        """Set the corresponding MITRE ATT&CK reference."""
        self._attack_reference = attack_reference

    @property
    def tactic_id(self) -> str:
        """Return the ID of the tactic this technique achieves."""
        return self._tactic_id

    @tactic_id.setter
    def tactic_id(self, tactic_id: str) -> None:
        """Set the ID of the tactic this technique achieves."""
        self._tactic_id = tactic_id

    @property
    def tactic_name(self) -> str:
        """Return the name of the tactic this technique achieves."""
        return self._tactic_name

    @tactic_name.setter
    def tactic_name(self, tactic_name: str) -> None:
        """Set the name of the tactic this technique achieves."""
        self._tactic_name = tactic_name.replace("/", "／").replace(":", ";")  # noqa: RUF001

    @property
    def is_subtechnique(self) -> bool:
        """Return whether this object is a subtechnique."""
        return self._is_subtechnique

    @is_subtechnique.setter
    def is_subtechnique(self, is_subtechnique: bool) -> None:
        """Set whether this object is a subtechnique."""
        self._is_subtechnique = is_subtechnique

    @property
    def main_id(self) -> str:
        """Return the main technique ID (same as id, or parent id for subtechniques)."""
        return self._main_id

    @main_id.setter
    def main_id(self, main_id: str) -> None:
        """Set the main technique ID."""
        self._main_id = main_id

    @property
    def parent_id(self) -> str:
        """Return the parent technique ID, for subtechniques."""
        return self._parent_id

    @parent_id.setter
    def parent_id(self, parent_id: str) -> None:
        """Set the parent technique ID."""
        self._parent_id = parent_id

    @property
    def parent_name(self) -> str:
        """Return the parent technique name, for subtechniques."""
        return self._parent_name

    @parent_name.setter
    def parent_name(self, parent_name: str) -> None:
        """Set the parent technique name."""
        self._parent_name = parent_name.replace("/", "／").replace(":", ";")  # noqa: RUF001

    @property
    def subtechniques(self) -> list[dict[str, Any]]:
        """Return the subtechniques of this technique."""
        return self._subtechniques

    @subtechniques.setter
    def subtechniques(self, subtechnique: dict[str, Any]) -> None:
        """Add a subtechnique of this technique."""
        self._subtechniques.append(subtechnique)

    @property
    def mitigations(self) -> list[dict[str, Any]]:
        """Return the mitigations that mitigate this technique."""
        return self._mitigations

    @mitigations.setter
    def mitigations(self, mitigation: dict[str, Any]) -> None:
        """Add a mitigation that mitigates this technique."""
        self._mitigations.append(mitigation)

    @property
    def case_studies(self) -> list[dict[str, Any]]:
        """Return the case studies that employ this technique."""
        return self._case_studies

    @case_studies.setter
    def case_studies(self, case_study: dict[str, Any]) -> None:
        """Add a case study that employs this technique."""
        self._case_studies.append(case_study)


class ATLASMitigation(ATLASObject):
    """Define an ATLAS mitigation."""

    def __init__(self, name: str) -> None:
        """Initialize the ATLASMitigation class."""
        ATLASObject.__init__(self=self, name=name)
        self._lifecycle_phases: list[str] = []
        self._categories: list[str] = []
        self._techniques_mitigated: list[dict[str, Any]] = []

    @property
    def lifecycle_phases(self) -> list[str]:
        """Return the AI lifecycle phases this mitigation applies to."""
        return self._lifecycle_phases

    @lifecycle_phases.setter
    def lifecycle_phases(self, lifecycle_phases: list[str]) -> None:
        """Set the AI lifecycle phases this mitigation applies to."""
        self._lifecycle_phases = lifecycle_phases

    @property
    def categories(self) -> list[str]:
        """Return the categories of this mitigation."""
        return self._categories

    @categories.setter
    def categories(self, categories: list[str]) -> None:
        """Set the categories of this mitigation."""
        self._categories = categories

    @property
    def techniques_mitigated(self) -> list[dict[str, Any]]:
        """Return the techniques mitigated by this mitigation."""
        return self._techniques_mitigated

    @techniques_mitigated.setter
    def techniques_mitigated(self, technique_mitigated: dict[str, Any]) -> None:
        """Add a technique mitigated by this mitigation."""
        self._techniques_mitigated.append(technique_mitigated)


class ATLASCaseStudy(ATLASObject):
    """Define an ATLAS case study."""

    def __init__(self, name: str) -> None:
        """Initialize the ATLASCaseStudy class."""
        ATLASObject.__init__(self=self, name=name)
        self._type: str = ""  # e.g. "Incident" or "Exercise"
        self._actor: str = ""
        self._target: str = ""
        self._date: str = ""
        self._date_granularity: str = ""
        self._references: list[dict[str, str]] = []
        self._procedure: list[dict[str, Any]] = []

    @property
    def type(self) -> str:
        """Return the type of the case study (Incident or Exercise)."""
        return self._type

    @type.setter
    def type(self, type: str) -> None:
        """Set the type of the case study."""
        self._type = type

    @property
    def actor(self) -> str:
        """Return the actor behind the case study."""
        return self._actor

    @actor.setter
    def actor(self, actor: str) -> None:
        """Set the actor behind the case study."""
        self._actor = actor

    @property
    def target(self) -> str:
        """Return the target of the case study."""
        return self._target

    @target.setter
    def target(self, target: str) -> None:
        """Set the target of the case study."""
        self._target = target

    @property
    def date(self) -> str:
        """Return the incident date of the case study."""
        return self._date

    @date.setter
    def date(self, date: str) -> None:
        """Set the incident date of the case study."""
        self._date = date

    @property
    def date_granularity(self) -> str:
        """Return the granularity of the incident date."""
        return self._date_granularity

    @date_granularity.setter
    def date_granularity(self, date_granularity: str) -> None:
        """Set the granularity of the incident date."""
        self._date_granularity = date_granularity

    @property
    def references(self) -> list[dict[str, str]]:
        """Return the references of the case study."""
        return self._references

    @references.setter
    def references(self, reference: dict[str, str]) -> None:
        """Add a reference of the case study."""
        self._references.append(reference)

    @property
    def procedure(self) -> list[dict[str, Any]]:
        """Return the ordered procedure steps of the case study."""
        return self._procedure

    @procedure.setter
    def procedure(self, step: dict[str, Any]) -> None:
        """Add a procedure step to the case study."""
        self._procedure.append(step)
