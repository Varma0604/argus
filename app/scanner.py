from dataclasses import dataclass
from packaging.requirements import InvalidRequirement, Requirement


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str | None


def parse_requirements(text: str) -> list[Dependency]:
    """Parse the practical subset of requirements.txt used by this scanner.

    Only exact pins are sent to OSV's version query. Ranges and unpinned entries
    remain visible in results but are marked unresolved for vulnerability lookup.
    """
    dependencies: list[Dependency] = []
    seen: set[tuple[str, str | None]] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "http:", "https:")):
            continue
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            continue
        pin = next(iter(requirement.specifier), None)
        version = pin.version if pin and pin.operator == "==" and "*" not in pin.version else None
        dep = Dependency(requirement.name, version)
        key = (dep.name.lower().replace("_", "-"), dep.version)
        if key not in seen:
            seen.add(key)
            dependencies.append(dep)
    return dependencies
