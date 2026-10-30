"""Dependency manifest parsers used by Argus's first multi-ecosystem release."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass

from packaging.requirements import InvalidRequirement, Requirement


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str | None
    ecosystem: str = "PyPI"
    manifest_path: str | None = None


def _deduplicate(dependencies: list[Dependency]) -> list[Dependency]:
    seen: set[tuple[str, str, str | None]] = set()
    result = []
    for dependency in dependencies:
        key = (dependency.ecosystem, dependency.name.lower().replace("_", "-"), dependency.version)
        if key not in seen:
            seen.add(key)
            result.append(dependency)
    return result


def parse_requirements(text: str, manifest_path: str | None = None) -> list[Dependency]:
    dependencies: list[Dependency] = []
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
        dependencies.append(Dependency(requirement.name, version, "PyPI", manifest_path))
    return _deduplicate(dependencies)


def parse_pyproject(text: str, manifest_path: str | None = None) -> list[Dependency]:
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    dependencies: list[Dependency] = []
    project = document.get("project", {})
    for requirement_text in project.get("dependencies", []) or []:
        dependencies.extend(parse_requirements(str(requirement_text), manifest_path))
    poetry = document.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry, dict):
        for name, specifier in poetry.items():
            if name.lower() == "python":
                continue
            version = str(specifier) if isinstance(specifier, str) and re.fullmatch(r"[0-9][0-9A-Za-z.+!_-]*", specifier) else None
            dependencies.append(Dependency(name, version, "PyPI", manifest_path))
    return _deduplicate(dependencies)


def _npm_version(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return value if re.fullmatch(r"[0-9][0-9A-Za-z.+-]*", value) else None


def parse_package_json(text: str, manifest_path: str | None = None) -> list[Dependency]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return []
    dependencies: list[Dependency] = []
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        values = document.get(field, {})
        if isinstance(values, dict):
            for name, specifier in values.items():
                dependencies.append(Dependency(name, _npm_version(specifier), "npm", manifest_path))
    return _deduplicate(dependencies)


def parse_package_lock(text: str, manifest_path: str | None = None) -> list[Dependency]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return []
    dependencies: list[Dependency] = []
    packages = document.get("packages", {})
    if isinstance(packages, dict):
        for path, package in packages.items():
            if not path.startswith("node_modules/") or not isinstance(package, dict):
                continue
            dependencies.append(Dependency(path.removeprefix("node_modules/"), _npm_version(package.get("version")), "npm", manifest_path))
    if not dependencies and isinstance(document.get("dependencies"), dict):
        def walk(values: dict) -> None:
            for name, package in values.items():
                if not isinstance(package, dict):
                    continue
                dependencies.append(Dependency(name, _npm_version(package.get("version")), "npm", manifest_path))
                nested = package.get("dependencies")
                if isinstance(nested, dict):
                    walk(nested)
        walk(document["dependencies"])
    return _deduplicate(dependencies)


def parse_manifest(path: str, text: str) -> list[Dependency]:
    name = path.rsplit("/", 1)[-1]
    if name == "requirements.txt":
        return parse_requirements(text, path)
    if name == "pyproject.toml":
        return parse_pyproject(text, path)
    if name == "package.json":
        return parse_package_json(text, path)
    if name in {"package-lock.json", "npm-shrinkwrap.json"}:
        return parse_package_lock(text, path)
    return []
