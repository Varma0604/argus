from app.scanner import parse_manifest, parse_requirements


def test_parses_pins_comments_extras_and_deduplicates():
    deps = parse_requirements("requests==2.31.0\n# comment\nFastAPI[standard]>=0.1\nrequests==2.31.0\n-r base.txt\n")
    assert [(d.name, d.version) for d in deps] == [("requests", "2.31.0"), ("FastAPI", None)]


def test_parses_pyproject_and_node_lock_manifests():
    python = parse_manifest("services/api/pyproject.toml", "[project]\ndependencies = ['httpx==0.27.0', 'fastapi>=0.115']")
    node = parse_manifest("web/package-lock.json", '{"lockfileVersion": 3, "packages": {"node_modules/react": {"version": "18.3.1"}}}')
    assert [(d.name, d.version, d.ecosystem, d.manifest_path) for d in python] == [
        ("httpx", "0.27.0", "PyPI", "services/api/pyproject.toml"),
        ("fastapi", None, "PyPI", "services/api/pyproject.toml"),
    ]
    assert [(d.name, d.version, d.ecosystem, d.manifest_path) for d in node] == [
        ("react", "18.3.1", "npm", "web/package-lock.json"),
    ]
