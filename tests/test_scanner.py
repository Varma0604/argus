from app.scanner import parse_requirements


def test_parses_pins_comments_extras_and_deduplicates():
    deps = parse_requirements("requests==2.31.0\n# comment\nFastAPI[standard]>=0.1\nrequests==2.31.0\n-r base.txt\n")
    assert [(d.name, d.version) for d in deps] == [("requests", "2.31.0"), ("FastAPI", None)]
