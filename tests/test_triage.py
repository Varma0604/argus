from app.triage import TriageValidationError, validate_triage


EVIDENCE = [{
    "osv_id": "GHSA-demo-1234",
    "package_name": "example-package",
    "installed_version": "1.2.3",
    "ecosystem": "PyPI",
    "severity": "HIGH",
    "summary": "Example finding",
}]


def valid_payload():
    return {
        "summary": "One high-severity finding needs review.",
        "actions": [{
            "osv_id": "GHSA-demo-1234",
            "package_name": "example-package",
            "installed_version": "1.2.3",
            "priority": "high",
            "rationale": "The scanned package version has the cited finding.",
            "next_step": "Review the vendor advisory and upgrade plan.",
        }],
        "disclaimer": "AI-generated guidance; verify before applying changes.",
    }


def test_triage_accepts_actions_grounded_in_scan_evidence():
    assert validate_triage(valid_payload(), EVIDENCE)["actions"][0]["osv_id"] == "GHSA-demo-1234"


def test_triage_rejects_hallucinated_osv_ids():
    payload = valid_payload()
    payload["actions"][0]["osv_id"] = "GHSA-not-in-this-scan"
    try:
        validate_triage(payload, EVIDENCE)
    except TriageValidationError as exc:
        assert "not in this scan" in str(exc)
    else:
        raise AssertionError("Expected ungrounded evidence to be rejected")
