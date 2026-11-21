# Argus user pilot

This is a short, consent-based usability pilot for the Argus dependency scanner.
It is not a security assessment and participants should only scan public
repositories or repositories they are authorized to share.

## What a participant does (about 5 minutes)

1. Open the live Argus API documentation and use `POST /api/v1/scans`.
2. Submit one public GitHub repository they maintain or know well.
3. Look at the dependency count, vulnerability findings, risk score, and evidence.
4. Answer the four questions below. Do not include credentials, private URLs, or
   proprietary dependency manifests in feedback.

## Questions

1. Could you complete a scan without help? If not, where did you get stuck?
2. Was the result understandable? Which field or phrase was unclear?
3. Did a finding look inaccurate, irrelevant, or missing context?
4. What is the one change that would make Argus more useful to you?

## What to record

Record only anonymous aggregate facts in `pilot-results-template.csv`:

- a pseudonymous participant ID (`P01`, `P02`, ...),
- whether the scan completed without assistance,
- the public repository scanned,
- minutes to completion,
- the main usability issue,
- the improvement made in response.

Do not claim usage or publish participant names until people have actually used
the system and consented to being identified.

## Exit criteria for a small pilot

Run at least five independent sessions. Prioritize the most frequent blocker,
ship a focused fix, and invite one earlier participant to retry the changed flow.
The project can then report exactly what happened, for example: "Five invited
developers completed scans of seven public repositories; feedback led to an
onboarding change." Only use numbers actually recorded in the results file.
