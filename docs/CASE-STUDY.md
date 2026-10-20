# Turning a domain resemblance into a reviewable case

The problem is deciding whether a domain that resembles a Malaysian brand deserves investigation, without confusing a certificate event, a vocabulary match or a reputation lookup with confirmed fraud.

Selat Watch implements a passive observation-to-case workflow. Domains use IDNA canonicalization and suffix-boundary checks against 20 editable brand profiles. Scores expose their brand, keyword, age, Unicode and supplied hosting reasons. Unknown evidence stays unknown. SQLite preserves original normalized observations, hashes, review history, report references and imported image evidence separately from the current assessment.

The analyst UI places the queue beside the case dossier. The distinctive evidence object is the ASCII/Unicode domain comparison with reasons and an explicit analyst decision. Mobile selection moves focus to the dossier and offers a return control. Refreshes preserve draft fields; asynchronous selections discard late responses.

Local testing found and fixed an idempotency error caused by generated observation timestamps, unclosed SQLite connections, repeated-case fetch pressure in the report ledger, stale selected scores after allowlist updates, and keyboard focus loss during case rerendering.

The frozen 12-case domain-rule exercise produced 8 true positives, 1 false positive, 3 true negatives and 0 false negatives (precision 88.89%, recall 100%). The independent held-out page-text split produced 6 TP, 1 FP, 5 TN and 0 FN (precision 85.71%, recall 100%). These tiny authored fixtures demonstrate evaluation mechanics, not external validity. The benign community-domain and OTP-safety-advice false positives are retained and explained.

CertStream collection and URLhaus/VirusTotal enrichment are actual adapter implementations with environment-based credentials, explicit invocation and failure states. Live accounts, provider connectivity/quotas, lossless CT coverage, independent labels, real screenshots of authorized targets, production deployment, external reports and takedowns were not validated. Automatic suspect-site capture, direct LLM inference and a Lambda deployment are absent. The supported screenshot workflow is local import; optional model evaluation consumes supplied predictions.

The evaluation numbers can be reproduced with `python app.py evaluate-domains` and `python app.py evaluate`; saved copies are in `docs/examples/`.
