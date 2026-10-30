# Detection-as-Code - one command per pipeline stage. Same commands locally and in CI.
#
#   make setup      create .venv with the pinned toolchain
#   make lint       YAML lint + `sigma check` (fails on malformed rules)
#   make validate   metadata / ATT&CK / mapping validation
#   make test       run every rule against the synthetic sample logs
#   make convert    Sigma -> Elastic + Wazuh queries (converted/)
#   make coverage   ATT&CK Navigator layer + Markdown summary + SVG (coverage/)
#   make selftest   prove the gates reject known-bad rules
#   make ci         everything above + "generated files are up to date" check
#
# Override the interpreter if you manage your own environment: make ci PY=python3

VENV    ?= .venv
PY      ?= $(VENV)/bin/python
SIGMA   ?= $(VENV)/bin/sigma
YAMLLINT?= $(VENV)/bin/yamllint
SIGMA_CHECK = $(SIGMA) check --fail-on-error --fail-on-issues -c config/sigma-validation.yml

.PHONY: help setup lock lint validate test convert coverage samples selftest drift ci \
        attack-data hunt atomics-list clean

help:
	@sed -n '2,13p' Makefile

setup:
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -r requirements.lock
	$(SIGMA) version

lock:
	$(VENV)/bin/pip install -r requirements.txt
	{ echo "# Full dependency lock (pip freeze of a clean venv). Python >= 3.10."; \
	  echo "# Regenerate after changing requirements.txt: make lock"; \
	  $(VENV)/bin/pip freeze; } > requirements.lock

lint:
	$(YAMLLINT) -c config/yamllint.yml rules mapping atomics pipelines config .github
	$(PY) tools/prime_attack_cache.py
	$(SIGMA_CHECK) rules/

validate:
	$(PY) tools/validate_rules.py $(if $(GITHUB_ACTIONS),--github,)

test:
	$(PY) tools/test_rules.py --report

convert:
	$(PY) tools/convert.py

coverage:
	$(PY) tools/coverage.py

samples:
	$(PY) sample-logs/generate_samples.py

# Negative tests: each command MUST fail; if one succeeds the gate is broken.
selftest:
	@$(PY) tools/prime_attack_cache.py >/dev/null
	@if $(SIGMA_CHECK) tests/fixtures/invalid/sigma >/dev/null 2>&1; then \
	  echo "SELFTEST FAIL: sigma check accepted a malformed rule"; exit 1; \
	else echo "selftest ok: sigma check rejects tests/fixtures/invalid/sigma"; fi
	@if $(SIGMA_CHECK) tests/fixtures/invalid/metadata >/dev/null 2>&1; then \
	  echo "SELFTEST FAIL: sigma check accepted invalid ATT&CK tags"; exit 1; \
	else echo "selftest ok: sigma check (attacktag) rejects tests/fixtures/invalid/metadata"; fi
	@if $(PY) tools/validate_rules.py --no-mapping tests/fixtures/invalid/metadata >/dev/null 2>&1; then \
	  echo "SELFTEST FAIL: validate_rules accepted bad metadata"; exit 1; \
	else echo "selftest ok: validate_rules rejects tests/fixtures/invalid/metadata"; fi
	@if $(PY) tools/validate_rules.py --no-mapping tests/fixtures/invalid/attribution >/dev/null 2>&1; then \
	  echo "SELFTEST FAIL: validate_rules accepted an unattributed SigmaHQ adaptation"; exit 1; \
	else echo "selftest ok: validate_rules rejects tests/fixtures/invalid/attribution"; fi

# Generated artefacts must match what the committed sources produce.
drift:
	@git diff --exit-code --stat -- converted coverage sample-logs \
	  || { echo "Generated files are stale: run 'make samples convert coverage' and commit."; exit 1; }
	@test -z "$$(git status --porcelain -- converted coverage sample-logs)" \
	  || { git status --porcelain -- converted coverage sample-logs; \
	       echo "Untracked generated files: run 'make convert coverage' and commit."; exit 1; }

ci: lint validate test samples convert coverage selftest drift
	@echo "CI pipeline passed."

attack-data:
	$(PY) tools/update_attack_data.py $(if $(ATTACK_VERSION),--version $(ATTACK_VERSION),)

hunt:
	$(PY) tools/hunt_lab.py --target $(or $(TARGET),wazuh) --since $(or $(SINCE),24h) $(HUNT_ARGS)

atomics-list:
	$(PY) tools/run_atomic.py --list

clean:
	rm -rf build .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
