# Build the iApp template. Pass VERSION to stamp a version non-interactively
# (e.g. `make VERSION=1.1.3`); with no VERSION the generator prompts for confirmation.
VERSION ?=

all:
	iApp/builder/generate_iapp.py --rules iRules --settings iApp/builder/iapp-settings.json --template iApp/builder/iapp-template.txt --bundled-rules HSSR --output iApp/MIDEYE_SHIELD.tmpl $(if $(strip $(VERSION)),--version $(strip $(VERSION)))

lint:
	@tools/lint-irules.sh

test: lint
	@set -e; for f in tests/test_*.tcl; do echo "== $$f"; tclsh $$f; done

# Prove the tests can fail. Breaks one behaviour at a time and requires the
# suite to notice; a green `test` says nothing about assertions that cannot fail.
mutate:
	tools/mutate-check.py

.PHONY: all lint test mutate
