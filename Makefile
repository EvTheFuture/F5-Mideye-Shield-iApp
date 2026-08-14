.PHONY: all lint test

all:
	iApp/builder/generate_iapp.py --rules iRules --settings iApp/builder/iapp-settings.json --template iApp/builder/iapp-template.txt --bundled-rules HSSR --output iApp/MIDEYE_SHIELD.tmpl

lint:
	@tools/lint-irules.sh

test: lint
	@set -e; for f in tests/test_*.tcl; do echo "== $$f"; tclsh $$f; done
