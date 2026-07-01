# Build the iApp template. Pass VERSION to stamp a version non-interactively
# (e.g. `make VERSION=1.1.3`); with no VERSION the generator prompts for confirmation.
VERSION ?=

all:
	iApp/builder/generate_iapp.py --rules iRules --settings iApp/builder/iapp-settings.json --template iApp/builder/iapp-template.txt --bundled-rules HSSR --output iApp/MIDEYE_SHIELD.tmpl $(if $(strip $(VERSION)),--version $(strip $(VERSION)))
