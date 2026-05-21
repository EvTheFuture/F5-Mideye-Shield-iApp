all:
	iApp/builder/generate_iapp.py --rules iRules --settings iApp/builder/iapp-settings.json --template iApp/builder/iapp-template.txt --bundled-rules HSSR --output iApp/MIDEYE_SHIELD.tmpl
