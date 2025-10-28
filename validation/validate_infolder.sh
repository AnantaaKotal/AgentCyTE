#!/usr/bin/env bash
# validate_all.sh
# Usage: ./validate_all.sh /path/to/xml/files /path/to/core_scenario.xsd

set -u  # abort on unset vars

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <xml_directory> <xsd_file>"
    exit 1
fi

XML_DIR="$1"
XSD_FILE="$2"

if [[ ! -d "$XML_DIR" ]]; then
    echo "Error: Directory '$XML_DIR' not found."
    exit 1
fi
if [[ ! -f "$XSD_FILE" ]]; then
    echo "Error: XSD file '$XSD_FILE' not found."
    exit 1
fi
if ! command -v xmllint >/dev/null 2>&1; then
    echo "Error: xmllint not found. Install libxml2-utils."
    exit 1
fi

shopt -s nullglob
files=("$XML_DIR"/*.xml)

if (( ${#files[@]} == 0 )); then
    echo "No .xml files found in '$XML_DIR'"
    exit 0
fi

ok=0
bad=0

for xml_file in "${files[@]}"; do
    echo "→ Checking: $xml_file"
    if xmllint --noout --schema "$XSD_FILE" "$xml_file"; then
        echo "  ✅ Valid"
        ((ok++))
    else
        echo "  ❌ Invalid"
        ((bad++))
    fi
    echo
done

echo "Summary: $ok valid, $bad invalid, total ${#files[@]}"
(( bad > 0 )) && exit 1 || exit 0
