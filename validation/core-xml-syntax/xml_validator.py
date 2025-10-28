# Validate a CORE scenario XML against the schema derived from corexml.py
from lxml import etree
import sys

def main(xml_path, xsd_path):
    with open(xsd_path, "rb") as f:
        schema_doc = etree.parse(f)
    schema = etree.XMLSchema(schema_doc)
    parser = etree.XMLParser(schema=schema)
    try:
        etree.parse(xml_path, parser)
        print("VALID")
        sys.exit(0)
    except etree.XMLSyntaxError as e:
        print("INVALID")
        for err in e.error_log:
            print(f"{err.level_name} L{err.line}:C{err.column} - {err.message}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python validate_core_scenario.py <scenario.xml> <schema.xsd>")
        sys.exit(2)
    main(sys.argv[1], sys.argv[2])
