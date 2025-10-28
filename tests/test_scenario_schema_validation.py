import os
import glob
from lxml import etree

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), '..', 'validation', 'scenarios.xsd')
SCHEMA_PATH = os.path.abspath(SCHEMA_PATH)

def _load_schema():
    with open(SCHEMA_PATH, 'rb') as f:
        doc = etree.parse(f)
    return etree.XMLSchema(doc)

def _validate_file(schema, path):
    with open(path, 'rb') as f:
        doc = etree.parse(f)
    schema.assertValid(doc)

def test_sample_xml_validates():
    schema = _load_schema()
    sample_candidates = [
        'sample.xml',
        'sample_config_1scen.xml',
        'sample_config_2scen.xml'
    ]
    found_any = False
    for rel in sample_candidates:
        path = os.path.abspath(rel)
        if os.path.exists(path):
            # Skip files that are clearly CORE session exports (contain <scenario> root lower-case)
            txt_head = open(path, 'r', errors='ignore').read(200)
            if '<scenario' in txt_head and '<Scenarios' not in txt_head:
                continue
            _validate_file(schema, path)
            found_any = True
    assert found_any, "No sample XML files found to validate; expected at least one of sample.xml or sample_config_*.xml"

def test_generated_schema_samples_if_present():
    """If bulk-generated schema samples exist under outputs/schema-samples, validate them.

    This test is optional; it will pass quickly if the directory does not exist.
    """
    schema = _load_schema()
    samples_dir = os.path.abspath('outputs/schema-samples')
    if not os.path.isdir(samples_dir):
        return  # nothing to do
    xml_files = glob.glob(os.path.join(samples_dir, '*.xml'))
    for xf in xml_files:
        _validate_file(schema, xf)
