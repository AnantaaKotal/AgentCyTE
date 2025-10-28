import importlib
import pytest

def test_xml_parser_removed_importerror():
    with pytest.raises(ImportError) as ei:
        importlib.import_module('core_topo_gen.parsers.xml_parser')
    msg = str(ei.value)
    assert 'removed' in msg and 'specific parser modules' in msg
