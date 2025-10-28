import os, tempfile, xml.etree.ElementTree as ET
from core_topo_gen.parsers.node_info import parse_node_info

def build_xml(weight_rows, count_for_density=10, counts=None):
    counts = counts or []
    root = ET.Element('Scenarios')
    scen = ET.SubElement(root, 'Scenario', name='d')
    se = ET.SubElement(scen, 'ScenarioEditor')
    ni = ET.SubElement(se, 'section', name='Node Information')
    if count_for_density is not None:
        ni.set('total_nodes', str(count_for_density))
    # weight rows
    for name, factor in weight_rows:
        ET.SubElement(ni, 'item', selected=name, factor=str(factor))
    # count rows
    for name, c in counts:
        ET.SubElement(ni, 'item', selected=name, v_metric='Count', v_count=str(c), factor='0')
    td = tempfile.TemporaryDirectory()
    path = os.path.join(td.name, 'x.xml')
    ET.ElementTree(root).write(path)
    return td, path

def test_random_residual_added_when_missing():
    # No Random row provided -> parser returns weight items (parser does not inject random; UI layer handles insertion)
    td, path = build_xml([('Server', 1.0)], count_for_density=20)
    try:
        density_base, weight_items, count_items, services = parse_node_info(path, 'd')
        assert density_base == 20
        # Weight items preserved
        assert weight_items == [('Server', 1.0)]
    finally:
        td.cleanup()

def test_count_for_density_distribution_zero_base():
    # Zero base should yield density_base=0 even with weights
    td, path = build_xml([('Random', 1.0), ('Server', 2.0)], count_for_density=0)
    try:
        density_base, weight_items, count_items, _ = parse_node_info(path, 'd')
        assert density_base == 0
        assert len(weight_items) == 2
    finally:
        td.cleanup()
