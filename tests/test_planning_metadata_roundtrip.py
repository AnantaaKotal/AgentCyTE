import os
import xml.etree.ElementTree as ET
from core_topo_gen.parsers.planning_metadata import parse_planning_metadata
from core_topo_gen.parsers.node_info import parse_node_info
from core_topo_gen.parsers.routing import parse_routing_info
from core_topo_gen.parsers.vulnerabilities import parse_vulnerabilities_info


def build_minimal_xml(tmp_path):
    # Construct a minimal scenario dict equivalent (write manually to avoid coupling to web code)
    root = ET.Element("Scenarios")
    scen = ET.SubElement(root, "Scenario", name="meta")
    se = ET.SubElement(scen, "ScenarioEditor")

    # Node Information section with additive metadata
    ni = ET.SubElement(se, "section", name="Node Information")
    ni.set("base_nodes", "0")
    ni.set("additive_nodes", "13")
    ni.set("combined_nodes", "13")
    ni.set("weight_rows", "2")
    ni.set("count_rows", "1")
    ni.set("weight_sum", "3.0")
    ET.SubElement(ni, "item", selected="Workstation", factor="2.0")
    ET.SubElement(ni, "item", selected="Server", factor="1.0")
    ET.SubElement(ni, "item", selected="Appliance", v_metric="Count", v_count="3", factor="0.0")

    # Routing section metadata (density 0.2 over 13 hosts -> derived ~3); explicit 2
    routing = ET.SubElement(se, "section", name="Routing")
    routing.set("density", "0.200")
    routing.set("explicit_count", "2")
    routing.set("derived_count", "3")
    routing.set("total_planned", "5")
    routing.set("weight_rows", "1")
    routing.set("count_rows", "1")
    routing.set("weight_sum", "1.0")
    ET.SubElement(routing, "item", selected="OSPF", factor="1.0")
    ET.SubElement(routing, "item", selected="BGP", v_metric="Count", v_count="2", factor="0.0")

    # Vulnerabilities (density 0.5 clipped; 10 base -> 5 derived ; explicit 4)
    vul = ET.SubElement(se, "section", name="Vulnerabilities")
    vul.set("density", "0.500")
    vul.set("explicit_count", "4")
    vul.set("derived_count", "5")
    vul.set("total_planned", "9")
    vul.set("weight_rows", "1")
    vul.set("count_rows", "2")
    vul.set("weight_sum", "1.0")
    ET.SubElement(vul, "item", selected="Random", factor="1.0")
    ET.SubElement(vul, "item", selected="Specific", v_metric="Count", v_count="3", v_name="CVE-1", v_path="/tmp/a")
    ET.SubElement(vul, "item", selected="Specific", v_metric="Count", v_count="1", v_name="CVE-2", v_path="/tmp/b")

    # Write
    xml_path = os.path.join(tmp_path, "scenario_meta.xml")
    ET.ElementTree(root).write(xml_path)
    return xml_path


def test_planning_metadata_roundtrip(tmp_path):
    xml_path = build_minimal_xml(tmp_path)
    meta = parse_planning_metadata(str(xml_path), "meta")
    # Scenario-level aggregate may be absent (not written in this manually assembled XML), ensure graceful presence logic
    if 'scenario' in meta:
        assert 'scenario_total_nodes' in meta['scenario']
    assert meta["node_info"]["base_nodes"] == 0
    assert meta["node_info"]["additive_nodes"] == 13
    assert meta["node_info"]["combined_nodes"] == 13
    assert meta["routing"]["explicit_count"] == 2
    assert meta["routing"]["derived_count"] == 3
    assert meta["routing"]["total_planned"] == 5
    assert meta["vulnerabilities"]["explicit_count"] == 4
    assert meta["vulnerabilities"]["derived_count"] == 5
    assert meta["vulnerabilities"]["total_planned"] == 9

    # Backwards compatibility sanity: removing attributes still yields defaults
    # Remove metadata and ensure fallback doesn't crash
    tree = ET.parse(str(xml_path))
    root = tree.getroot()
    # Strip routing metadata
    for sec in root.findall(".//section[@name='Routing']"):
        for attr in ["explicit_count","derived_count","total_planned","weight_rows","count_rows","weight_sum"]:
            if attr in sec.attrib:
                del sec.attrib[attr]
    xml_bc_path = os.path.join(tmp_path, "scenario_legacy.xml")
    ET.ElementTree(root).write(xml_bc_path)
    meta2 = parse_planning_metadata(str(xml_bc_path), "meta")
    # Fallback explicit derived values may differ but structure should exist
    assert "routing" in meta2
    assert "node_info" in meta2
