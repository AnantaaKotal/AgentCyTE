import xml.etree.ElementTree as ET
import glob
import os

FULL_SESSION_OPTIONS = [
    {"name": "controlnet", "value": ""},
    {"name": "controlnet0", "value": ""},
    {"name": "controlnet1", "value": ""},
    {"name": "controlnet2", "value": ""},
    {"name": "controlnet3", "value": ""},
    {"name": "controlnet_updown_script", "value": ""},
    {"name": "enablerj45", "value": "1"},
    {"name": "preservedir", "value": "0"},
    {"name": "enablesdt", "value": "0"},
    {"name": "sdturl", "value": "tcp://127.0.0.1:50000/"},
    {"name": "ovs", "value": "0"},
    {"name": "platform_id_start", "value": "1"},
    {"name": "nem_id_start", "value": "1"},
    {"name": "link_enabled", "value": "1"},
    {"name": "loss_threshold", "value": "30"},
    {"name": "link_interval", "value": "1"},
    {"name": "link_timeout", "value": "4"},
    {"name": "mtu", "value": "0"}
]
def ensure_default_services(root):
    # Remove existing <default_services> if it exists
    default_services = root.find("default_services")
    if default_services is not None:
        root.remove(default_services)
        print("Removed existing <default_services> section")

    # Create fresh <default_services> with known correct structure
    default_services = ET.SubElement(root, "default_services")
    for node_type, services in {
        "mdr": ["zebra", "OSPFv3MDR", "IPForward"],
        "PC": ["DefaultRoute"],
        "prouter": [],
        "router": ["zebra", "OSPFv2", "OSPFv3", "IPForward"],
        "host": ["DefaultRoute", "SSH"]
    }.items():
        node_elem = ET.SubElement(default_services, "node", {"type": node_type})
        for svc_name in services:
            ET.SubElement(node_elem, "service", {"name": svc_name})
    print("Replaced <default_services> with correct version")


def ensure_session_options(root):
    session_options = root.find("session_options")
    if session_options is not None:
        root.remove(session_options)
        print("Removed existing <session_options> section")

    # Create fresh <session_options> block
    session_options = ET.SubElement(root, "session_options")
    for opt in FULL_SESSION_OPTIONS:
        ET.SubElement(session_options, "configuration", opt)
    print("Replaced <session_options> with correct version")

def ensure_session_metadata(root):
    # Remove existing <session_metadata> if it exists
    existing = root.find("session_metadata")
    if existing is not None:
        root.remove(existing)
        print("Removed existing <session_metadata> section")

    # Create fresh <session_metadata> with required structure
    session_metadata = ET.SubElement(root, "session_metadata")
    ET.SubElement(session_metadata, "configuration", {"name": "user", "value": "core"})
    ET.SubElement(session_metadata, "configuration", {"name": "node_prefix", "value": "n"})
    print("Replaced <session_metadata> section")

def ensure_session_origin(root):
    # Remove existing <session_origin> if it exists
    existing = root.find("session_origin")
    if existing is not None:
        root.remove(existing)
        print("Removed existing <session_origin> section")

    # Create fresh <session_origin>
    session_origin = ET.SubElement(root, "session_origin")
    ET.SubElement(session_origin, "location", {
        "lat": "47.5791667",
        "lon": "-122.132322",
        "alt": "2.000000"
    })
    print("Replaced <session_origin> section")

def ensure_element(parent, tag):
  
    found = parent.find(tag)
    if found is None:
        found = ET.SubElement(parent, tag)
    return found


def add_missing_sections(tree):
    root = tree.getroot()
    fix_duplicate_ids(root)

    # Remove existing sections if they exist
    for tag in ["session_origin", "session_options", "session_metadata", "default_services"]:
        existing = root.find(tag)
        if existing is not None:
            root.remove(existing)
            print(f"Removed existing <{tag}> section")

    # Find index to insert after configservice_configurations
    insertion_index = None
    for i, elem in enumerate(root):
        if elem.tag == "configservice_configurations":
            insertion_index = i + 1
            break

    if insertion_index is None:
        # Default to appending at the end if configservice_configurations is not found
        insertion_index = len(root)

    # Helper function to insert and return newly created element
    def insert_section(tag, attrib=None):
        elem = ET.Element(tag, attrib or {})
        root.insert(insertion_index, elem)
        print(f"Inserted <{tag}> at index {insertion_index}")
        insertion_index_plus_one = insertion_index + 1
        return elem, insertion_index_plus_one

    # 1. <session_origin>
    session_origin, insertion_index = insert_section("session_origin", {
        "lat": "47.579166412353516",
        "lon": "-122.13232421875",
        "alt": "2.0",
        "scale": "150.0"
    })

    # 2. <session_options>
    session_options, insertion_index = insert_section("session_options")
    for opt in FULL_SESSION_OPTIONS:
        ET.SubElement(session_options, "configuration", opt)

    # 3. <session_metadata>
    session_metadata, insertion_index = insert_section("session_metadata")
    for meta in [
        {"name": "shapes", "value": "[]"},
        {"name": "hidden", "value": "[]"},
        {"name": "edges", "value": "[]"},
        {"name": "canvas", "value": '{"gridlines": true, "canvases": [{"id": 1, "wallpaper": null, "wallpaper_style": 1, "fit_image": false, "dimensions": [1000, 750]}]}'}
    ]:
        ET.SubElement(session_metadata, "configuration", meta)

    # 4. <default_services>
    default_services, insertion_index = insert_section("default_services")
    for node_type, services in {
        "mdr": ["zebra", "OSPFv3MDR", "IPForward"],
        "PC": ["DefaultRoute"],
        "prouter": [],
        "router": ["zebra", "OSPFv2", "OSPFv3", "IPForward"],
        "host": ["DefaultRoute", "SSH"]
    }.items():
        node_elem = ET.SubElement(default_services, "node", {"type": node_type})
        for svc_name in services:
            ET.SubElement(node_elem, "service", {"name": svc_name})

    print("Finished adding missing sections in correct order")

  

def fix_duplicate_ids(root):
    print("duplicate id found")


def check_and_fix_xml(file_path, output_path=None):
    tree = ET.parse(file_path)
    add_missing_sections(tree)
    if not output_path:
        output_path = file_path
    tree.write(output_path, encoding="utf-8", xml_declaration=True)
    print(f"Checked and updated: {output_path}")


input_dir = "." 

input_pattern = os.path.join(input_dir, "generated_core_scenario-throughcode-3feedback*.xml")
 
xml_files = glob.glob(input_pattern)

output_dir = "fixed_scenarios"


for file_path in xml_files:
    base_name = os.path.basename(file_path)
    output_path = os.path.join(output_dir, f"fixed_{base_name}")
    check_and_fix_xml(file_path, output_path)
