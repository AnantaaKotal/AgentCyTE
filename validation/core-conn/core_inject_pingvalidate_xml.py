'''
@author: Jaime Acosta
@date: 2025-07-07
@description:
This script processes an XML file to add a UserDefined service to each device.
It also generates a bash script for each device that pings all other devices in the network.
'''

import lxml.etree as ET
import logging
import sys

def validate_xml(xml_path, xsd_path):
    # Parse XSD schema
    with open(xsd_path, 'rb') as xsd_file:
        schema_root = ET.XML(xsd_file.read())
        schema = ET.XMLSchema(schema_root)

    # Parse XML file
    with open(xml_path, 'rb') as xml_file:
        xml_doc = ET.parse(xml_file)

    # Validate
    is_valid = schema.validate(xml_doc)
    if is_valid:
        print("XML is valid.")
    else:
        print("XML is invalid.")
        for error in schema.error_log:
            print(f"Line {error.line}: {error.message}")
    return is_valid

def add_service_to_userdefined(xml_file, nodeip_map, output_file):
    logging.info("Starting to process XML file: %s", xml_file)
    # Parse the XML
    parser = ET.XMLParser(strip_cdata=False)
    tree = ET.parse(xml_file, parser=parser)
    scenario = tree.getroot()

    # Find all <device> tags
    logging.debug("Finding all <device> tags in the XML.")
    devices = scenario.findall(".//device")

    for device in devices:
        logging.debug("Processing device: %s", device)
        device_id = device.get("id")
        if not device_id:
            logging.debug("Found <device> without 'id' attribute. Skipping.")
            continue

        logging.debug(f"Processing device with id: {device_id}")
        #find the services tag, and if it doesn't exist, add it
        logging.debug(f"Checking for <services> tag for device id: {device_id}")
        services = device.find(".//services")
        if services == None or services == []:
            logging.debug(f"No <services> tag found for device id {device_id}. Adding it.")
            services = ET.SubElement(device, "services")

        #get the service and check if the UserDefined tag exists
        services_service = services.findall(".//service")
        #if no service tag exists, then add one for the UserDefined service
        if services_service == None or services_service == []:
            logging.debug(f"No <service> tag found for device id {device_id}. Adding it.")
            services_service = ET.SubElement(services, "service", name="UserDefined")
        else:
            #get all services and check if any are UserDefined, if not, then add one
            contains_userdefined = False
            logging.debug(f"Checking for <UserDefined> tag in services for device id: {device_id}")
            for service in services_service:
                if 'name' in service.attrib and service.attrib['name'] == "UserDefined":
                    contains_userdefined = True
                    break
            if contains_userdefined == False:
                logging.debug(f"No <UserDefined> tag found for device id {device_id}. Adding it.")
                services.append(ET.Element("service",name="UserDefined"))

        # Find <UserDefined> tag with matching id
        logging.debug(f"Finding <service_configurations> for device id: {device_id}")
        service_configurations = scenario.find(f".//service_configurations")
        if service_configurations is None or service_configurations == []:
            logging.debug("No <service_configurations> found in the XML. Adding it.")
            service_configurations = ET.SubElement(scenario, "service_configurations")
        if service_configurations is None or service_configurations == []:
            logging.error("Could not create service_configuration. Quitting.")
            sys.exit(1)
        userdefined = service_configurations.find(f".//service[@name='UserDefined'][@node='{device_id}']")
        if userdefined == None or userdefined == []:
            logging.debug(f"No <UserDefined> found for device id {device_id}. Adding it.")
            userdefined = ET.SubElement(service_configurations, "service", name="UserDefined", node=device_id)
        else:
            logging.debug(f"Found matching <UserDefined> for device id {device_id}")

        # Create a new <startup> tag
        startups = userdefined.find(f".//startups")
        if startups == None or startups == []:
            logging.debug(f"No <startups> found in <UserDefined> for device id {device_id}. Adding it.")
            startups = ET.SubElement(userdefined, "startups")
        else:
            logging.debug(f"Found <startups> in <UserDefined> for device id {device_id}")
        #create the startup command to run the pings
        logging.debug(f"Adding startup command for device id {device_id}")
        pcmd = ET.Element("startup")
        pcmd.text = f"/bin/bash pings_{device_id}.sh"
        startups.append(pcmd)

        # Create a new <file> tag
        logging.debug(f"Adding <files> section for device id {device_id}")
        files = userdefined.find(f".//files")
        if files == None or files == []:
            logging.debug(f"No <files> found in <UserDefined> for device id {device_id}. Adding it.")
            files = ET.SubElement(userdefined, "files")
        else:
            logging.debug(f"Found <files> in <UserDefined> for device id {device_id}")
        file = ET.Element("file")
        filetext = f"#!/bin/bash\n"
        logging.debug(f"Creating ping commands for device id {device_id}")
        for mapping in nodeip_map:
            if mapping == device_id:
                continue
            #create the file that has pings to all other nodes
            for ipv4 in nodeip_map[mapping]:
                logging.debug(f"Adding ping command for {mapping} with IPv4 {ipv4}")
                filetext += f"ping {ipv4} -c 60 | grep ' bytes from ' | wc -l > /tmp/{device_id}_to_{mapping}___{ipv4}.txt &"
                filetext += "\n"
        file.attrib['name'] = f"pings_{device_id}.sh"
        file.text = ET.CDATA(filetext)
        files.append(file)
    logging.debug("All devices processed. Finalizing XML.")
    # Write updated XML to output file
    logging.info("Writing updated XML to output file: %s", output_file)
    tree.write(output_file, encoding="utf-8", xml_declaration=True, pretty_print=True)
    logging.info(f"Updated XML written to {output_file}")

def get_nodes_ipv4(xml_file):
    logging.info("Starting to extract IPv4 addresses from XML file: %s", xml_file)
    # Parse the XML
    parser = ET.XMLParser(strip_cdata=False)
    tree = ET.parse(xml_file, parser=parser)
    scenario = tree.getroot()
    nodeip_map = {}
    # Find all <device> tags
    logging.debug("Finding all <links> tags in the XML.")
    links = scenario.findall(".//links/link")

    for link in links:
        logging.debug(f"Processing link: {link}")
        nodeipv4 = None
        if "node1" in link.attrib:
            nodeid = link.get("node1")
            iface1 = link.find(".//iface1")
            if iface1 != None:
                if 'ip4' in iface1.attrib:
                    logging.debug(f"Node {nodeid} has IPv4 address: {iface1.attrib['ip4']}")
                    nodeipv4 = iface1.attrib['ip4']
                    if nodeid not in nodeip_map:
                        nodeip_map[nodeid] = set()
                    nodeip_map[nodeid].add(nodeipv4)
        if "node2" in link.attrib:
            nodeid = link.get("node2")
            iface2 = link.find(".//iface2")
            if iface2 != None:
                if 'ip4' in iface2.attrib:
                    logging.debug(f"Node {nodeid} has IPv4 address: {iface2.attrib['ip4']}")
                    nodeipv4 = iface2.attrib['ip4']
                    if nodeid not in nodeip_map:
                        nodeip_map[nodeid] = set()
                    nodeip_map[nodeid].add(nodeipv4)
    return nodeip_map

if __name__ == "__main__":
    logger = logging.getLogger()
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    input_xml = "input.xml"    # Path to input XML file
    output_xml = "output.xml"  # Path to output XML file
    nodeip_map = get_nodes_ipv4(input_xml)
    add_service_to_userdefined(input_xml, nodeip_map, output_xml)
