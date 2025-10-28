import os, tempfile
import xml.etree.ElementTree as ET
from core_topo_gen.parsers.routing import parse_routing_info

XML_TMPL = """<Scenarios><Scenario name='p'><ScenarioEditor>
  <section name='Node Information'>
    <item selected='Workstation' factor='1'/>
  </section>
  <section name='Routing'>
    {items}
  </section>
</ScenarioEditor></Scenario></Scenarios>"""

def write(items_xml: str):
    td = tempfile.TemporaryDirectory()
    path = os.path.join(td.name, 's.xml')
    with open(path, 'w') as f:
        f.write(XML_TMPL.format(items=items_xml))
    return td, path

def test_only_selected_protocols_no_random():
    td, path = write("""<item selected='OSPFv2' factor='1'/>""")
    try:
        density, items = parse_routing_info(path, 'p')
        assert density == 0.0
        protos = {i.protocol for i in items}
        assert protos == {'OSPFv2'}
    finally:
        td.cleanup()

def test_random_fallback_uses_selected_pool():
    # Include a Random item plus two concrete; parse should keep Random marker (assignment handled later in builder)
    td, path = write("""
      <item selected='Random' factor='1'/>
      <item selected='OSPFv2' factor='1'/>
      <item selected='BGP' factor='1'/>
    """)
    try:
        density, items = parse_routing_info(path, 'p')
        protos = {i.protocol for i in items}
        # parse_routing_info should include protocols exactly as provided
        assert protos == {'Random','OSPFv2','BGP'}
    finally:
        td.cleanup()
