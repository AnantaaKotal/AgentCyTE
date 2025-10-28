import os
import tempfile
import textwrap
from core_topo_gen.parsers.node_info import parse_node_info
from core_topo_gen.parsers.routing import parse_routing_info
from core_topo_gen.utils.allocation import compute_role_counts

SIMPLE_XML_TEMPLATE = '''<Scenarios>
  <Scenario name="demo">
    <ScenarioEditor>
      <section name="Node Information">
        <item selected="Workstation" factor="1" />
      </section>
      {routing_section}
    </ScenarioEditor>
  </Scenario>
</Scenarios>'''

COUNT_ONLY_ROUTING = '''<section name="Routing">
  <item selected="OSPF" v_metric="Count" v_count="1" />
</section>'''

DENSITY_AND_COUNT_ROUTING = '''<section name="Routing" density="0.6">
  <item selected="OSPF" v_metric="Count" v_count="2" />
  <item selected="BGP" factor="1" />
</section>'''

NO_ROUTING = ''

def write_xml(tmpdir, routing):
    path = os.path.join(tmpdir, 'scenario.xml')
    with open(path, 'w') as f:
        f.write(SIMPLE_XML_TEMPLATE.format(routing_section=routing))
    return path

def test_count_only_routing_parsing_exact():
  with tempfile.TemporaryDirectory() as td:
    xml_path = write_xml(td, COUNT_ONLY_ROUTING)
    density_base, weight_items, count_items, _services = parse_node_info(xml_path, 'demo')
    roles = compute_role_counts(density_base, weight_items)
    # Count items should not alter base allocation inside this test scenario (one count row)
    for role, c in count_items:
      roles[role] = roles.get(role, 0) + c
    # With only a weight row and no explicit total_nodes, default base now = 10
    assert density_base == 10
    assert sum(roles.values()) == 10
    density, ritems = parse_routing_info(xml_path, 'demo')
    assert density == 0.0
    # Expect exactly one count-based routing item with abs_count=1
    assert any(getattr(i, 'abs_count', 0) == 1 for i in ritems), ritems


def test_no_routing_section():
    with tempfile.TemporaryDirectory() as td:
        xml_path = write_xml(td, NO_ROUTING)
        density, ritems = parse_routing_info(xml_path, 'demo')
        assert density == 0.0
        assert ritems == []


def test_density_and_count_routing_parse():
    with tempfile.TemporaryDirectory() as td:
        xml_path = write_xml(td, DENSITY_AND_COUNT_ROUTING)
        density, ritems = parse_routing_info(xml_path, 'demo')
        assert density == 0.6
    count_sum = sum(getattr(i, 'abs_count', 0) for i in ritems)
    assert count_sum == 2
    weight = sum(i.factor for i in ritems if getattr(i, 'abs_count', 0) == 0)
    assert weight > 0
