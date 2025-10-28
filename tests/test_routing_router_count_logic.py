from core_topo_gen.parsers.node_info import parse_node_info
from core_topo_gen.parsers.routing import parse_routing_info
from core_topo_gen.utils.allocation import compute_role_counts
import tempfile, os

XML_BASE = """<Scenarios>
  <Scenario name='s'>
    <ScenarioEditor>
      <section name='Node Information'>
        <item selected='Server' factor='1'/>
      </section>
      {routing}
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""

ROUTING_DENSITY_AND_COUNT = """<section name='Routing' density='0.5'>
  <item selected='OSPF' v_metric='Count' v_count='3'/>
  <item selected='BGP' factor='1'/>
</section>"""

ROUTING_COUNT_ONLY = """<section name='Routing'>
  <item selected='OSPF' v_metric='Count' v_count='2'/>
</section>"""


def write(xml_content):
    td = tempfile.TemporaryDirectory()
    path = os.path.join(td.name, 'x.xml')
    with open(path, 'w') as f:
        f.write(XML_BASE.format(routing=xml_content))
    return td, path


def derive_planned_counts(xml_path):
  density_base, weight_items, count_items, _ = parse_node_info(xml_path, 's')
  roles = compute_role_counts(density_base, weight_items)
  for role, c in count_items:
    roles[role] = roles.get(role, 0) + c
  density, ritems = parse_routing_info(xml_path, 's')
  total_hosts = sum(roles.values())
  count_router_count = sum(getattr(ri, 'abs_count', 0) for ri in ritems)
  # replicate new logic
  density_router_count = 0
  if density and density > 0 and total_hosts > 0:
    if density >= 1.0:
      density_router_count = int(round(density))
    else:
      density_router_count = int(round(total_hosts * max(0.0, min(1.0, density))))
    density_router_count = max(0, min(total_hosts, density_router_count))
  only_count_based = (count_router_count > 0) and (not density or density <= 0)
  if only_count_based:
    router_count = min(total_hosts, count_router_count)
  else:
    router_count = min(total_hosts, density_router_count + count_router_count)
  return total_hosts, density_router_count, count_router_count, router_count


def test_count_only_exact():
    td, path = write(ROUTING_COUNT_ONLY)
    try:
        total_hosts, dcnt, ccnt, planned = derive_planned_counts(path)
        assert ccnt == 2
        assert dcnt == 0
        assert planned == 2
    finally:
        td.cleanup()


def test_density_adds_and_clamps():
    td, path = write(ROUTING_DENSITY_AND_COUNT)
    try:
        total_hosts, dcnt, ccnt, planned = derive_planned_counts(path)
        assert ccnt == 3
        assert dcnt > 0
        assert planned <= total_hosts
        assert planned == min(total_hosts, dcnt + ccnt)
    finally:
        td.cleanup()
