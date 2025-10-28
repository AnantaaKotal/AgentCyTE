import os, tempfile
from core_topo_gen.parsers.node_info import parse_node_info
from core_topo_gen.utils.allocation import compute_role_counts

XML = """<Scenarios>
  <Scenario name='add'>
    <ScenarioEditor>
      <section name='Node Information'>
        <item selected='Workstation' factor='2'/>
        <item selected='Server' factor='1'/>
        <item selected='Database' v_metric='Count' v_count='2'/>
        <item selected='Sensor' v_metric='Count' v_count='1'/>
      </section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""

def test_node_info_additive_semantics():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, 's.xml')
        with open(path, 'w') as f:
            f.write(XML)
        density_base, weight_items, count_items, services = parse_node_info(path, 'add')
        # Density base now defaults to 10 when not explicitly provided
        assert density_base == 10
        assert services == []
        assert len(weight_items) == 2
        assert set(r for r,_ in weight_items) == {'Workstation','Server'}
        assert sorted(count_items) == [('Database', 2), ('Sensor', 1)]
        # Allocate weight roles across base (10 distributed by 2:1 ratio => ~6 and ~4 after rounding logic)
        total_factor = sum(f for _, f in weight_items)
        norm_items = [(r, f/total_factor) for r, f in weight_items]
        weight_counts = compute_role_counts(density_base, norm_items)
        assert sum(weight_counts.values()) == 10
        # Add additive counts
        for role, c in count_items:
            weight_counts[role] = weight_counts.get(role, 0) + c
        assert sum(weight_counts.values()) == 13  # 10 base + 3 additive
