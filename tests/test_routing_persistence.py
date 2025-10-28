import textwrap
import tempfile
import os
from core_topo_gen.parsers.routing import parse_routing_info

XML = textwrap.dedent(
    """<Scenarios>
  <Scenario name='persist'>
    <ScenarioEditor>
      <section name='Node Information' density='0.0'>
        <item selected='Random' factor='1.000' v_metric='Count' v_count='4'/>
      </section>
      <section name='Routing' density='0.0'>
        <item selected='OSPFv2' factor='1.000' r2r_mode='Uniform'/>
  <item selected='RIP' factor='1.000' r2r_mode='Exact' r2r_edges='3' r2s_mode='Exact' r2s_edges='2'/>
        <item selected='EIGRP' factor='1.000' r2r_mode='NonUniform' r2s_mode='Min'/>
      </section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""
)


def test_routing_persistence_round_trip():
    # Write XML to a temp file so parser (which expects a path) can read it
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, 'scenario.xml')
        with open(path, 'w') as f:
            f.write(XML)
        density, routing = parse_routing_info(path, 'persist')
        # Build dict keyed by protocol
        rd = {r.protocol: r for r in routing}
        assert 'OSPFv2' in rd and rd['OSPFv2'].r2r_mode == 'Uniform'
    rip = rd['RIP']
    assert rip.r2r_mode == 'Exact'
    assert rip.r2r_edges == 3
    assert rip.r2s_mode == 'Exact'
    assert rip.r2s_edges == 2
    eigrp = rd['EIGRP']
    assert eigrp.r2r_mode == 'NonUniform'
    assert eigrp.r2s_mode == 'Min'