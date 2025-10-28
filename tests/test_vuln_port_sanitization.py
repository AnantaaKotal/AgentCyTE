import textwrap

from core_topo_gen.utils import vuln_process


def test_prune_service_ports_removes_host_mapping_strings():
    service = {'ports': ['8080:80', '8443:443/tcp', '53/udp']}

    vuln_process._prune_service_ports(service)

    assert service['ports'][0] == '80'
    assert service['ports'][1] == '443/tcp'
    assert service['ports'][2] == '53/udp'


def test_prune_service_ports_removes_published_fields():
    service = {
        'ports': [
            {'target': 80, 'published': 8080, 'protocol': 'tcp'},
            {'target': 443, 'protocol': 'tcp'},
        ]
    }

    vuln_process._prune_service_ports(service)

    assert service['ports'][0] == {'target': 80, 'protocol': 'tcp'}
    assert service['ports'][1] == {'target': 443, 'protocol': 'tcp'}


def test_strip_port_mappings_from_text_handles_strings_and_dicts():
    compose_text = textwrap.dedent(
        """
        services:
          app:
            image: demo
            container_name: app-old
            ports:
              - "8080:80"
              - 8443:443/tcp
              - 53/udp
              - target: 9000
                published: 9000
                protocol: tcp
          other:
            image: test
        """
    )

    sanitized = vuln_process._strip_port_mappings_from_text(compose_text)

    assert '8080:80' not in sanitized
    assert '8443:443/tcp' not in sanitized
    assert 'published:' not in sanitized
    assert '- 80' in sanitized or '- "80"' in sanitized
    assert '443/tcp' in sanitized
    assert '53/udp' in sanitized
