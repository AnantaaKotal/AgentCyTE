# Scenario Report

Scenario: Demo
Generated: 2025-10-20 16:33:14

## Summary
- Total nodes: 1
- Routers: 1  |  Switches: 0  |  Hosts: 0
- Traffic flows: 0
- Segmentation rules: 0

## Routers
- Router 1: protocol=(none) services=[IPForward, zebra]

## Details
### Generation parameters
- hitl_attachment: {'enabled': True, 'session_option_enabled': True, 'interfaces': [{'name': 'en0', 'attachment': 'existing_router', 'assignment': 'peer', 'rj45_node_id': 200, 'peer_node_id': 1, 'linked': True, 'uplink_router_node_id': 1}, {'name': 'en1', 'attachment': 'existing_router', 'assignment': 'network', 'rj45_node_id': 201, 'peer_node_id': 42, 'linked': False, 'uplink_router_node_id': 5, 'uplink_linked': False}], 'created_nodes': [200, 201], 'created_network_nodes': [301]}
