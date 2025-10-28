from core_topo_gen.planning.full_preview import build_full_preview

def test_segmentation_preview_artifacts(tmp_path):
    role_counts = {'PC': 4}
    full = build_full_preview(
        role_counts=role_counts,
        routers_planned=1,
        services_plan={},
        vulnerabilities_plan={},
        r2r_policy=None,
        r2s_policy={'mode':'Exact','target_per_router':1},
        routing_items=None,
        routing_plan={},
        segmentation_density=0.8,
        segmentation_items=[{'selected':'Firewall','factor':0.5},{'selected':'NAT','factor':0.5}],
        traffic_plan=None,
        seed=101,
        ip4_prefix='10.10.0.0/16'
    )
    seg_prev = full.get('segmentation_preview') or {}
    artifacts = seg_prev.get('artifacts') or []
    assert isinstance(artifacts, list)
    # We expect at least the summary json to be listed
    assert any(a.get('file')=='segmentation_summary.json' for a in artifacts), artifacts
