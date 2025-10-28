from __future__ import annotations
from pathlib import Path

from core_topo_gen.parsers.hitl import parse_hitl_info


def test_parse_hitl_info_handles_interfaces(tmp_path: Path) -> None:
    xml_content = """
    <Scenarios>
      <Scenario name="Demo">
        <ScenarioEditor>
          <HardwareInLoop enabled="true">
            <Interface name="en0" alias="ethernet" mac="aa:bb:cc:dd:ee:ff" ipv4="10.0.0.1/24, 10.0.0.2/24" ipv6="fe80::1" />
            <Interface name=" usb 0 " />
          </HardwareInLoop>
        </ScenarioEditor>
      </Scenario>
    </Scenarios>
    """
    xml_path = tmp_path / "scenario.xml"
    xml_path.write_text(xml_content, encoding="utf-8")

    info = parse_hitl_info(str(xml_path), "Demo")

    assert info["enabled"] is True
    assert len(info["interfaces"]) == 2
    first = info["interfaces"][0]
    assert first["name"] == "en0"
    assert first["alias"] == "ethernet"
    assert first["mac"] == "aa:bb:cc:dd:ee:ff"
    assert first["ipv4"] == ["10.0.0.1/24", "10.0.0.2/24"]
    assert first["ipv6"] == ["fe80::1"]
    assert first["attachment"] == "existing_router"

    second = info["interfaces"][1]
    assert second["attachment"] == "existing_router"
