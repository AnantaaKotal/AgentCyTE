from core.config import ConfigString, ConfigBool, Configuration
from core.services.base import CoreService, ShadowDir, ServiceMode


class DockerComposeService(CoreService):
    """Run a per-node docker-compose file on service start.

    Expects compose files at /tmp/vulns/docker-compose-<node.name>.yml
    """

    # unique name for service
    name: str = "DockerCompose"
    # group for GUI display
    group: str = "Containers"
    # files generated into the node context
    files: list[str] = ["runcompose.sh"]
    # required executables on PATH
    executables: list[str] = []
    # dependencies
    dependencies: list[str] = []
    # startup commands
    startup: list[str] = ["/bin/bash runcompose.sh &"]
    # validation/stop
    validate: list[str] = []
    shutdown: list[str] = []
    validation_mode: ServiceMode = ServiceMode.NON_BLOCKING

    shadow_directories: list[ShadowDir] = []

    def get_text_template(self, name: str) -> str:  # type: ignore[override]
        """Generate script to start docker compose for this node.

        NOTE: This script assumes the host docker daemon is reachable from the
        node context (e.g., via /var/run/docker.sock). If not, ensure host-side
        automation executes the same command.
        """
        return """
        #!/bin/bash
        set -euo pipefail
        LOG="compose_output.txt"
        YML="/tmp/vulns/docker-compose-${node.name}.yml"
        echo "[DockerCompose] node id(${node.id}) name(${node.name}) using $YML" >> "$LOG"
        if [ ! -f "$YML" ]; then
          echo "[DockerCompose] compose file not found: $YML" >> "$LOG"
          exit 0
        fi
        if ! command -v docker >/dev/null 2>&1; then
          echo "[DockerCompose] docker CLI not available in node; skipping" >> "$LOG"
          exit 0
        fi
        # Bring up services in detached mode
        docker compose -f "$YML" up -d >> "$LOG" 2>&1 || echo "[DockerCompose] docker compose failed" >> "$LOG"
        """
