from core.config import ConfigString, ConfigBool, Configuration
from core.services.base import CoreService, ShadowDir, ServiceMode

# class that subclasses CoreService
class TrafficService(CoreService):
    # unique name for your service within CORE
    name: str = "Traffic"
    # the group your service is associated with, used for display in GUI
    group: str = "Simple"
    # directories that the service should shadow mount, hiding the system directory
    #directories: list[str] = ["/usr/local/core"]
    # files that this service should generate, defaults to nodes home directory
    # or can provide an absolute path to a mounted directory
    files: list[str] = ["runtraffic.sh"]
    # executables that should exist on path, that this service depends on
    executables: list[str] = []
    # other services that this service depends on, defines service start order
    dependencies: list[str] = []
    # commands to run to start this service
    startup: list[str] = ["/bin/bash runtraffic.sh &"]
    # commands to run to validate this service
    validate: list[str] = []
    # commands to run to stop this service
    shutdown: list[str] = []
    # validation mode BLOCKING, NON_BLOCKING, and TIMER
    validation_mode: ServiceMode = ServiceMode.NON_BLOCKING

    # defines directories that this service can help shadow within a node
    shadow_directories: list[ShadowDir] = []

    def get_text_template(self, name: str) -> str:
        """
        This function is used to return a string template that will be rendered
        by the templating engine. Available variables will be node and any other
        key/value pairs returned by the "data()" function.

        :param name: name of file to get template for
        :return: string template
        """
        return """
        #!/bin/bash
        # Traffic starter
        # node id(${node.id}) name(${node.name})
        cp /tmp/traffic/traffic_${node.id}_*.py .
        for file in traffic_${node.id}_*.py; do
           echo "running: python3 $file" >> output.txt
           python3 $file &
        done
        """

