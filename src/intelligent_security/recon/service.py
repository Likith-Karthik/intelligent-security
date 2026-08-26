"""Discovery of executable capabilities available to the recon stage."""

from intelligent_security.domain import Audit, CapabilityDiscovery, CapabilityStage
from intelligent_security.execution.service import ExecutionService
from intelligent_security.registry.service import CapabilityRegistry


class ReconDiscoveryService:
    """Build a recon-only catalog without invoking a plugin or a model."""

    def discover(self, audit: Audit, registry: CapabilityRegistry, execution: ExecutionService) -> CapabilityDiscovery:
        eligible_plugin_ids = execution.executable_plugin_ids(audit, registry)
        return registry.discover(
            audit,
            eligible_plugin_ids=eligible_plugin_ids,
            stages={CapabilityStage.RECON},
        )
