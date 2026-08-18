"""Plugin manifest discovery and capability matching."""
from .service import CapabilityRegistry, RegistryError, RegistrySnapshot

__all__ = ["CapabilityRegistry", "RegistryError", "RegistrySnapshot"]
