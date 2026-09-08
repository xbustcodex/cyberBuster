"""Plugin module — catalog, executor, and Fernet-based secret crypto."""
from .catalog import CATALOG, CATALOG_BY_KIND, get_type
from .crypto import encrypt, decrypt, mask
from .executor import dispatch, query, EVENT_KINDS

__all__ = ["CATALOG", "CATALOG_BY_KIND", "get_type", "encrypt", "decrypt", "mask", "dispatch", "query", "EVENT_KINDS"]
