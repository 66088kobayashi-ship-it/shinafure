"""品触れ (Shinafure): canary people registered by data owners, matched by AI
providers against inference inputs, through a ledger that never sees plaintext."""
from .canary import Canary, make_canaries
from .issuance import Opening, Ticket, canary_from_ticket, new_opening
from .registry import Detector, Registry, register_canaries, register_ticketed

__all__ = ["Canary", "make_canaries", "Detector", "Registry", "register_canaries", "register_ticketed",
           "Opening", "Ticket", "canary_from_ticket", "new_opening"]
__version__ = "0.5.0"
