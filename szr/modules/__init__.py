from .scan import ScanModule
from .probe import ProbeModule
from .eapol import EapolModule
from .deauth import DeauthModule
from .pmkid import PmkidModule
from .ids import IDSModule
from .flood import FloodModule
from .wps import WpsModule
from .portal import PortalModule
from .mitm import MitmModule
from .playbook import PlaybookModule


def yukle(ctx):
    m = {
        "scan": ScanModule(ctx),
        "probe": ProbeModule(ctx),
        "eapol": EapolModule(ctx),
        "deauth": DeauthModule(ctx),
        "pmkid": PmkidModule(ctx),
        "ids": IDSModule(ctx),
        "flood": FloodModule(ctx),
        "wps": WpsModule(ctx),
        "portal": PortalModule(ctx),
        "playbook": PlaybookModule(ctx),
    }
    if ctx.mitm_enabled:
        m["mitm"] = MitmModule(ctx)
    return m
