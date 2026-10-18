import logging
import sys
import time
from threading import Lock, Thread
from typing import Dict, List, Optional

from scapy.all import sniff, conf

try:
    import readline
except ImportError:
    readline = None

log = logging.getLogger("szr-wifi")

TOOL_NAME = "szr-wifi"
TOOL_PROMPT = f"{TOOL_NAME} > "
QUIET = False

C_RESET = "\033[0m"
C_INFO = "\033[36m"
C_OK = "\033[32m"
C_WARN = "\033[33m"
C_ERR = "\033[31m"
C_DIM = "\033[2m"


def _color(level):
    return {"info": C_INFO, "ok": C_OK, "warn": C_WARN,
            "err": C_ERR, "dim": C_DIM}.get(level, "")


def set_quiet(v):
    global QUIET
    QUIET = v


class TUI:
    def __init__(self, prompt=TOOL_PROMPT):
        self.prompt = prompt
        self.lock = Lock()

    def write(self, msg, level="info"):
        if QUIET:
            return
        with self.lock:
            buf = ""
            if readline:
                try:
                    buf = readline.get_line_buffer()
                except Exception:
                    buf = ""
            sys.stdout.write("\r\033[K" + _color(level) + msg + C_RESET + "\n")
            if buf:
                sys.stdout.write(self.prompt + buf)
            sys.stdout.flush()

    def raw(self, msg):
        with self.lock:
            sys.stdout.write("\r\033[K" + msg + "\n")
            sys.stdout.flush()


class Sniffer:
    def __init__(self, iface):
        self.iface = iface
        self.subs = []
        self.lock = Lock()
        self.running = False
        self.thread = None

    def sub(self, fn):
        with self.lock:
            if fn not in self.subs:
                self.subs.append(fn)

    def unsub(self, fn):
        with self.lock:
            if fn in self.subs:
                self.subs.remove(fn)

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        def cb(p):
            with self.lock:
                subs = list(self.subs)
            for fn in subs:
                try:
                    fn(p)
                except Exception as e:
                    log.debug("sniffer sub: %s", e)

        while self.running:
            try:
                sniff(iface=self.iface, prn=cb, store=False, timeout=1,
                      stop_filter=lambda p: not self.running)
            except Exception as e:
                log.debug("sniff: %s", e)
                time.sleep(0.5)

    def stop(self):
        self.running = False


class Context:
    def __init__(self, iface, mitm_enabled=False, all_channels=False):
        self.iface = iface
        self.mitm_enabled = mitm_enabled
        self.all_channels = all_channels
        self.tui = TUI()
        self.should_exit = False
        self.sniffer = Sniffer(iface)
        self.modules: Dict[str, "Module"] = {}

    def log(self, msg, level="info"):
        self.tui.write(msg, level)

    def shutdown(self):
        for m in self.modules.values():
            if m.active:
                try:
                    m.off()
                except Exception:
                    pass
        self.sniffer.stop()


class Module:
    name = "base"

    def __init__(self, ctx):
        self.ctx = ctx
        self.active = False

    def on(self, *a):
        pass

    def off(self):
        pass

    def status(self):
        return "active" if self.active else "off"
