"""
DeadNet v3 — own-the-PHY UI (Kivy/KivyMD 1.2.0 shell).

Three sections drive the ANDROID<->APP{RECON,ATTACK} state machine in
AppController (app_controller.py):

  RECON   — OWN PHY (seize monitor, Android guarded) + live target inventory;
            CapGate status; RELEASE.
  SELECT  — pick targets (single / comma / S<pattern>) against the recon list.
  ATTACK  — mode picker (1-12 + NUKE) with a per-action knob panel (only the
            fields a mode uses) + plain-language description; pps + burst;
            FIRE/STOP; two live gauges (ACCEPTED % and actual RATE).

Thin shell: all orchestration + device calls live in AppController / engine.
A burst keeps running while backgrounded (on_pause); STOP is the one authority
that halts it (instant — it interrupts any in-flight send).
"""
import subprocess
import threading
import traceback

from kivy.app import App  # noqa: F401
from kivymd.app import MDApp
from kivy.clock import Clock
from kivy.logger import Logger, LOG_LEVELS
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivymd.toast.kivytoast import toast

from gauge import Gauge  # noqa: F401  (registers <Gauge> for main.kv)
from app_controller import AppController, AppState
from engine.attack import ATTACK_CATALOG, mode_desc, mode_knobs

try:
    from jnius import autoclass  # noqa: F401  (present only on-device)
    _ON_DEVICE = True
except Exception:
    _ON_DEVICE = False

Logger.setLevel(LOG_LEVELS["info"])
DEADNET_PREF = "DeadNet"

# spinner order: modes 1..12 then NUKE (id 0) last; labels straight from catalogue
_MODE_IDS = [i for i in sorted(ATTACK_CATALOG) if i != 0] + [0]
_MODE_LABELS = [ATTACK_CATALOG[i].label for i in _MODE_IDS]
_MODE_BY_LABEL = {ATTACK_CATALOG[i].label: i for i in _MODE_IDS}

# per-knob UI metadata: key -> (caption, hint, int-only)
_KNOB_META = {
    "cli":     ("target client MAC", "aa:bb:cc:dd:ee:ff", False),
    "fake":    ("spoofed source / BSSID", "blank = auto (random for beacon flood)", False),
    "ssid":    ("SSID",              "network name (blank = target's)", False),
    "hex":     ("custom frame (hex)", "e.g. c0000000ffffffffffff...", False),
    "payload": ("payload (hex)",     "optional action body", False),
    "reason":  ("reason code",       "0 = default (7 deauth / 8 disassoc)", True),
}


class MainApp(MDApp):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ctl = None
        self._root_ok = self._try_root()

    # -- lifecycle ----------------------------------------------------------
    def on_start(self):
        self.theme_cls.theme_style = "Dark"
        if not self._root_ok:
            self._toast("Error: device is not rooted")
            return
        appdir = self.user_data_dir if _ON_DEVICE else "/tmp/deadnet"
        self.ctl = AppController(appdir, managed_iface="wlan0", mon_iface="mon0",
                                 on_event=self._on_event)
        self.root.ids.mode_spinner.values = _MODE_LABELS
        self.on_mode_pick(self.root.ids.mode_spinner.text)   # seed desc + knobs
        self._refresh_status()
        Clock.schedule_interval(self._tick, 0.5)

    def on_pause(self):
        # keep running while backgrounded — a burst in flight must NOT be torn
        # down just because the app lost focus (stopping is the STOP button's job)
        return True

    def on_stop(self):
        # intentionally does NOT stop an attack: closing the app ends the process
        # (and with it the burst); we don't add fragile lifecycle teardown.
        return

    @staticmethod
    def _try_root() -> bool:
        try:
            subprocess.call(["su", "-c", "id"])
            return True
        except Exception:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: no root")
            return False

    # -- nav ----------------------------------------------------------------
    def goto(self, name: str):
        self.root.ids.sm.current = name
        if name == "recon":
            self._render_targets()
        elif name == "select":
            self._render_selection()

    # -- controller events (marshalled onto the UI thread) ------------------
    def _on_event(self, kind: str, data: dict):
        Clock.schedule_once(lambda dt: self._handle_event(kind, data))

    def _handle_event(self, kind: str, data: dict):
        if kind == "error":
            self._toast(data.get("msg", "error"))
        elif kind == "state":
            self._apply_status(data)
        elif kind == "recon":
            self._toast(f"RECON — monitor ch{data.get('channel')}")
            self._render_targets()
        elif kind in ("target", "targets_cleared"):
            if self.root.ids.sm.current == "recon":
                self._render_targets()
        elif kind == "selection":
            self._render_selection()
            self._toast(f"selected: {data.get('n', 0)}")
        elif kind == "capgate":
            ok = data.get("patched")
            self._toast(("CapGate: PATCHED — " if ok else "CapGate: BLOCKED — ")
                        + str(data.get("reason", "")))
            self._refresh_status()
        elif kind == "attack_start":
            self.root.ids.attack_status.text = (
                f"firing mode {data.get('mode')} @ {data.get('pps')} pps "
                f"over {data.get('n')} target(s)")
            self.goto("attack")
        elif kind == "attack_done":
            self.root.ids.attack_status.text = (
                f"done: {data.get('ok', 0)}/{data.get('sent', 0)} accepted "
                f"(avg {data.get('avg', 0)} pps)")
        elif kind == "released":
            self._toast("PHY released to Android")
            self._refresh_status()

    # -- status strip -------------------------------------------------------
    def _refresh_status(self):
        if self.ctl is not None:
            self._apply_status(self.ctl.capabilities())

    def _apply_status(self, caps: dict):
        if self.root is None:
            return
        st = (caps.get("state") or "android").upper()
        patched = caps.get("patched")
        gate = ("PATCHED" if patched else ("BLOCKED" if patched is False else "?"))
        extra = ""
        if caps.get("state") == AppState.RECON.value:
            extra = f"  ·  targets {caps.get('targets', 0)} (AP {caps.get('aps', 0)})"
        elif caps.get("state") == AppState.ATTACK.value:
            extra = f"  ·  attacking {caps.get('selected', 0)} target(s)"
        self.root.ids.status_bar.text = (
            f"[b]{st}[/b]   cfg80211: {gate}   sel {caps.get('selected', 0)}{extra}")
        self.root.ids.recon_count.text = (
            f"targets: {caps.get('targets', 0)}  (AP {caps.get('aps', 0)} / "
            f"sta {caps.get('stations', 0)})")

    # -- §1 RECON -----------------------------------------------------------
    def on_own(self):
        self._run(lambda: self.ctl.own_recon(), "seizing PHY -> RECON…")

    def on_release(self):
        self._run(lambda: self.ctl.release(), "releasing PHY to Android…")

    def on_capgate(self):
        self._run(lambda: self.ctl.check_capability(), "probing cfg80211 (CapGate)…")

    def on_clear_targets(self):
        if self.ctl:
            self.ctl.clear_targets()
            self._render_targets()

    def _render_targets(self):
        if self.ctl is None or self.root is None:
            return
        try:
            rows = self.ctl.targets()
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: targets read {exc}")
            return
        lst = self.root.ids.target_list
        lst.clear_widgets()
        if not rows:
            lst.add_widget(self._info_label("no targets yet — OWN PHY to start monitor recon"))
            self._refresh_status()
            return
        for i, t in enumerate(rows[:250], start=1):
            lst.add_widget(self._target_row(i, t))
        self._refresh_status()

    def _target_row(self, idx, t):
        kind = "AP" if t.get("kind") == "ap" else "sta"
        label = t.get("ssid") or t.get("vendor") or "(unknown)"
        txt = (f"[b]{idx}. {label}[/b]  [size=15]{t.get('mac','')}  "
               f"ch{t.get('channel', 0)}  {t.get('rssi', 0)}dBm  {kind}[/size]")
        lab = Label(text=txt, markup=True, font_size=19, halign="left",
                    valign="middle", size_hint_y=None, height=52,
                    color=((0.55, 0.7, 1.0, 1) if kind == "AP" else (0.85, 0.85, 0.85, 1)))
        lab.bind(size=lambda w, v: setattr(w, "text_size", (w.width, None)))
        return lab

    # -- §2 SELECT ----------------------------------------------------------
    def on_apply_selection(self, text):
        if self.ctl is None:
            return
        self.ctl.set_selection(text or "")
        self._render_selection()

    def on_clear_selection(self):
        if self.ctl:
            self.ctl.clear_selection()
            self._render_selection()

    def _render_selection(self):
        if self.ctl is None or self.root is None:
            return
        try:
            rows = self.ctl.selected()
        except Exception:  # noqa: BLE001
            rows = []
        lst = self.root.ids.sel_list
        lst.clear_widgets()
        self.root.ids.sel_count.text = f"selected: {len(rows)}"
        if not rows:
            lst.add_widget(self._info_label(
                "nothing selected — enter 3 / 1,3 / Shome* / all above"))
            self._refresh_status()
            return
        for i, m in enumerate(rows, start=1):
            kind = "AP" if m.get("typ") == "ap" else "sta"
            label = m.get("label") or m.get("ssid") or m.get("mac")
            txt = (f"[b]{i}. {label}[/b]  [size=15]{m.get('mac','')}  "
                   f"{m.get('freq', 0)}MHz  {kind}[/size]")
            lab = Label(text=txt, markup=True, font_size=19, halign="left",
                        valign="middle", size_hint_y=None, height=50)
            lab.bind(size=lambda w, v: setattr(w, "text_size", (w.width, None)))
            lst.add_widget(lab)
        self._refresh_status()

    # -- §3 ATTACK ----------------------------------------------------------
    def on_mode_pick(self, label):
        if self.ctl is None or self.root is None:
            return
        mode = _MODE_BY_LABEL.get(label, 1)
        self.ctl.set_mode(mode)
        self.root.ids.mode_desc.text = mode_desc(mode)
        self._build_knobs(mode_knobs(mode))

    def _build_knobs(self, knobs):
        """Rebuild the per-action knob panel to show only this mode's fields."""
        panel = self.root.ids.knob_panel
        panel.clear_widgets()
        for key in knobs:
            caption, hint, int_only = _KNOB_META.get(key, (key, "", False))
            row = BoxLayout(orientation="horizontal", size_hint_y=None, height=62,
                            spacing=10)
            lab = Label(text=caption, markup=True, font_size=18, halign="left",
                        valign="middle", size_hint_x=None, width=240,
                        color=(0.75, 0.78, 0.9, 1))
            lab.bind(size=lambda w, v: setattr(w, "text_size", (w.width, None)))
            ti = TextInput(hint_text=hint, multiline=False, font_size=22,
                           input_filter=("int" if int_only else None),
                           text=self._knob_initial(key))
            ti.bind(on_text_validate=lambda inst, k=key: self._apply_knob(k, inst.text),
                    focus=lambda inst, val, k=key: (None if val else self._apply_knob(k, inst.text)))
            row.add_widget(lab)
            row.add_widget(ti)
            panel.add_widget(row)

    def _knob_initial(self, key):
        c = self.ctl
        return {"cli": getattr(c, "knob_cli", ""), "fake": getattr(c, "knob_fake", ""),
                "ssid": getattr(c, "knob_ssid", ""), "hex": getattr(c, "knob_hex", ""),
                "payload": getattr(c, "knob_payload", ""),
                "reason": (str(c.knob_reason) if getattr(c, "knob_reason", 0) else "")}.get(key, "")

    def _apply_knob(self, key, value):
        if self.ctl is None:
            return
        {"cli": self.ctl.set_client, "fake": self.ctl.set_fake,
         "ssid": self.ctl.set_ssid, "hex": self.ctl.set_custom_hex,
         "payload": self.ctl.set_payload, "reason": self.ctl.set_reason
         }.get(key, lambda _v: None)(value)

    def on_pps(self, text):
        if self.ctl is None:
            return
        try:
            self.ctl.set_pps(int(float(text)))
        except (TypeError, ValueError):
            pass

    def on_budget(self, text):
        if self.ctl is None:
            return
        try:
            self.ctl.set_budget(int(float(text)))
        except (TypeError, ValueError):
            self.ctl.set_budget(0)

    def on_fire(self):
        if self.ctl is None:
            return
        self._run(lambda: self.ctl.start_attack(), "FIRE…")

    def on_stop(self):
        if self.ctl is None:
            return
        self._run(lambda: self.ctl.stop_attack(), "stopping…")

    # -- periodic tick ------------------------------------------------------
    def _tick(self, dt):
        if self.ctl is None or self.root is None:
            return
        caps = self.ctl.capabilities()
        if caps.get("attacking"):
            self._update_gauges(self.ctl.state_metrics())
        # live-grow the recon list while monitoring
        if caps.get("state") == AppState.RECON.value and self.root.ids.sm.current == "recon":
            self._render_targets()

    def _update_gauges(self, m):
        # ACCEPTED — accepted/sent as a percentage (full green = kernel took all)
        acc = self.root.ids.cell_acc
        pct = m["accept_pct"]
        acc.gauge_value = pct
        acc.gauge_max = 100
        acc.big_text = f"{pct}%"
        if m["sent"] and m["miss"] == 0:
            acc.arc_rgba = acc.big_rgba = [0.07, 0.69, 0.07, 1]
            acc.caption_text = "all accepted"
        else:
            acc.arc_rgba = acc.big_rgba = [0.82, 0.55, 0.11, 1]
            acc.caption_text = f"{m['miss']} rejected"

        # RATE — actual pps against the target (full = hitting target)
        rate = self.root.ids.cell_rate
        rate.gauge_value = m["actual_pps"]
        rate.gauge_max = max(1, m["pps"])
        rate.big_text = str(int(m["actual_pps"]))
        rate.caption_text = f"/ {m['pps']} target"

    # -- helpers ------------------------------------------------------------
    def _run(self, fn, msg):
        if self.ctl is None:
            return
        self._toast(msg)
        threading.Thread(target=self._guarded, args=(fn,), daemon=True).start()

    def _guarded(self, fn):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: action failed {exc} {traceback.format_exc()}")
            self._on_event("error", {"msg": str(exc)})

    @staticmethod
    def _info_label(text):
        lab = Label(text=text, font_size=19, halign="left", valign="middle",
                    size_hint_y=None, height=30, color=(0.7, 0.7, 0.7, 1))
        lab.bind(size=lambda w, v: setattr(w, "text_size", (w.width, None)))
        return lab

    @staticmethod
    def _toast(msg):
        try:
            toast(msg, duration=2, background=[0, 0, 0, 1])
        except Exception:  # noqa: BLE001
            Logger.info(f"{DEADNET_PREF}: {msg}")


if __name__ == "__main__":
    MainApp().run()
