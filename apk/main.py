"""
DeadNet — single-radio, 2-preset redesign (PR #2) UI.

Three nav sections (owner's convention): Detect & Connect / Scan & Select /
Configure & Trigger. Two presets on the one internal radio:
  RECON & RECORD -> monitor + air sniff;  LOCK & LEVEL -> associate + focused fire.

This file is the thin Kivy/KivyMD 1.2.0 shell. All orchestration lives in
AppController (app_controller.py), which drives the engine/ layer. Release-back of
the radio to Android is guaranteed (RadioController atexit/signal + on_stop()).
"""
import dataclasses
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
from app_controller import AppController, Mode, EmitMode

try:
    from jnius import autoclass  # noqa: F401  (present only on-device)
    _ON_DEVICE = True
except Exception:
    _ON_DEVICE = False

Logger.setLevel(LOG_LEVELS["info"])
DEADNET_PREF = "DeadNet"

# knobs we never auto-render (derived/managed by the controller)
_KNOB_SKIP = {"emit_mode", "scan_phases"}


class MainApp(MDApp):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ctl = None
        self._root_ok = self._try_root()
        self._peaks = {"tx": 1.0, "surv": 1.0, "evid": 1.0}
        self._knob_widgets = {}

    # -- lifecycle ----------------------------------------------------------
    def on_start(self):
        self.theme_cls.theme_style = "Dark"
        if not self._root_ok:
            self._toast("Error: device is not rooted")
            return
        appdir = self.user_data_dir if _ON_DEVICE else "/tmp/deadnet"
        self.ctl = AppController(appdir, managed_iface="wlan0",
                                 on_event=self._on_event)
        self._build_knob_panel()
        self._refresh_detect()
        Clock.schedule_interval(self._tick, 0.5)

    def on_stop(self):
        # hard guarantee: hand the radio back to Android on app exit
        if self.ctl is not None:
            try:
                self.ctl.shutdown()
            except Exception as exc:  # noqa: BLE001
                Logger.error(f"{DEADNET_PREF}: shutdown on_stop {exc}")

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
        if name == "scan":
            self.refresh_scents()

    # -- controller events (marshalled onto the UI thread) ------------------
    def _on_event(self, kind: str, data: dict):
        Clock.schedule_once(lambda dt: self._handle_event(kind, data))

    def _handle_event(self, kind: str, data: dict):
        if kind == "error":
            self._toast(data.get("msg", "error"))
        elif kind == "mode":
            self._refresh_detect()
            self._toast(f"{data.get('preset','')} / {data.get('mode','')}")
        elif kind == "detecting":
            self.root.ids.router_hint.text = "smelling routers… pick 1–2"
        elif kind == "ap_selected":
            self._refresh_detect()
        elif kind == "connected":
            self._refresh_detect()
            links = data.get("links", {})
            self._toast(f"connected: {links.get('mode','')}")
            self.goto("scan")
        elif kind == "scan":
            self.root.ids.scan_status.text = (
                f"P{data.get('phase')} smelling {data.get('done')}/{data.get('total')}")
        elif kind == "scan_done":
            self.root.ids.scan_status.text = "scan complete"
            self.refresh_scents()
        elif kind in ("selected", "deselected", "selection_cleared"):
            self._refresh_sel_count()

    # -- §1 Detect & Select -------------------------------------------------
    def on_detect(self):
        """Seize the radio into monitor and smell routers across both bands."""
        self._run(lambda: self.ctl.detect_and_select(hop_both_bands=True),
                  "seizing radio — smelling routers…")

    def on_adhd(self, on: bool):
        if self.ctl is not None:
            self.ctl.adhd = bool(on)

    def on_connect(self):
        """Release monitor, associate, scope focused smelling to the subnet."""
        if self.ctl is None:
            return
        if not self.ctl.target_aps:
            self._toast("pick 1–2 routers first")
            return
        self._run(lambda: self.ctl.connect(adhd=self.ctl.adhd),
                  "connecting + focused smelling…")

    def on_release(self):
        self._run(lambda: self.ctl.release(), "releasing radio to Android…")

    def _refresh_detect(self):
        if self.ctl is None or self.root is None:
            return
        cap = self.ctl.capabilities()
        self.root.ids.radio_state.text = (
            f"radio: [b]{cap['state']}[/b]   assoc: {cap.get('associated') or '-'}")
        links = getattr(self.ctl, "links", {}) or {}
        if links:
            w0 = links.get("wlan0", {})
            extra = " + wlan1" if links.get("wlan1") else ""
            self.root.ids.link_state.text = (
                f"[b]{links.get('mode','')}[/b]  {w0.get('ssid','')}{extra}")
        else:
            n = len(self.ctl.target_aps)
            self.root.ids.link_state.text = f"targets: {n}/2" if n else ""

    def _render_routers(self, routers, selected):
        lst = self.root.ids.router_list
        lst.clear_widgets()
        from kivy.factory import Factory
        for r in routers[:60]:
            bssid = r.get("mac", "")
            ssid = r.get("ssid") or "(hidden)"
            txt = (f"[b]{ssid}[/b]\n[size=19]{bssid}   ch{r.get('channel',0)}   "
                   f"{r.get('signal_dbm',0)}dBm[/size]")
            row = Factory.RouterRow(text=txt, bssid=bssid,
                                    size_hint_y=None, height=84)
            row.state = "down" if bssid in selected else "normal"
            row.bind(on_press=lambda w, b=bssid: self._toggle_router(b, w))
            lst.add_widget(row)

    def _toggle_router(self, bssid, widget):
        if self.ctl is None:
            return
        if widget.state == "down":
            if not self.ctl.select_ap(bssid):
                widget.state = "normal"      # refused (cap of 2)
        else:
            self.ctl.deselect_ap(bssid)
        self._refresh_detect()

    def _refresh_routers(self):
        if self.ctl is None or self.root is None:
            return
        try:
            routers = self.ctl.routers()
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: router read {exc}")
            return
        self._render_routers(routers, set(self.ctl.target_aps))

    # -- §2 Scan & Select ---------------------------------------------------
    def refresh_scents(self):
        if self.ctl is None:
            return
        threading.Thread(target=self._refresh_scents_worker, daemon=True).start()

    def _refresh_scents_worker(self):
        try:
            scents = self.ctl.scents()
            selected = {s["mac"] for s in self.ctl.selected()}
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: scent read {exc}")
            return
        Clock.schedule_once(lambda dt: self._render_scents(scents, selected))

    def _render_scents(self, scents, selected):
        lst = self.root.ids.scent_list
        lst.clear_widgets()
        for s in scents[:200]:
            lst.add_widget(self._scent_row(s, s["mac"] in selected))
        self._refresh_sel_count()

    def _scent_row(self, s, is_sel):
        row = BoxLayout(size_hint_y=None, height=58, spacing=6)
        kind = "AP" if not s["is_station"] else "sta"
        label = s["ssid"] or s["vendor"] or "(unknown)"
        txt = (f"[b]{label}[/b]  [size=15]{s['mac']}  {s['ip'] or ''}  "
               f"ch{s['channel']}  {s['signal_dbm']}dBm  {kind}[/size]")
        lab = Label(text=txt, markup=True, font_size=18, halign="left", valign="middle")
        lab.bind(size=lambda w, v: setattr(w, "text_size", v))
        btn = Button(text="[b]-[/b]" if is_sel else "[b]Select +[/b]", markup=True,
                     size_hint_x=None, width=170, font_size=20,
                     background_color=((0.4, 0.1, 0.1, 1) if is_sel else (0.1, 0.35, 0.1, 1)))
        mac = s["mac"]
        btn.bind(on_press=lambda *a: self._toggle_select(mac, is_sel))
        row.add_widget(lab)
        row.add_widget(btn)
        return row

    def _toggle_select(self, mac, is_sel):
        if is_sel:
            self.ctl.deselect(mac)
        else:
            self.ctl.select(mac)
        self.refresh_scents()

    def on_clear_selection(self):
        if self.ctl:
            self.ctl.clear_selection()
            self.refresh_scents()

    def _refresh_sel_count(self):
        if self.ctl is None:
            return
        try:
            n = len(self.ctl.selected())
        except Exception:  # noqa: BLE001
            n = 0
        self.root.ids.sel_count.text = f"selected: {n}"

    # -- §3 Configure & Trigger ---------------------------------------------
    def on_fire(self):
        if self.ctl is None:
            return
        if self.ctl.mode != Mode.LOCKED:
            self._toast("FIRE needs Lock & Level first")
            return
        self._run(lambda: self.ctl.fire(), "firing…")

    def on_cease(self):
        self._run(lambda: self.ctl.cease(), "ceasing…")

    def _build_knob_panel(self):
        panel = self.root.ids.knob_panel
        panel.clear_widgets()
        for f in dataclasses.fields(self.ctl.knobs):
            if f.name in _KNOB_SKIP:
                continue
            val = getattr(self.ctl.knobs, f.name)
            row = BoxLayout(size_hint_y=None, height=52, spacing=8)
            row.add_widget(Label(text=f.name, font_size=18, halign="left",
                                 valign="middle", text_size=(None, None)))
            if isinstance(val, bool):
                b = Button(text="ON" if val else "OFF", size_hint_x=None, width=120,
                           background_color=((0.1, 0.4, 0.1, 1) if val else (0.3, 0.3, 0.3, 1)))
                b.bind(on_press=lambda btn, n=f.name: self._toggle_knob(n, btn))
                row.add_widget(b)
                self._knob_widgets[f.name] = b
            else:
                ti = TextInput(text=str(val), multiline=False, input_filter="float",
                               size_hint_x=None, width=160, font_size=18)
                ti.bind(on_text_validate=lambda w, n=f.name: self._set_knob(n, w.text),
                        focus=lambda w, foc, n=f.name: (None if foc else self._set_knob(n, w.text)))
                row.add_widget(ti)
                self._knob_widgets[f.name] = ti
            panel.add_widget(row)

    def _toggle_knob(self, name, btn):
        new = not getattr(self.ctl.knobs, name)
        setattr(self.ctl.knobs, name, new)
        btn.text = "ON" if new else "OFF"
        btn.background_color = (0.1, 0.4, 0.1, 1) if new else (0.3, 0.3, 0.3, 1)

    def _set_knob(self, name, text):
        cur = getattr(self.ctl.knobs, name)
        try:
            val = type(cur)(float(text)) if isinstance(cur, (int, float)) else text
            if isinstance(cur, int):
                val = int(float(text))
            setattr(self.ctl.knobs, name, val)
        except Exception:  # noqa: BLE001
            self._toast(f"bad value for {name}")

    # -- periodic tick ------------------------------------------------------
    def _tick(self, dt):
        if self.ctl is None or self.root is None:
            return
        if self.ctl.mode == Mode.FIRING:
            self._update_gauges(self.ctl.state_metrics())
        # stream smelled routers into the Detect list while discovering
        if self.ctl.mode == Mode.RECON and self.root.ids.sm.current == "detect":
            self._refresh_routers()

    def _update_gauges(self, m):
        tx = self.root.ids.cell_tx
        tx.gauge_value = m["tx_ps"]
        tx.gauge_max = self._auto("tx", m["tx_ps"], 50.0)
        tx.big_text = str(int(round(m["tx_ps"])))

        surv = self.root.ids.cell_surv
        surv.gauge_value = m["leaking"]
        surv.gauge_max = self._auto("surv", m["leaking"], 5.0)
        if m["confirmed"]:
            surv.arc_rgba = [0.07, 0.69, 0.07, 1]
            surv.big_rgba = [0.07, 0.69, 0.07, 1]
            surv.big_text = "0"
            surv.caption_text = "[b]CONFIRMED[/b]"
        else:
            surv.arc_rgba = [0.82, 0.11, 0.11, 1]
            surv.big_rgba = [0.82, 0.11, 0.11, 1]
            surv.big_text = str(int(m["leaking"]))
            surv.caption_text = "leaking"

        evid = self.root.ids.cell_evid
        evid.gauge_value = m["evidence"]
        evid.gauge_max = self._auto("evid", m["evidence"], 50.0)
        evid.big_text = str(int(m["evidence"]))

    def _auto(self, key, value, floor):
        peak = max(value, self._peaks[key] * 0.9, floor)
        self._peaks[key] = peak
        return peak

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
        lab = Label(text=text, font_size=18, halign="left", valign="middle",
                    size_hint_y=None, height=28)
        lab.bind(size=lambda w, v: setattr(w, "text_size", v))
        return lab

    @staticmethod
    def _toast(msg):
        try:
            toast(msg, duration=2, background=[0, 0, 0, 1])
        except Exception:  # noqa: BLE001
            Logger.info(f"{DEADNET_PREF}: {msg}")


if __name__ == "__main__":
    MainApp().run()
