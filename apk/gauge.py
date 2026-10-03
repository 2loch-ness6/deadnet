from kivy.uix.widget import Widget
from kivy.properties import NumericProperty, StringProperty, ListProperty
from kivy.graphics import Color, Line, Ellipse
from math import cos, sin, radians


#   --------------------------------------------------------------------------------------------------------------------
#   Gauge
#   --------------------------------------------------------------------------------------------------------------------
#   A lightweight semicircular rate gauge drawn with raw Kivy canvas instructions (no external deps / no images, so it
#   survives a buildozer build cleanly). The needle sweeps a 180 deg arc over the top of the dial, left (min) to
#   right (max). `value`/`max_value` set the needle position, `arc_color` recolors the active arc + needle hub,
#   and the number/label themselves live in the .kv so they can use Kivy markup.
#
#   Kivy's Line(circle=...) measures angles in degrees, 0 deg at 12 o'clock, increasing clockwise. The top semicircle
#   therefore runs from -90 (9 o'clock) through 0 (top) to +90 (3 o'clock).
#   --------------------------------------------------------------------------------------------------------------------

_ARC_START = -90.0  # 9 o'clock
_ARC_SWEEP = 180.0  # over the top to 3 o'clock
_LINE_W = 10
_NEEDLE_W = 3


class Gauge(Widget):
    value = NumericProperty(0.0)
    max_value = NumericProperty(100.0)

    arc_color = ListProperty([0.07, 0.69, 0.07, 1])   # green by default
    track_color = ListProperty([1, 1, 1, 0.08])
    needle_color = ListProperty([1, 1, 1, 0.9])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(pos=self._redraw, size=self._redraw, value=self._redraw,
                  max_value=self._redraw, arc_color=self._redraw,
                  track_color=self._redraw, needle_color=self._redraw)

    def _geom(self):
        # dial centred horizontally, pinned toward the top of the widget (room for text below)
        d = min(self.width, self.height * 1.6)
        cx = self.center_x
        cy = self.y + self.height * 0.42
        r = d * 0.42
        return cx, cy, r

    def _fraction(self):
        if self.max_value <= 0:
            return 0.0
        f = self.value / self.max_value
        return 0.0 if f < 0 else (1.0 if f > 1 else f)

    def _redraw(self, *_):
        self.canvas.clear()
        cx, cy, r = self._geom()
        frac = self._fraction()
        with self.canvas:
            # dim background track (full top semicircle)
            Color(*self.track_color)
            Line(circle=(cx, cy, r, _ARC_START, _ARC_START + _ARC_SWEEP), width=_LINE_W, cap="round")

            # active arc up to the current value
            Color(*self.arc_color)
            Line(circle=(cx, cy, r, _ARC_START, _ARC_START + _ARC_SWEEP * frac), width=_LINE_W, cap="round")

            # needle: frac 0 -> points left, frac 1 -> points right, sweeping over the top
            ang = radians(180.0 - 180.0 * frac)  # math angle CCW from +x
            tip_x = cx + (r * 0.92) * cos(ang)
            tip_y = cy + (r * 0.92) * sin(ang)
            Color(*self.needle_color)
            Line(points=[cx, cy, tip_x, tip_y], width=_NEEDLE_W, cap="round")

            # hub
            Color(*self.arc_color)
            hub = r * 0.13
            Ellipse(pos=(cx - hub, cy - hub), size=(hub * 2, hub * 2))
