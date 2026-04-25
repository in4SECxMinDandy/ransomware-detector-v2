from matplotlib.figure import Figure

from gui.components.plot_frame import PlotFrame


class _DummyTkWidget:
    def __init__(self):
        self.destroyed = False
        self.pack_calls = []

    def pack(self, **kwargs):
        self.pack_calls.append(kwargs)

    def destroy(self):
        self.destroyed = True


class _DummyCanvas:
    def __init__(self, figure, master):
        self.figure = figure
        self.master = master
        self.widget = _DummyTkWidget()

    def get_tk_widget(self):
        return self.widget

    def draw_idle(self):
        pass


def test_setup_canvas_preserves_ctk_internal_canvas(monkeypatch):
    previous_mpl_canvas = _DummyCanvas(Figure(), None)
    ctk_internal_canvas = object()

    frame = object.__new__(PlotFrame)
    frame._figure = Figure()
    frame._mpl_canvas = previous_mpl_canvas
    frame._canvas = ctk_internal_canvas

    monkeypatch.setattr("gui.components.plot_frame.FigureCanvasTkAgg", _DummyCanvas)

    PlotFrame._setup_canvas(frame)

    assert frame._canvas is ctk_internal_canvas
    assert frame._mpl_canvas is not previous_mpl_canvas
    assert previous_mpl_canvas.get_tk_widget().destroyed is True
    assert frame._mpl_canvas.get_tk_widget().pack_calls == [{"fill": "both", "expand": True}]
