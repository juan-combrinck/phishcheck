from PySide6.QtCore import QThread, Signal


class Task(QThread):
    """Runs fn() -> (ok, message) off the UI thread."""
    result = Signal(bool, str)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            ok, msg = self.fn()
        except Exception as exc:
            ok, msg = False, str(exc)
        self.result.emit(ok, msg)
