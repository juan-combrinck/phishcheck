import ctypes
import os
import sys
from pathlib import Path

from PySide6.QtCore import QPointF, QRect, QRectF, QSize, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import (QBrush, QColor, QDesktopServices, QFont, QFontMetrics, QGuiApplication, QIcon, QPainter, QPen,
                           QPixmap, QRadialGradient)
from PySide6.QtWidgets import (QApplication, QCheckBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel,
                               QListWidget, QListWidgetItem, QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton,
                               QScrollArea, QSplitter, QStyle, QStyledItemDelegate, QTableWidget, QTableWidgetItem,
                               QTabWidget, QTextEdit, QToolButton, QVBoxLayout, QWidget)

from . import analyzer, intel, mailbox, outlook, parser, report
from .outlook_picker import OutlookPicker
from .settings_dialog import SettingsDialog, record_status
from .tasks import Task

ASSETS = Path(__file__).resolve().parent.parent / "assets"

YELLOW = "#FFD400"
BG, PANEL, EDGE, TEXT, MUTED = "#0b0b0b", "#151515", "#2b2b2b", "#ececec", "#8a8a8a"
RED, ORANGE, GREEN = "#ff3b30", "#ff8c00", "#35e06b"
SEV_COLOR = {"high": RED, "medium": ORANGE, "low": YELLOW, "info": MUTED}
VERDICT_COLOR = {"High": RED, "Medium": ORANGE, "Low": GREEN}
MONO = "Consolas"

STYLE = f"""
* {{ font-family: 'Segoe UI'; color: {TEXT}; }}
QMainWindow, QWidget#root {{ background: {BG}; }}
QLabel#title {{ color: {YELLOW}; font: 700 22px '{MONO}'; letter-spacing: 3px; }}
QLabel#sub {{ color: {MUTED}; font: 11px '{MONO}'; }}
QLabel#meta {{ background: {PANEL}; border: 1px solid {EDGE}; border-left: 3px solid {YELLOW}; padding: 10px; font: 12px '{MONO}'; }}
QFrame#panel {{ background: {PANEL}; border: 1px solid {EDGE}; border-radius: 6px; }}
QLabel#ledlabel {{ color: {MUTED}; font: 700 10px '{MONO}'; letter-spacing: 1px; }}
QLabel#score {{ font: 700 30px '{MONO}'; }}
QLabel#verdict {{ font: 700 13px '{MONO}'; letter-spacing: 2px; }}
QPushButton {{ background: {PANEL}; color: {YELLOW}; border: 1px solid {YELLOW}; border-radius: 4px; padding: 8px 14px;
              font: 700 11px '{MONO}'; letter-spacing: 1px; }}
QPushButton:hover {{ background: {YELLOW}; color: #000; }}
QPushButton:pressed {{ background: #c9a600; color: #000; }}
QPushButton:disabled {{ color: #555; border-color: #333; background: {PANEL}; }}
QCheckBox {{ color: {MUTED}; font: 11px '{MONO}'; spacing: 8px; }}
QCheckBox::indicator {{ width: 14px; height: 14px; border: 1px solid {YELLOW}; background: {BG}; border-radius: 2px; }}
QCheckBox::indicator:checked {{ background: {YELLOW}; }}
QTabWidget::pane {{ border: 1px solid {EDGE}; background: {PANEL}; top: -1px; }}
QTabBar::tab {{ background: {BG}; color: {MUTED}; padding: 8px 16px; border: 1px solid {EDGE}; border-bottom: none;
               font: 700 11px '{MONO}'; }}
QTabBar::tab:selected {{ color: #000; background: {YELLOW}; border-color: {YELLOW}; }}
QTabBar::tab:hover:!selected {{ color: {YELLOW}; }}
QTableWidget {{ background: {PANEL}; alternate-background-color: #101010; gridline-color: {EDGE}; border: none;
               selection-background-color: #3a3200; selection-color: {YELLOW}; font: 12px '{MONO}'; }}
QHeaderView::section {{ background: #1d1d1d; color: {YELLOW}; border: none; border-bottom: 1px solid {YELLOW};
                       padding: 6px; font: 700 11px '{MONO}'; }}
QProgressBar {{ background: {BG}; border: 1px solid {EDGE}; border-radius: 3px; height: 6px; text-align: center; }}
QProgressBar::chunk {{ background: {YELLOW}; border-radius: 2px; }}
QStatusBar {{ background: {PANEL}; color: {MUTED}; font: 11px '{MONO}'; border-top: 1px solid {EDGE}; }}
QScrollBar:vertical {{ background: {BG}; width: 10px; }}
QScrollBar::handle:vertical {{ background: #3a3a3a; border-radius: 4px; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background: {YELLOW}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar:horizontal {{ background: {BG}; height: 10px; }}
QScrollBar::handle:horizontal {{ background: #3a3a3a; border-radius: 4px; }}
QListWidget {{ background: {PANEL}; border: 1px solid {EDGE}; outline: 0; }}
QTreeWidget {{ background: {PANEL}; border: 1px solid {EDGE}; font: 12px '{MONO}'; outline: 0; }}
QTreeWidget::item {{ padding: 4px; }}
QTreeWidget::item:selected {{ background: #3a3200; color: {YELLOW}; }}
QPlainTextEdit, QTextEdit {{ background: #0e0e0e; border: 1px solid {EDGE}; font: 12px '{MONO}'; }}
QSplitter::handle {{ background: {EDGE}; }}
QDialog {{ background: {BG}; }}
QMessageBox {{ background: {PANEL}; }}
QLineEdit {{ background: #0e0e0e; border: 1px solid {EDGE}; border-radius: 4px; padding: 7px; font: 12px '{MONO}';
            selection-background-color: {YELLOW}; selection-color: #000; }}
QLineEdit:focus {{ border-color: {YELLOW}; }}
QToolButton {{ background: transparent; border: 1px solid {EDGE}; border-radius: 4px; }}
QToolButton:hover {{ border-color: {YELLOW}; background: #2a2400; }}
QScrollArea {{ border: none; background: {PANEL}; }}
QToolTip {{ background: {BG}; color: {YELLOW}; border: 1px solid {YELLOW}; padding: 3px; }}
"""


class Led(QWidget):
    """Round LED with glow. States: off, green, yellow, orange, red, scan (blinking yellow)."""
    COLORS = {"green": GREEN, "yellow": YELLOW, "orange": ORANGE, "red": RED, "scan": YELLOW}

    def __init__(self, size=22):
        super().__init__()
        self.setFixedSize(size + 12, size + 12)
        self.state, self.phase = "off", True

    def set_state(self, state):
        self.state = state
        self.update()

    def blink(self, on):
        self.phase = on
        if self.state in ("scan", "red"):
            self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        c = QPointF(self.width() / 2, self.height() / 2)
        r = min(self.width(), self.height()) / 2 - 6
        lit = self.state != "off" and not (self.state == "scan" and not self.phase)
        pulse = self.state == "red" and not self.phase
        p.setPen(QPen(QColor("#050505"), 3))
        p.setBrush(QColor("#1a1a1a"))
        p.drawEllipse(c, r + 2, r + 2)
        if lit:
            col = QColor(self.COLORS[self.state])
            glow = QRadialGradient(c, r + 7)
            glow.setColorAt(0.55, QColor(col.red(), col.green(), col.blue(), 120 if not pulse else 50))
            glow.setColorAt(1.0, QColor(col.red(), col.green(), col.blue(), 0))
            p.setPen(Qt.NoPen)
            p.setBrush(QBrush(glow))
            p.drawEllipse(c, r + 7, r + 7)
            body = QRadialGradient(QPointF(c.x() - r / 3, c.y() - r / 3), r * 1.5)
            body.setColorAt(0, col.lighter(160))
            body.setColorAt(0.5, col)
            body.setColorAt(1, col.darker(170))
            p.setBrush(QBrush(body))
        else:
            p.setBrush(QColor("#262626"))
        p.setPen(Qt.NoPen)
        p.drawEllipse(c, r, r)
        p.setBrush(QColor(255, 255, 255, 70 if lit else 18))
        p.drawEllipse(QPointF(c.x() - r / 3, c.y() - r / 3), r / 3.2, r / 4)


class LedMeter(QWidget):
    """Segmented LED bar that animates up to the risk score."""
    N = 25

    def __init__(self):
        super().__init__()
        self.setMinimumHeight(30)
        self.target = self.shown = 0
        self._t = QTimer(self, interval=22, timeout=self._step)

    def set_value(self, v):
        self.target = v
        self._t.start()

    def _step(self):
        if self.shown < self.target:
            self.shown += 1
        elif self.shown > self.target:
            self.shown -= 1
        else:
            self._t.stop()
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        gap = 4
        w = (self.width() - gap * (self.N - 1)) / self.N
        for i in range(self.N):
            frac = i / (self.N - 1)
            col = QColor(GREEN if frac < 0.4 else YELLOW if frac < 0.64 else ORANGE if frac < 0.8 else RED)
            on = (i + 1) * (100 / self.N) <= self.shown + 0.01
            rect = QRectF(i * (w + gap), 4, w, self.height() - 8)
            if on:
                halo = QColor(col)
                halo.setAlpha(60)
                p.setPen(Qt.NoPen)
                p.setBrush(halo)
                p.drawRoundedRect(rect.adjusted(-2, -2, 2, 2), 3, 3)
                p.setBrush(col)
            else:
                p.setPen(QPen(QColor("#2e2e2e"), 1))
                p.setBrush(QColor("#171717"))
            p.drawRoundedRect(rect, 2, 2)


def _open_url(url):
    QDesktopServices.openUrl(QUrl(url))


class Worker(QThread):
    """Static scan: parse + offline checks. Fast, and never touches the network."""
    done = Signal(object)
    failed = Signal(str)
    status = Signal(str)

    def __init__(self, path):
        super().__init__()
        self.path = path

    def run(self):
        try:
            self.status.emit("Parsing email")
            pe = parser.parse_file(self.path)
            self.done.emit(analyzer.analyze(pe, self.status.emit))
        except Exception as exc:
            self.failed.emit(str(exc))


class IntelWorker(QThread):
    """Online lookups, one target at a time, so results appear in the Threat Intel tab as they arrive."""
    row = Signal(int, object)
    status = Signal(str)
    completed = Signal(object)

    def __init__(self, targets):
        super().__init__()
        self.targets, self.cancelled = targets, False

    def cancel(self):
        self.cancelled = True

    def run(self):
        findings = []
        for i, t in enumerate(self.targets):
            if self.cancelled:
                return
            self.status.emit(f"looking up {t['label'][:40]}  ({i + 1}/{len(self.targets)})")
            try:
                res = intel.lookup(t, lambda: self.cancelled, self.status.emit)
            except Exception as exc:
                err = {"status": "error", "msg": str(exc)}
                res = {"vt": err, "abuse": err}
            if self.cancelled:
                return
            self.row.emit(i, res)
            findings += intel.to_findings(t, res)
        self.completed.emit(findings)


def _table(headers):
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setEditTriggers(QTableWidget.NoEditTriggers)
    t.setSelectionBehavior(QTableWidget.SelectRows)
    t.setAlternatingRowColors(True)
    t.verticalHeader().setVisible(False)
    t.setShowGrid(False)
    t.setWordWrap(True)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
    return t


def _fill(t, rows):
    t.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, v in enumerate(row):
            t.setItem(r, c, QTableWidgetItem(str(v)))
    t.resizeRowsToContents()


def _panel():
    f = QFrame()
    f.setObjectName("panel")
    return f


def _copy_icon(color, check=False):
    pm = QPixmap(32, 32)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(QPen(QColor(color), 2.6, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    p.setBrush(Qt.NoBrush)
    if check:
        p.drawPolyline([QPointF(8, 17), QPointF(14, 23), QPointF(25, 9)])
    else:
        p.drawRoundedRect(QRectF(11, 11, 15, 16), 3, 3)  # front sheet
        p.drawPolyline([QPointF(20, 7), QPointF(8, 7), QPointF(6, 9), QPointF(6, 21), QPointF(9, 21)])  # back sheet
    p.end()
    return QIcon(pm)


class CopyButton(QToolButton):
    """Small copy icon; copies `text_fn()` to the clipboard and flashes a check mark."""

    def __init__(self, text_fn, on_copied=lambda t: None):
        super().__init__()
        self.text_fn, self.on_copied = text_fn, on_copied
        self.setFixedSize(30, 28)
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip("Copy to clipboard")
        self._idle, self._done = _copy_icon(YELLOW), _copy_icon(GREEN, check=True)
        self.setIcon(self._idle)
        self.clicked.connect(self._copy)

    def _copy(self):
        text = self.text_fn()
        QGuiApplication.clipboard().setText(text)
        self.setIcon(self._done)
        QTimer.singleShot(1200, lambda: self.setIcon(self._idle))
        self.on_copied(text)


class AttachmentsView(QScrollArea):
    """One card per attachment: name + size, then MD5 / SHA-1 / SHA-256 rows, each with a copy button."""

    def __init__(self, on_copied):
        super().__init__()
        self.on_copied = on_copied
        self.setWidgetResizable(True)
        self.host = QWidget()
        self.lay = QVBoxLayout(self.host)
        self.lay.setContentsMargins(12, 12, 12, 12)
        self.lay.setSpacing(10)
        self.setWidget(self.host)
        self.populate([])

    def populate(self, attachments):
        while self.lay.count():
            item = self.lay.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)  # detach now; deleteLater alone leaves it visible until the next event loop turn
                w.deleteLater()
        if not attachments:
            empty = QLabel("No attachments in this email.")
            empty.setObjectName("sub")
            self.lay.addWidget(empty)
        for a in attachments:
            card = _panel()
            cl = QVBoxLayout(card)
            cl.setContentsMargins(14, 10, 14, 12)
            cl.setSpacing(6)
            name = QLabel(f"<span style='color:{YELLOW};font-weight:bold'>{a.filename.replace('<', '&lt;')}</span>"
                          f"  <span style='color:{MUTED}'>{a.size:,} bytes</span>")
            name.setTextInteractionFlags(Qt.TextSelectableByMouse)
            cl.addWidget(name)
            for label, value in (("MD5", a.md5), ("SHA-1", a.sha1), ("SHA-256", a.sha256)):
                row = QHBoxLayout()
                lab = QLabel(label)
                lab.setObjectName("ledlabel")
                lab.setFixedWidth(62)
                val = QLabel(value or "-")
                val.setTextInteractionFlags(Qt.TextSelectableByMouse)
                val.setStyleSheet(f"font: 12px '{MONO}'")
                row.addWidget(lab)
                row.addWidget(val, 1)
                row.addWidget(CopyButton(lambda v=value: v, self.on_copied))
                cl.addLayout(row)
            self.lay.addWidget(card)
        self.lay.addStretch()


LEVEL_COLOR = {"high": RED, "medium": ORANGE, "clean": GREEN, "unknown": YELLOW, "off": MUTED, "error": "#d99a3d"}


class Main(QMainWindow):
    LEDS = [("HEADERS", "Headers"), ("LINKS", "Links"), ("BODY", "Body"), ("FILES", "Attachment"), ("INTEL", "Intel")]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("PhishCheck")
        self.setWindowIcon(QIcon(str(ASSETS / "icon.png")))
        self.resize(1360, 820)
        self.setAcceptDrops(True)
        self.report = self.worker = self.intel_worker = self.task = None
        self.pending = None
        self.targets, self.intel_results, self.intel_token = [], {}, 0
        self.retired = []  # finished-or-cancelled threads kept alive until they stop
        self.leds = {}
        self.folder = mailbox.mail_folder()

        # ---- header
        logo = QLabel()
        logo.setPixmap(QPixmap(str(ASSETS / "icon.png")).scaled(54, 54, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        t = QLabel("PHISHCHECK")
        t.setObjectName("title")
        s = QLabel("static email threat analyzer  //  attachments are never executed")
        s.setObjectName("sub")
        tl = QVBoxLayout()
        tl.setSpacing(0)
        tl.addWidget(t)
        tl.addWidget(s)
        self.power = Led(14)
        self.power.set_state("green")
        self.ol_led = Led(14)
        self.ol_led.setToolTip("Checking Outlook...")
        head = QHBoxLayout()
        head.addWidget(logo)
        head.addLayout(tl)
        head.addStretch()
        for text, led in (("OUTLOOK", self.ol_led), ("SYSTEM", self.power)):
            lab = QLabel(text)
            lab.setObjectName("ledlabel")
            head.addWidget(lab)
            head.addWidget(led)
            head.addSpacing(10)

        # ---- actions
        b_ol = QPushButton("OUTLOOK MAILBOX")
        b_ol.clicked.connect(self.open_picker)
        b_file = QPushButton("OPEN .EML / .MSG")
        b_file.clicked.connect(self.open_file)
        self.b_save = QPushButton("EXPORT REPORT")
        self.b_save.clicked.connect(self.save)
        self.b_save.setEnabled(False)
        self.b_intel = QPushButton("RUN THREAT INTEL")
        self.b_intel.clicked.connect(lambda: self._start_intel(manual=True))
        self.b_intel.setEnabled(False)
        b_set = QPushButton("SETTINGS / API KEYS")
        b_set.clicked.connect(self.open_settings)
        self.online = QCheckBox("auto-run lookups")
        self.online.setChecked(True)
        actions = QHBoxLayout()
        for w in (b_ol, b_file, self.b_save, self.b_intel, b_set):
            actions.addWidget(w)
        actions.addStretch()
        actions.addWidget(self.online)

        # ---- dashboard: LEDs + score meter
        dash = _panel()
        dl = QHBoxLayout(dash)
        dl.setContentsMargins(16, 12, 16, 12)
        for label, key in self.LEDS:
            col = QVBoxLayout()
            col.setSpacing(0)
            led = Led()
            self.leds[key] = led
            lab = QLabel(label)
            lab.setObjectName("ledlabel")
            lab.setAlignment(Qt.AlignCenter)
            col.addWidget(led, 0, Qt.AlignCenter)
            col.addWidget(lab)
            dl.addLayout(col)
            dl.addSpacing(8)
        dl.addSpacing(14)
        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet(f"color:{EDGE}")
        dl.addWidget(sep)
        dl.addSpacing(14)
        self.score = QLabel("--")
        self.score.setObjectName("score")
        self.score.setMinimumWidth(90)
        self.verdict = QLabel("AWAITING INPUT")
        self.verdict.setObjectName("verdict")
        self.verdict.setStyleSheet(f"color:{MUTED}")
        sc = QVBoxLayout()
        sc.setSpacing(0)
        sc.addWidget(self.score)
        sc.addWidget(self.verdict)
        dl.addLayout(sc)
        self.meter = LedMeter()
        dl.addWidget(self.meter, 1)

        self.busy = QProgressBar()
        self.busy.setTextVisible(False)
        self.busy.setFixedHeight(6)
        self.busy.setRange(0, 100)

        self.meta = QLabel("Click OUTLOOK MAILBOX to pick an email, or drop an .eml / .msg anywhere in this window.")
        self.meta.setObjectName("meta")
        self.meta.setTextFormat(Qt.RichText)
        self.meta.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.meta.setWordWrap(True)

        # ---- tabs
        self.t_find = _table(["SEV", "AREA", "DETAIL", "PTS"])
        self.t_intel = _table(["TYPE", "TARGET", "VIRUSTOTAL", "ABUSE.CH"])
        ih = self.t_intel.horizontalHeader()
        for col, mode, width in ((0, QHeaderView.Fixed, 80), (1, QHeaderView.Interactive, 280), (3, QHeaderView.Fixed, 170)):
            ih.setSectionResizeMode(col, mode)
            self.t_intel.setColumnWidth(col, width)
        self.t_intel.currentCellChanged.connect(lambda r, *_: self._show_detail(r))
        self.intel_note = QLabel("")
        self.intel_note.setObjectName("sub")
        self.intel_note.setWordWrap(True)
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        intel_tab = QWidget()
        il = QVBoxLayout(intel_tab)
        il.setContentsMargins(10, 8, 10, 8)
        il.addWidget(self.intel_note)
        il.addWidget(self.t_intel, 1)
        il.addWidget(self.detail, 4)

        self.att_view = AttachmentsView(lambda t: self._copied(t))
        self.t_link = _table(["TEXT", "URL", ""])
        for tb, first_w in ((self.t_link, 260),):
            th = tb.horizontalHeader()
            th.setSectionResizeMode(0, QHeaderView.Interactive)
            tb.setColumnWidth(0, first_w)
            th.setSectionResizeMode(2, QHeaderView.Fixed)
            tb.setColumnWidth(2, 48)
            tb.cellDoubleClicked.connect(lambda r, c, tb=tb: self.copy_cell(tb, r, c))

        hdr_tab = QWidget()
        hl = QVBoxLayout(hdr_tab)
        hl.setContentsMargins(10, 8, 10, 8)
        top = QHBoxLayout()
        hint = QLabel("full raw headers - one click copies the whole block")
        hint.setObjectName("sub")
        self.hdr_text = QPlainTextEdit()
        self.hdr_text.setReadOnly(True)
        self.hdr_text.setLineWrapMode(QPlainTextEdit.NoWrap)
        top.addWidget(CopyButton(lambda: self.hdr_text.toPlainText(), self._copied))
        top.addWidget(hint)
        top.addStretch()
        hl.addLayout(top)
        hl.addWidget(self.hdr_text, 1)
        tabs = QTabWidget()
        for w, n in ((self.t_find, "FINDINGS"), (intel_tab, "THREAT INTEL"), (self.att_view, "ATTACHMENTS + HASHES"),
                     (self.t_link, "LINKS"), (hdr_tab, "RAW HEADERS")):
            tabs.addTab(w, n)
        self.tabs = tabs

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(10)
        rl.addLayout(actions)
        rl.addWidget(dash)
        rl.addWidget(self.busy)
        rl.addWidget(self.meta)
        rl.addWidget(tabs, 1)

        lay = QVBoxLayout()
        lay.setContentsMargins(18, 14, 18, 10)
        lay.setSpacing(10)
        lay.addLayout(head)
        lay.addWidget(right, 1)
        root = QWidget()
        root.setObjectName("root")
        root.setLayout(lay)
        self.setCentralWidget(root)
        self.statusBar().showMessage("READY  //  double-click any hash, link or header cell to copy it")

        self._phase, self._sweep, self._busy = True, 0, False
        QTimer(self, interval=420, timeout=self._blink).start()
        QTimer(self, interval=30, timeout=self._animate_busy).start()
        self._update_intel_note()
        QTimer.singleShot(600, self.check_outlook)

    # --- animation -----------------------------------------------------
    def _blink(self):
        self._phase = not self._phase
        for led in self.leds.values():
            led.blink(self._phase)
        self.power.set_state("yellow" if self._busy and self._phase else "green")

    def _animate_busy(self):
        if not self._busy:
            return
        self._sweep = (self._sweep + 3) % 200
        self.busy.setValue(self._sweep if self._sweep <= 100 else 200 - self._sweep)

    def _on_status(self, msg):
        self.statusBar().showMessage(f"SCANNING  //  {msg}")
        m = msg.lower()
        key = ("Headers" if "header" in m else "Links" if "links" in m else "Body" if "body" in m
               else "Attachment" if "static" in m else "Intel" if ("looking up" in m or "waiting" in m) else None)
        if key:
            for led in self.leds.values():
                if led.state == "scan" and led is not self.leds[key]:
                    led.set_state("yellow")
            self.leds[key].set_state("scan")

    # --- Outlook status --------------------------------------------------
    def check_outlook(self):
        self.task = Task(outlook.test_connection)
        self.task.result.connect(self._outlook_status)
        self.task.start()

    def _outlook_status(self, ok, msg):
        self.ol_led.set_state("green" if ok else "off")
        self.ol_led.setToolTip(msg)
        record_status("OUTLOOK", ok, msg)

    # --- opening emails ------------------------------------------------------
    def open_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Open email (a copy is kept in the Email Check folder)",
                                           str(self.folder), "Emails (*.eml *.msg)")
        if p:
            self.scan(str(mailbox.add_to_folder(p, self.folder)))

    def open_picker(self):
        dlg = OutlookPicker(self.folder, self)
        if dlg.exec() and dlg.saved_path:
            self.scan(dlg.saved_path)
        self.check_outlook()

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        for u in e.mimeData().urls():
            f = u.toLocalFile()
            if Path(f).suffix.lower() in mailbox.EXTS:
                self.scan(str(mailbox.add_to_folder(f, self.folder)))
                break

    def _copied(self, text):
        self.statusBar().showMessage(f"COPIED  //  {text[:80]}")

    def _fill_copy_table(self, table, rows, value_col):
        """Fill a table whose last column is a copy icon that copies row[value_col]."""
        _fill(table, rows)
        last = table.columnCount() - 1
        for r, row in enumerate(rows):
            table.setCellWidget(r, last, CopyButton(lambda v=str(row[value_col]): v, self._copied))
        table.resizeRowsToContents()

    def copy_cell(self, table, r, c):
        it = table.item(r, c)
        if it:
            QGuiApplication.clipboard().setText(it.text())
            self.statusBar().showMessage(f"COPIED  //  {it.text()[:80]}")

    def open_settings(self):
        if SettingsDialog(self).exec():
            self.statusBar().showMessage("SETTINGS SAVED  //  new keys apply to the next lookup")
            self.folder = mailbox.mail_folder()
            self._update_intel_note()
        self.check_outlook()

    # --- static scan ---------------------------------------------------------
    def scan(self, path):
        self._cancel_intel()
        if self.worker and self.worker.isRunning():
            self.pending = path  # run it as soon as the current (fast) static scan finishes
            return
        self._busy = True
        for led in self.leds.values():
            led.set_state("off")
        self.verdict.setText("SCANNING...")
        self.verdict.setStyleSheet(f"color:{YELLOW}")
        self.score.setText("--")
        self.score.setStyleSheet(f"color:{YELLOW}")
        self.meter.set_value(0)
        self.b_save.setEnabled(False)
        self.b_intel.setEnabled(False)
        self.worker = Worker(path)
        self.worker.status.connect(self._on_status)
        self.worker.failed.connect(self._failed)
        self.worker.done.connect(self.show_report)
        self.worker.finished.connect(self._after_worker)
        self.worker.start()

    def _after_worker(self):
        if self.pending:
            path, self.pending = self.pending, None
            self.scan(path)

    def _finish_busy(self):
        self._busy = False
        self.busy.setValue(0)

    def _failed(self, msg):
        self._finish_busy()
        for led in self.leds.values():
            led.set_state("off")
        self.verdict.setText("SCAN FAILED")
        self.verdict.setStyleSheet(f"color:{RED}")
        self.statusBar().showMessage("FAILED")
        QMessageBox.critical(self, "Error", msg)

    def show_report(self, r):
        if self.pending:
            return  # a newer email was picked meanwhile; its scan starts next
        self._finish_busy()
        self.report = r
        e = r.email
        self.b_save.setEnabled(True)
        self.b_intel.setEnabled(True)
        esc = lambda x: (x or "-").replace("<", "&lt;")
        self.meta.setText(f"<span style='color:{YELLOW}'>SUBJECT</span>&nbsp; {esc(e.subject)}<br>"
                          f"<span style='color:{YELLOW}'>FROM</span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; {esc(e.sender)}<br>"
                          f"<span style='color:{YELLOW}'>REPLY-TO</span> {esc(e.reply_to)}")
        self._render_summary(r)
        self.att_view.populate(e.attachments)
        self._fill_copy_table(self.t_link, [(l.text[:60], l.href) for l in e.links], value_col=1)
        self.hdr_text.setPlainText("\n".join(f"{k}: {v}" for k, v in e.headers))
        self.statusBar().showMessage(f"DONE  //  {len(r.findings)} findings, {len(e.attachments)} attachment(s), "
                                     f"{len(e.links)} link(s)")
        self._start_intel()

    def _render_summary(self, r):
        col = VERDICT_COLOR[r.verdict]
        self.score.setText(f"{r.score}")
        self.score.setStyleSheet(f"color:{col}")
        self.verdict.setText(f"{r.verdict.upper()} RISK")
        self.verdict.setStyleSheet(f"color:{col}")
        self.meter.set_value(r.score)

        order = {"info": 0, "low": 1, "medium": 2, "high": 3}
        led_for = {"info": "green", "low": "yellow", "medium": "orange", "high": "red"}
        worst = {}
        for f in r.findings:
            if order[f.severity] >= order.get(worst.get(f.category, "info"), 0):
                worst[f.category] = f.severity
        for key, led in self.leds.items():
            if key != "Intel":
                led.set_state(led_for[worst.get(key, "info")])

        _fill(self.t_find, [(f.severity.upper(), f.category, f.message, f"+{f.points}") for f in r.findings])
        for i, f in enumerate(r.findings):
            self.t_find.item(i, 0).setForeground(QColor(SEV_COLOR[f.severity]))
            self.t_find.item(i, 0).setFont(QFont(MONO, 9, QFont.Bold))
        hh = self.t_find.horizontalHeader()
        for c, width in ((0, 80), (1, 110), (3, 60)):
            hh.setSectionResizeMode(c, QHeaderView.Fixed)
            self.t_find.setColumnWidth(c, width)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        self.t_find.resizeRowsToContents()

    # --- threat intel -----------------------------------------------------------
    def _update_intel_note(self):
        text = "VIRUSTOTAL: ACTIVE" if intel.have_vt() else "VIRUSTOTAL: NO KEY (add one under SETTINGS / API KEYS)"
        if intel.have_abuse():
            text += "    |    ABUSE.CH: ACTIVE"
        self.intel_note.setText(text + "    |    select a row for the details. Free VirusTotal keys allow 4 lookups per minute.")

    def _cancel_intel(self):
        self.intel_token += 1
        if self.intel_worker:
            self.intel_worker.cancel()
            self.retired.append(self.intel_worker)
            self.intel_worker = None
        self.retired = [w for w in self.retired if w.isRunning()]

    def _set_intel_cell(self, row, col, text, level):
        it = QTableWidgetItem(text)
        it.setForeground(QColor(LEVEL_COLOR[level]))
        it.setFont(QFont(MONO, 9, QFont.Bold if level in ("high", "medium") else QFont.Normal))
        self.t_intel.setItem(row, col, it)

    def _show_detail(self, row):
        if row in self.intel_results:
            self.detail.setHtml(intel.detail_html(self.targets[row], self.intel_results[row]))
        elif 0 <= row < len(self.targets):
            self.detail.setHtml(f"<span style='color:{MUTED}'>Waiting for this lookup to finish...</span>")

    def _fill_intel_table(self, running):
        self.t_intel.clearContents()
        self.t_intel.setRowCount(len(self.targets))
        self.t_intel.setColumnHidden(3, not intel.have_abuse())  # optional provider: only shown once a key is saved
        wait = "queued..." if running else "not looked up yet"
        for i, t in enumerate(self.targets):
            self.t_intel.setItem(i, 0, QTableWidgetItem("FILE" if t["kind"] == "file" else "DOMAIN"))
            label = t["label"] if t["kind"] == "file" else f"{t['label']}   ({t['url'][:60]})"
            self.t_intel.setItem(i, 1, QTableWidgetItem(label))
            if intel.have_vt():
                self._set_intel_cell(i, 2, wait, "unknown")
            else:
                self._set_intel_cell(i, 2, *intel.describe_vt({"status": "no_key"}))
            self._set_intel_cell(i, 3, wait if intel.have_abuse() else "not configured", "unknown" if intel.have_abuse() else "off")
        self.t_intel.resizeRowsToContents()
        if not self.targets:
            self.detail.setHtml(f"<span style='color:{MUTED}'>Nothing to look up: this email has no attachments or links.</span>")
        elif not intel.have_vt() and not intel.have_abuse():
            self.detail.setHtml(f"<span style='color:{YELLOW}'>No API key saved.</span> <span style='color:{MUTED}'>"
                                "Open SETTINGS / API KEYS, paste your VirusTotal key, and press RUN THREAT INTEL.</span>")
        else:
            self.t_intel.selectRow(0)

    def _start_intel(self, manual=False):
        r = self.report
        if not r:
            return
        self._cancel_intel()
        self.targets = intel.build_targets(r.email)
        self.intel_results = {}
        r.intel = []
        self._update_intel_note()
        keys = intel.have_vt() or intel.have_abuse()
        run = bool(self.targets) and keys and (manual or self.online.isChecked())
        self._fill_intel_table(running=run)
        self.leds["Intel"].set_state("off")
        analyzer.rescore(r, [])
        self._render_summary(r)
        if not self.targets:
            self.statusBar().showMessage("DONE  //  nothing to look up (no attachments or links)")
            return
        if not run:
            why = "no API keys saved (SETTINGS / API KEYS)" if not keys else "auto-run is off, press RUN THREAT INTEL"
            self.statusBar().showMessage(f"DONE  //  online lookups skipped: {why}")
            return
        self.leds["Intel"].set_state("scan")
        token = self.intel_token
        w = IntelWorker(self.targets)
        w.status.connect(lambda m, tk=token: tk == self.intel_token and self._on_status(m))
        w.row.connect(lambda i, res, tk=token: tk == self.intel_token and self._on_intel_row(i, res))
        w.completed.connect(lambda f, tk=token: tk == self.intel_token and self._on_intel_done(f))
        self.intel_worker = w
        self._busy = True
        w.start()

    def _on_intel_row(self, i, res):
        self.intel_results[i] = res
        vt_text, vt_level = intel.describe_vt(res["vt"])
        ab_text, ab_level = intel.describe_abuse(res["abuse"])
        self._set_intel_cell(i, 2, vt_text, vt_level)
        self._set_intel_cell(i, 3, ab_text, ab_level)
        self.t_intel.resizeRowsToContents()
        self.report.intel = [(self.targets[k], v) for k, v in sorted(self.intel_results.items())]
        if self.t_intel.currentRow() == i:
            self._show_detail(i)

    def _on_intel_done(self, findings):
        self._finish_busy()
        r = self.report
        analyzer.rescore(r, findings)
        self._render_summary(r)
        levels, worst_row = [], None
        for i, res in sorted(self.intel_results.items()):
            lv = [intel.describe_vt(res["vt"])[1], intel.describe_abuse(res["abuse"])[1]]
            levels += lv
            if worst_row is None and ("high" in lv or "medium" in lv):
                worst_row = i
        led = ("red" if "high" in levels else "orange" if "medium" in levels else "yellow" if "error" in levels
               else "green" if "clean" in levels else "off")
        self.leds["Intel"].set_state(led)
        bad = sum(1 for lv in levels if lv in ("high", "medium"))
        self.statusBar().showMessage(f"INTEL DONE  //  {len(self.targets)} target(s) checked, {bad} flagged  //  score now {r.score}")
        if worst_row is not None:
            self.t_intel.selectRow(worst_row)
            self.tabs.setCurrentIndex(1)

    # --- export ----------------------------------------------------------------------
    def save(self):
        reports = self.folder / "Reports"
        reports.mkdir(exist_ok=True)
        name = f"report_{mailbox.safe_name(self.report.email.subject, 40)}.html"
        p, _ = QFileDialog.getSaveFileName(self, "Save report", str(reports / name), "HTML (*.html)")
        if p:
            with open(p, "w", encoding="utf-8") as f:
                f.write(report.to_html(self.report))
            self.statusBar().showMessage(f"SAVED  //  {p}")

    def closeEvent(self, e):
        self._cancel_intel()
        for w in self.retired:
            w.wait(3000)
        super().closeEvent(e)


def main():
    if sys.platform == "win32":  # own taskbar identity so the icon shows instead of python's
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("phishcheck.app.1")
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    app.setWindowIcon(QIcon(str(ASSETS / "icon.png")))
    w = Main()
    w.show()
    if sys.platform == "win32":  # launched hidden (no console flash): the first show is eaten by the hidden-start flag, so show again
        ctypes.windll.user32.ShowWindow(int(w.winId()), 1)
        w.raise_()
        w.activateWindow()
    sys.exit(app.exec())
