import os
from datetime import datetime

from PySide6.QtWidgets import QDialog, QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout

from . import intel, mailbox, outlook
from .tasks import Task

GREEN, RED, YELLOW = "#35e06b", "#ff3b30", "#FFD400"


def record_status(name: str, ok: bool, msg: str):
    """Persist the last test result so it is still there the next time Settings opens."""
    results = intel.load_config().get("STATUS", {})
    results[name] = {"ok": ok, "msg": msg, "time": datetime.now().strftime("%d %b %H:%M")}
    intel.save_config({"STATUS": results})


def saved_status(name: str):
    return intel.load_config().get("STATUS", {}).get(name)


def _show(label: QLabel, ok, msg, when=""):
    label.setText(f"{msg}  ({when})" if when else msg)
    label.setStyleSheet(f"color:{GREEN if ok else RED}")


class KeyRow(QFrame):
    """Label + masked input + show/test buttons + status line for one API key."""

    def __init__(self, env_name, title, blurb, link, tester):
        super().__init__()
        self.setObjectName("panel")
        self.env_name, self.tester, self.task, self.tested_key = env_name, tester, None, None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(6)

        head = QLabel(f"<b style='color:#FFD400'>{title}</b>  <span style='color:#8a8a8a'>{blurb}</span>")
        head.setWordWrap(True)
        lay.addWidget(head)
        get = QLabel(f"<a href='{link}' style='color:#FFD400'>Get a free key &rarr;</a>")
        get.setOpenExternalLinks(True)
        lay.addWidget(get)

        row = QHBoxLayout()
        self.saved_key = intel.load_config().get(env_name, "")
        self.edit = QLineEdit(self.saved_key)
        self.edit.setEchoMode(QLineEdit.Password)
        self.edit.setPlaceholderText("paste API key here")
        self.show_btn = QPushButton("SHOW")
        self.show_btn.setCheckable(True)
        self.show_btn.toggled.connect(self._toggle)
        self.test_btn = QPushButton("TEST")
        self.test_btn.clicked.connect(self._test)
        row.addWidget(self.edit, 1)
        row.addWidget(self.show_btn)
        row.addWidget(self.test_btn)
        lay.addLayout(row)

        self.status = QLabel("")
        self.status.setObjectName("sub")
        lay.addWidget(self.status)
        last = saved_status(env_name)
        if self.saved_key and last:
            _show(self.status, last["ok"], f"saved key: {last['msg']}", last["time"])
        elif self.saved_key:
            self.status.setText("key saved (not tested yet)")
        else:
            self.status.setText("no key saved")
        if os.environ.get(env_name):
            self.status.setText(self.status.text() + f"  |  note: environment variable {env_name} overrides this field")

    def value(self):
        return self.edit.text().strip()

    def _toggle(self, on):
        self.edit.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password)
        self.show_btn.setText("HIDE" if on else "SHOW")

    def _done(self, ok, msg):
        self.test_btn.setEnabled(True)
        _show(self.status, ok, msg, "just now")
        record_status(self.env_name, ok, msg)

    def _test(self):
        key = self.value()
        if not key:
            _show(self.status, False, "enter a key first")
            return
        self.test_btn.setEnabled(False)
        self.status.setStyleSheet(f"color:{YELLOW}")
        self.status.setText("testing...")
        self.tested_key = key
        self.task = Task(lambda: self.tester(key))
        self.task.result.connect(self._done)
        self.task.start()


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("PhishCheck - Settings")
        self.setMinimumWidth(660)
        self.task = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(12)

        title = QLabel("SETTINGS")
        title.setObjectName("title")
        lay.addWidget(title)
        note = QLabel("Keys are stored locally in config.json next to the app. Only file hashes, domains and URLs are "
                      "ever sent to these services, never attachments or email bodies.")
        note.setObjectName("sub")
        note.setWordWrap(True)
        lay.addWidget(note)

        self.vt = KeyRow("VT_API_KEY", "VIRUSTOTAL", "file hash + domain reputation (free tier: 4 lookups/min, 500/day)",
                         "https://www.virustotal.com/gui/join-us", intel.test_vt_key)
        self.abuse = KeyRow("ABUSECH_AUTH_KEY", "ABUSE.CH", "MalwareBazaar + URLhaus known-malware lists (one key covers both)",
                            "https://auth.abuse.ch/", intel.test_abusech_key)
        lay.addWidget(self.vt)
        lay.addWidget(self.abuse)

        # Email Check folder
        fo = QFrame()
        fo.setObjectName("panel")
        fl = QVBoxLayout(fo)
        fl.setContentsMargins(14, 12, 14, 12)
        fl.addWidget(QLabel("<b style='color:#FFD400'>EMAIL CHECK FOLDER</b>  <span style='color:#8a8a8a'>"
                            "every email the app scans lives here (Outlook exports too)</span>"))
        frow = QHBoxLayout()
        self.folder = QLineEdit(str(mailbox.mail_folder()))
        browse = QPushButton("BROWSE")
        browse.clicked.connect(self._browse)
        frow.addWidget(self.folder, 1)
        frow.addWidget(browse)
        fl.addLayout(frow)
        lay.addWidget(fo)

        # Outlook
        ol = QFrame()
        ol.setObjectName("panel")
        ol_l = QVBoxLayout(ol)
        ol_l.setContentsMargins(14, 12, 14, 12)
        ol_l.addWidget(QLabel("<b style='color:#FFD400'>OUTLOOK</b>  <span style='color:#8a8a8a'>no API key needed: "
                              "classic Outlook is read locally through COM, just keep it running</span>"))
        orow = QHBoxLayout()
        self.ol_btn = QPushButton("RE-TEST CONNECTION")
        self.ol_btn.clicked.connect(self._test_outlook)
        self.ol_status = QLabel("")
        self.ol_status.setObjectName("sub")
        orow.addWidget(self.ol_btn)
        orow.addWidget(self.ol_status, 1)
        ol_l.addLayout(orow)
        lay.addWidget(ol)
        last = saved_status("OUTLOOK")
        if last:
            _show(self.ol_status, last["ok"], f"last check: {last['msg']}", last["time"])
        self._test_outlook()  # always show the live state when the dialog opens

        btns = QHBoxLayout()
        btns.addStretch()
        cancel = QPushButton("CANCEL")
        cancel.clicked.connect(self.reject)
        save = QPushButton("SAVE")
        save.clicked.connect(self._save)
        btns.addWidget(cancel)
        btns.addWidget(save)
        lay.addLayout(btns)

    def _browse(self):
        p = QFileDialog.getExistingDirectory(self, "Choose the Email Check folder", self.folder.text())
        if p:
            self.folder.setText(p)

    def _test_outlook(self):
        self.ol_btn.setEnabled(False)
        self.ol_status.setStyleSheet(f"color:{YELLOW}")
        self.ol_status.setText("checking...")
        self.task = Task(outlook.test_connection)
        self.task.result.connect(self._outlook_done)
        self.task.start()

    def _outlook_done(self, ok, msg):
        self.ol_btn.setEnabled(True)
        _show(self.ol_status, ok, msg, "just now")
        record_status("OUTLOOK", ok, msg)

    def _save(self):
        values = {"VT_API_KEY": self.vt.value(), "ABUSECH_AUTH_KEY": self.abuse.value(),
                  "MAIL_FOLDER": self.folder.text().strip()}
        status = intel.load_config().get("STATUS", {})
        for row in (self.vt, self.abuse):  # a changed key invalidates its old test result
            if row.value() != row.saved_key and row.value() != row.tested_key:
                status.pop(row.env_name, None)
        values["STATUS"] = status
        intel.save_config(values)
        self.accept()
