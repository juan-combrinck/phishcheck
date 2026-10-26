"""A small three-pane window that mimics Outlook: folders | message list | preview. Pick an email to scan it."""
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QApplication, QCheckBox, QDialog, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox,
                               QPlainTextEdit, QPushButton, QSplitter, QTableWidget, QTableWidgetItem, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from . import outlook

MAX_MESSAGES = 200
MAX_DEPTH = 5


class OutlookPicker(QDialog):
    def __init__(self, dest_dir, parent=None):
        super().__init__(parent)
        self.setWindowTitle("PhishCheck - Outlook mailbox")
        self.resize(1180, 680)
        self.dest, self.saved_path, self.app, self.ns = dest_dir, None, None, None

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["FOLDERS"])
        self.tree.currentItemChanged.connect(self._folder_changed)

        self.subs = QCheckBox("include sub-folders")
        self.subs.toggled.connect(lambda *_: self._folder_changed(self.tree.currentItem(), None))
        self.search = QLineEdit()
        self.search.setPlaceholderText("filter this folder by sender or subject...")
        self.search.textChanged.connect(self._filter)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["FROM", "SUBJECT", "RECEIVED", "ATT"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Interactive)
        hh.setSectionResizeMode(1, QHeaderView.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.Fixed)
        hh.setSectionResizeMode(3, QHeaderView.Fixed)
        self.table.setColumnWidth(0, 200)
        self.table.setColumnWidth(2, 130)
        self.table.setColumnWidth(3, 50)
        self.table.currentCellChanged.connect(lambda r, *_: self._preview(r))
        self.table.cellDoubleClicked.connect(lambda *_: self._scan_selected())

        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setPlaceholderText("Select an email to preview it (plain text only, nothing is opened or run).")

        mid = QWidget()
        ml = QVBoxLayout(mid)
        ml.setContentsMargins(0, 0, 0, 0)
        top = QHBoxLayout()
        top.addWidget(self.search, 1)
        top.addWidget(self.subs)
        ml.addLayout(top)
        split_v = QSplitter(Qt.Vertical)
        split_v.addWidget(self.table)
        split_v.addWidget(self.preview)
        split_v.setSizes([380, 220])
        ml.addWidget(split_v)

        split = QSplitter(Qt.Horizontal)
        split.addWidget(self.tree)
        split.addWidget(mid)
        split.setSizes([260, 900])

        self.status = QLabel("connecting to Outlook...")
        self.status.setObjectName("sub")
        b_scan = QPushButton("SCAN SELECTED EMAIL")
        b_scan.clicked.connect(self._scan_selected)
        b_cur = QPushButton("USE EMAIL OPEN IN OUTLOOK")
        b_cur.clicked.connect(self._scan_current)
        b_ref = QPushButton("REFRESH")
        b_ref.clicked.connect(lambda: self._folder_changed(self.tree.currentItem(), None))
        b_close = QPushButton("CLOSE")
        b_close.clicked.connect(self.reject)
        bar = QHBoxLayout()
        bar.addWidget(self.status, 1)
        for b in (b_ref, b_cur, b_scan, b_close):
            bar.addWidget(b)

        lay = QVBoxLayout(self)
        lay.addWidget(split, 1)
        lay.addLayout(bar)
        QTimer.singleShot(50, self._connect)

    # --- Outlook access (UI thread only) ------------------------------
    def _connect(self):
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            self.app = outlook.get_app()
            self.ns = self.app.GetNamespace("MAPI")
            self._load_folders()
            self.status.setText("connected  //  double-click an email to scan it")
        except Exception as exc:
            self.status.setText(f"could not connect: {exc}")
            QMessageBox.warning(self, "Outlook", f"Could not connect to classic Outlook.\n\n{exc}\n\n"
                                                 "Start Outlook first, then reopen this window.")
        finally:
            QApplication.restoreOverrideCursor()

    def _add_folder(self, parent, folder, depth):
        try:
            count = folder.Items.Count
            mail = depth == 0 or folder.DefaultItemType == 0  # hide Calendar / Contacts / Tasks / Notes
        except Exception:
            count, mail = 0, True
        if not mail:
            return None
        label = folder.Name if depth == 0 else f"{folder.Name}  ({count})"
        node = QTreeWidgetItem(parent, [label])
        node.setData(0, Qt.UserRole, (folder.EntryID, folder.StoreID))
        node.setData(0, Qt.UserRole + 1, folder.Name)
        if depth < MAX_DEPTH:
            try:
                for sub in folder.Folders:
                    self._add_folder(node, sub, depth + 1)
            except Exception:
                pass
        return node

    def _load_folders(self):
        self.tree.clear()
        for root in self.ns.Folders:
            try:
                self._add_folder(self.tree, root, 0)
            except Exception:
                continue
        self.tree.expandAll()  # show every sub-folder, not just the top level
        try:  # jump to the default Inbox
            inbox = self.ns.GetDefaultFolder(6).EntryID
            top = self.tree.invisibleRootItem()
            stack = [top.child(i) for i in range(top.childCount())]
            while stack:
                n = stack.pop()
                if n.data(0, Qt.UserRole)[0] == inbox:
                    self.tree.setCurrentItem(n)
                    break
                stack.extend(n.child(i) for i in range(n.childCount()))
        except Exception:
            pass

    def _folder_changed(self, node, _prev):
        if not node or not self.ns:
            return
        entry, store = node.data(0, Qt.UserRole)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            folder = self.ns.GetFolderFromID(entry, store)
            folders = [folder]
            if self.subs.isChecked():
                i = 0
                while i < len(folders) and len(folders) < 200:
                    try:
                        folders.extend(f for f in folders[i].Folders if f.DefaultItemType == 0)
                    except Exception:
                        pass
                    i += 1
            rows = []
            for fo in folders:
                try:
                    items = fo.Items
                    items.Sort("[ReceivedTime]", True)
                    it, got = items.GetFirst(), 0
                    while it is not None and got < MAX_MESSAGES:
                        try:
                            if it.Class == 43:  # olMail
                                rows.append((it.SenderName or "", it.Subject or "(no subject)", it.ReceivedTime,
                                             "yes" if it.Attachments.Count else "", it.EntryID, fo.StoreID))
                                got += 1
                        except Exception:
                            pass
                        it = items.GetNext()
                except Exception:
                    continue
            rows.sort(key=lambda r: str(r[2]), reverse=True)
            rows = [(a, b, c.strftime("%d %b %Y %H:%M"), d, e, f) for a, b, c, d, e, f in rows[:MAX_MESSAGES]]
        except Exception as exc:
            self.status.setText(f"could not read folder: {exc}")
            return
        finally:
            QApplication.restoreOverrideCursor()
        self.table.setRowCount(len(rows))
        for r, (frm, subj, when, att, eid, sid) in enumerate(rows):
            for c, v in enumerate((frm, subj, when, att)):
                self.table.setItem(r, c, QTableWidgetItem(v))
            self.table.item(r, 0).setData(Qt.UserRole, (eid, sid))
        self.preview.clear()
        self.search.clear()
        more = f" (newest {MAX_MESSAGES} shown)" if len(rows) == MAX_MESSAGES else ""
        self.status.setText(f"{len(rows)} email(s) in {node.data(0, Qt.UserRole + 1)}{more}")

    def _filter(self, text):
        t = text.lower()
        for r in range(self.table.rowCount()):
            hay = (self.table.item(r, 0).text() + " " + self.table.item(r, 1).text()).lower()
            self.table.setRowHidden(r, t not in hay)

    def _selected_ids(self):
        r = self.table.currentRow()
        return self.table.item(r, 0).data(Qt.UserRole) if r >= 0 else None

    def _preview(self, row):
        ids = self._selected_ids() if row >= 0 else None
        if not ids:
            return
        try:
            item = self.ns.GetItemFromID(*ids)
            names = ", ".join(a.FileName for a in item.Attachments) or "none"
            body = (item.Body or "")[:4000]
            self.preview.setPlainText(f"FROM: {item.SenderName}\nSUBJECT: {item.Subject}\nATTACHMENTS: {names}\n"
                                      f"{'-' * 60}\n{body}")
        except Exception as exc:
            self.preview.setPlainText(f"could not preview: {exc}")

    # --- actions ---------------------------------------------------------
    def _scan_selected(self):
        ids = self._selected_ids()
        if not ids:
            QMessageBox.information(self, "Outlook", "Select an email first.")
            return
        try:
            self.saved_path = outlook.save_item(self.ns.GetItemFromID(*ids), self.dest)
            self.accept()
        except Exception as exc:
            QMessageBox.warning(self, "Outlook", f"Could not export the email: {exc}")

    def _scan_current(self):
        try:
            self.saved_path = outlook.export_selected(self.dest)[0]
            self.accept()
        except Exception as exc:
            QMessageBox.warning(self, "Outlook", str(exc))
