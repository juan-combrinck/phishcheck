"""Classic Outlook (COM) integration. Does not work with the new Outlook.

COM objects must stay on the thread that created them: the picker dialog uses them on the UI thread, while
test_connection() runs in a worker thread and initialises COM itself.
"""
from pathlib import Path

from .mailbox import safe_name, stamp


def get_app(launch: bool = True):
    import win32com.client

    try:
        return win32com.client.GetActiveObject("Outlook.Application")  # attach to the running Outlook
    except Exception:
        if not launch:
            raise RuntimeError("Outlook is not running. Start classic Outlook first.")
        return win32com.client.Dispatch("Outlook.Application")


def save_item(item, dest: Path) -> str:
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / f"{stamp()}_{safe_name(item.Subject)}.msg"
    item.SaveAs(str(path), 3)  # olMSGUnicode
    return str(path)


def export_selected(dest: Path) -> list:
    """Save the mail(s) currently selected in the open Outlook window into `dest`."""
    app = get_app()
    try:
        sel = app.ActiveExplorer().Selection
    except Exception:
        raise RuntimeError("No Outlook window is open.")
    if sel.Count == 0:
        raise RuntimeError("No email is selected in Outlook.")
    paths = [save_item(sel.Item(i), dest) for i in range(1, min(sel.Count, 10) + 1) if sel.Item(i).Class == 43]
    if not paths:
        raise RuntimeError("The selected item is not an email.")
    return paths


def test_connection():
    """Returns (ok, message). Never launches Outlook, only checks whether it is running."""
    import pythoncom

    pythoncom.CoInitialize()
    try:
        try:
            app = get_app(launch=False)
            return True, f"connected to Outlook {app.Version}"
        except RuntimeError as exc:
            return False, str(exc)
        except Exception as exc:
            return False, f"could not reach Outlook: {exc}"
    finally:
        pythoncom.CoUninitialize()
