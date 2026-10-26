"""Generates assets/icon.png and assets/icon.ico (the PhishCheck logo). Re-run to regenerate."""
import struct
import sys
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QPointF, QRectF, Qt
from PySide6.QtGui import QBrush, QColor, QGuiApplication, QImage, QPainter, QPainterPath, QPen, QPolygonF

YELLOW, BLACK = QColor("#FFD400"), QColor("#0b0b0b")


def draw(size: int) -> QImage:
    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(Qt.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    s = size / 256.0
    p.scale(s, s)

    # black rounded tile with yellow rim
    p.setPen(QPen(YELLOW, 8))
    p.setBrush(QBrush(BLACK))
    p.drawRoundedRect(QRectF(8, 8, 240, 240), 52, 52)

    # shield
    shield = QPainterPath()
    shield.moveTo(128, 40)
    shield.lineTo(204, 66)
    shield.cubicTo(204, 130, 190, 176, 128, 214)
    shield.cubicTo(66, 176, 52, 130, 52, 66)
    shield.closeSubpath()
    p.setPen(Qt.NoPen)
    p.setBrush(QBrush(YELLOW))
    p.drawPath(shield)

    # fish-hook cut into the shield (phish + check)
    pen = QPen(BLACK, 17, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    hook = QPainterPath()
    hook.moveTo(128, 78)
    hook.lineTo(128, 142)
    hook.cubicTo(128, 184, 98, 186, 98, 156)
    p.drawPath(hook)
    p.drawLine(QPointF(110, 94), QPointF(146, 94))  # eye bar
    p.drawLine(QPointF(98, 156), QPointF(88, 145))  # barb

    # LED dot
    p.setPen(Qt.NoPen)
    p.setBrush(QBrush(QColor("#35e06b")))
    p.drawEllipse(QPointF(196, 196), 13, 13)
    p.setBrush(QBrush(QColor(255, 255, 255, 140)))
    p.drawEllipse(QPointF(192, 191), 4.5, 4.5)
    p.end()
    return img


def png_bytes(img: QImage) -> bytes:
    ba = QByteArray()
    buf = QBuffer(ba)
    buf.open(QIODevice.WriteOnly)
    img.save(buf, "PNG")
    return bytes(ba)


def main():
    QGuiApplication(sys.argv)
    out = Path(__file__).resolve().parent / "assets"
    out.mkdir(exist_ok=True)
    draw(512).save(str(out / "icon.png"), "PNG")

    sizes = [16, 24, 32, 48, 64, 128, 256]
    blobs = [png_bytes(draw(n)) for n in sizes]
    header = struct.pack("<HHH", 0, 1, len(sizes))
    offset = 6 + 16 * len(sizes)
    entries = b""
    for n, b in zip(sizes, blobs):
        entries += struct.pack("<BBBBHHII", n % 256, n % 256, 0, 0, 1, 32, len(b), offset)
        offset += len(b)
    (out / "icon.ico").write_bytes(header + entries + b"".join(blobs))
    print("wrote", out / "icon.png", out / "icon.ico")


if __name__ == "__main__":
    main()
