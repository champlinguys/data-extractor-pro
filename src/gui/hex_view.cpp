#include "gui/hex_view.h"
#include <QFont>
#include <QFontDatabase>

HexView::HexView(QWidget* parent) : QPlainTextEdit(parent) {
    setReadOnly(true);
    setLineWrapMode(QPlainTextEdit::NoWrap);
    QFont f = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    setFont(f);
    setPlaceholderText("Select a file to preview its contents");
}

void HexView::clearData() { clear(); }

void HexView::setData(const std::vector<uint8_t>& data, uint64_t baseOffset) {
    static const char* hex = "0123456789abcdef";
    QString out;
    // The caller bounds how much it hands us (the preview-size preference);
    // keep a generous safety cap so a stray large buffer can't freeze the UI.
    const size_t limit = 4 * 1024 * 1024;
    size_t n = data.size() < limit ? data.size() : limit;
    out.reserve(static_cast<int>(n / 16 * 78 + 80));

    for (size_t i = 0; i < n; i += 16) {
        char off[24];
        std::snprintf(off, sizeof off, "%08llx  ",
                      (unsigned long long)(baseOffset + i));
        out += off;

        QString ascii;
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < n) {
                uint8_t b = data[i + j];
                out += hex[b >> 4];
                out += hex[b & 0xF];
                out += ' ';
                ascii += (b >= 0x20 && b < 0x7F) ? QChar(b) : QChar('.');
            } else {
                out += "   ";
            }
            if (j == 7) out += ' ';
        }
        out += " |" + ascii + "|\n";
    }
    if (data.size() > n)
        out += QString("... (%1 more bytes)\n").arg(data.size() - n);
    setPlainText(out);
}
