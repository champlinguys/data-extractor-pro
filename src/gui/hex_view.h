#pragma once
#include <QPlainTextEdit>
#include <vector>
#include <cstdint>

// Read-only hex+ASCII dump of a byte buffer, used to preview the head of a
// selected file. Monospaced, classic `hexdump -C` style layout.
class HexView : public QPlainTextEdit {
    Q_OBJECT
public:
    explicit HexView(QWidget* parent = nullptr);
    void setData(const std::vector<uint8_t>& data, uint64_t baseOffset = 0);
    void clearData();
};
