#include "bitlocker/keys.h"
#include "core/byte_reader.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cstring>
#include <cstdlib>

namespace de::bitlocker {

std::optional<std::vector<uint8_t>> parseRecoveryPassword(const std::string& pw) {
    std::vector<uint16_t> groups;
    std::string cur;
    auto flush = [&]() -> bool {
        if (cur.size() != 6) return false;
        uint32_t v = static_cast<uint32_t>(std::strtoul(cur.c_str(), nullptr, 10));
        if (v % 11 != 0) return false;
        v /= 11;
        if (v > 0xFFFF) return false;
        groups.push_back(static_cast<uint16_t>(v));
        cur.clear();
        return true;
    };
    for (char c : pw) {
        if (c == '-' || c == ' ') { if (!flush()) return std::nullopt; }
        else if (c >= '0' && c <= '9') cur.push_back(c);
        else return std::nullopt;
    }
    if (!flush()) return std::nullopt;
    if (groups.size() != 8) return std::nullopt;

    std::vector<uint8_t> bin(16);
    for (size_t i = 0; i < 8; ++i) { // little-endian uint16 each
        bin[i * 2]     = groups[i] & 0xFF;
        bin[i * 2 + 1] = groups[i] >> 8;
    }
    return bin;
}

std::vector<uint8_t> deriveStretchKey(const std::vector<uint8_t>& recoveryBin,
                                      const uint8_t salt[16]) {
    // Hashed data layout (packed): updated(32) + initial(32) + salt(16) + count(8).
    struct {
        uint8_t updated[32];
        uint8_t initial[32];
        uint8_t salt[16];
        uint64_t count;
    } d;
    std::memset(&d, 0, sizeof d);
    SHA256(recoveryBin.data(), recoveryBin.size(), d.initial); // initial = SHA256(binary)
    std::memcpy(d.salt, salt, 16);

    for (uint64_t i = 0; i < 0x100000; ++i) {
        SHA256(reinterpret_cast<const uint8_t*>(&d), sizeof d, d.updated);
        d.count++;
    }
    return std::vector<uint8_t>(d.updated, d.updated + 32);
}

std::optional<std::vector<uint8_t>>
aesCcmDecrypt(const std::vector<uint8_t>& key, const uint8_t nonce[12],
              const std::vector<uint8_t>& macAndData) {
    if (macAndData.size() < 16) return std::nullopt;
    const uint8_t* tag = macAndData.data();
    const uint8_t* ct = macAndData.data() + 16;
    int ctLen = static_cast<int>(macAndData.size() - 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::nullopt;
    std::vector<uint8_t> out(ctLen);
    int len = 0;
    bool ok = false;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ccm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 12, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16,
                            const_cast<uint8_t*>(tag)) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) == 1 &&
        EVP_DecryptUpdate(ctx, nullptr, &len, nullptr, ctLen) == 1) {
        // A positive return here means the CCM tag verified.
        ok = EVP_DecryptUpdate(ctx, out.data(), &len, ct, ctLen) > 0;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return std::nullopt;
    return out;
}

namespace {
// The AES-CCM plaintext for a wrapped key is a metadata entry followed by a
// "key" property: entry header (8) + key header (key_type u16 + reserved u16),
// then the raw key bytes. So the key material starts at offset 12.
std::vector<uint8_t> extractKey(const std::vector<uint8_t>& plain) {
    if (plain.size() <= 12) return {};
    return std::vector<uint8_t>(plain.begin() + 12, plain.end());
}
} // namespace

std::optional<VolumeKeys> unlockWithRecovery(const FveMetadata& md,
                                             const std::string& recoveryPassword) {
    auto bin = parseRecoveryPassword(recoveryPassword);
    if (!bin) return std::nullopt;

    for (const auto& vmkProt : md.vmks) {
        if (vmkProt.protectionTypeRaw != 0x0800) continue; // recovery password
        if (!vmkProt.hasSalt || !vmkProt.encryptedVmk) continue;

        auto stretch = deriveStretchKey(*bin, vmkProt.salt);
        auto vmkPlain = aesCcmDecrypt(stretch, vmkProt.encryptedVmk->nonce,
                                      vmkProt.encryptedVmk->macAndData);
        if (!vmkPlain) return std::nullopt;      // wrong password
        auto vmk = extractKey(*vmkPlain);
        if (vmk.size() < 32) return std::nullopt;
        vmk.resize(32);

        if (!md.encryptedFvek) return std::nullopt;
        auto fvekPlain = aesCcmDecrypt(vmk, md.encryptedFvek->nonce,
                                       md.encryptedFvek->macAndData);
        if (!fvekPlain) return std::nullopt;
        VolumeKeys keys;
        keys.fvek = extractKey(*fvekPlain);
        keys.method = md.method;
        return keys;
    }
    return std::nullopt;
}

void aesXtsDecryptSector(const VolumeKeys& keys, uint64_t dataUnit,
                         uint8_t* sector) {
    bool xts256 = keys.method == EncryptionMethod::AesXts256;
    // XTS uses key1||key2. AES-XTS-128 => two 16-byte keys (32 total).
    size_t keyLen = xts256 ? 64 : 32;
    if (keys.fvek.size() < keyLen) return;

    uint8_t tweak[16] = {};
    for (int i = 0; i < 8; ++i) tweak[i] = (dataUnit >> (8 * i)) & 0xFF; // LE unit number

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;
    const EVP_CIPHER* c = xts256 ? EVP_aes_256_xts() : EVP_aes_128_xts();
    int len = 0;
    uint8_t out[512];
    if (EVP_DecryptInit_ex(ctx, c, nullptr, keys.fvek.data(), tweak) == 1)
        EVP_DecryptUpdate(ctx, out, &len, sector, 512);
    EVP_CIPHER_CTX_free(ctx);
    std::memcpy(sector, out, 512);
}

} // namespace de::bitlocker
