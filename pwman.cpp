// pwman.cpp -- chunk 3: Argon2id + XChaCha20-Poly1305 AEAD, with memory hygiene
// Compile: clang++ -std=c++17 -O2 pwman.cpp -lsodium -o pwman

#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <tuple>
#include <vector>
#include <cstring>
#include <sys/stat.h>
#include <sodium.h>
#include <termios.h>
#include <unistd.h>
#include <cstdint>

using Entry = std::tuple<std::string, std::string, std::string>;

// --- File format constants ---
const std::string MAGIC = "PWVN"; // 4 bytes
const uint32_t VERSION = 1;

// libsodium constants
constexpr size_t SALT_BYTES = crypto_pwhash_SALTBYTES; // 16
constexpr size_t KEY_BYTES  = crypto_aead_xchacha20poly1305_ietf_KEYBYTES; // 32
constexpr size_t NONCE_BYTES = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24

// Choose KDF params (moderate). Increase for production after benchmarking.
const uint64_t OPSLIMIT = crypto_pwhash_OPSLIMIT_MODERATE;
const size_t   MEMLIMIT = crypto_pwhash_MEMLIMIT_MODERATE;

static bool file_exists(const std::string &path) {
    struct stat st;
    return (stat(path.c_str(), &st) == 0);
}

void copy_to_clipboard(const std::string& text) {
    // Works on WSL by piping to Windows' clip.exe
    std::string command = "echo \"" + text + "\" | clip.exe";
    std::system(command.c_str());
}

// Prompt hidden (turn off echo)
std::string prompt_hidden(const std::string &msg) {
    std::cout << msg;
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::string input;
    std::getline(std::cin, input);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << "\n";
    return input;
}

// Simple escaping/unescaping for fields
static std::string escape_field(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\t') out += "\\t";
        else out += c;
    }
    return out;
}
static std::string unescape_field(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char nxt = s[++i];
            if (nxt == 'n') out += '\n';
            else if (nxt == 't') out += '\t';
            else if (nxt == '\\') out += '\\';
            else out += nxt;
        } else out += s[i];
    }
    return out;
}

// serialize / deserialize vault (same as before)
static std::string serialize_vault(const std::map<std::string, Entry> &vault) {
    std::ostringstream oss;
    for (auto &kv : vault) {
        oss << escape_field(kv.first) << '\t'
            << escape_field(std::get<0>(kv.second)) << '\t'
            << escape_field(std::get<1>(kv.second)) << '\t'
            << escape_field(std::get<2>(kv.second)) << '\n';
    }
    return oss.str();
}
static std::map<std::string, Entry> deserialize_vault(const std::string &data) {
    std::map<std::string, Entry> vault;
    std::istringstream iss(data);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty()) continue;
        std::vector<std::string> parts;
        std::string cur;
        std::istringstream lss(line);
        while (std::getline(lss, cur, '\t')) parts.push_back(cur);
        std::string name = parts.size() > 0 ? unescape_field(parts[0]) : "";
        std::string user = parts.size() > 1 ? unescape_field(parts[1]) : "";
        std::string pass = parts.size() > 2 ? unescape_field(parts[2]) : "";
        std::string notes = parts.size() > 3 ? unescape_field(parts[3]) : "";
        if (!name.empty()) vault[name] = {user, pass, notes};
    }
    return vault;
}

// --- Crypto helpers ---

// Derive a 32-byte key from password + salt using Argon2id (libsodium)
bool derive_key_from_password(const std::string &password, const unsigned char salt[SALT_BYTES], unsigned char out_key[KEY_BYTES]) {
    if (password.empty()) return false;
    if (crypto_pwhash(out_key, KEY_BYTES,
                      password.c_str(), password.size(),
                      salt,
                      OPSLIMIT, MEMLIMIT,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        // out of memory / too slow
        return false;
    }
    return true;
}

// AEAD encrypt plaintext -> cipher (cipher = nonce || ciphertext)
bool aead_encrypt(const std::string &plaintext, const unsigned char key[KEY_BYTES], std::vector<unsigned char> &out) {
    unsigned char nonce[NONCE_BYTES];
    randombytes_buf(nonce, NONCE_BYTES);

    unsigned long long clen = 0;
    out.resize(NONCE_BYTES + plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    // place nonce at beginning
    memcpy(out.data(), nonce, NONCE_BYTES);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            out.data() + NONCE_BYTES, &clen,
            (const unsigned char*)plaintext.data(), plaintext.size(),
            nullptr, 0, // no additional data
            nullptr, nonce, key) != 0) {
        return false;
    }
    // resize to actual length (nonce + clen)
    out.resize(NONCE_BYTES + (size_t)clen);
    return true;
}

// AEAD decrypt (expects cipher prefixed with nonce)
bool aead_decrypt(const std::vector<unsigned char> &in, const unsigned char key[KEY_BYTES], std::string &out_plain) {
    if (in.size() < NONCE_BYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES) return false;
    const unsigned char *nonce = in.data();
    const unsigned char *c = in.data() + NONCE_BYTES;
    size_t clen = in.size() - NONCE_BYTES;
    std::vector<unsigned char> m(clen); // over-allocate
    unsigned long long mlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            m.data(), &mlen,
            nullptr,
            c, clen,
            nullptr, 0,
            nonce, key) != 0) {
        return false;
    }
    out_plain.assign((char*)m.data(), (size_t)mlen);
    return true;
}

// --- File operations using the new file layout ---
// file layout:
// [MAGIC 4 bytes][VERSION 4 bytes big-endian][salt SALT_BYTES][nonce NONCE_BYTES][ciphertext...]

bool write_encrypted_file(const std::string &path, const unsigned char salt[SALT_BYTES], const std::vector<unsigned char> &cipher) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) return false;

    // header
    ofs.write(MAGIC.data(), 4);
    uint32_t v = VERSION;
    unsigned char vb[4];
    vb[0] = (v >> 24) & 0xFF;
    vb[1] = (v >> 16) & 0xFF;
    vb[2] = (v >> 8) & 0xFF;
    vb[3] = (v) & 0xFF;
    ofs.write((char*)vb, 4);
    ofs.write((char*)salt, SALT_BYTES);
    // cipher already includes nonce at its beginning
    ofs.write((char*)cipher.data(), cipher.size());
    return ofs.good();
}

bool read_encrypted_file(const std::string &path, unsigned char salt[SALT_BYTES], std::vector<unsigned char> &cipher) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    // read magic + version
    char magicbuf[4];
    ifs.read(magicbuf, 4);
    if (ifs.gcount() != 4) return false;
    if (std::string(magicbuf, 4) != MAGIC) return false;
    char vb[4];
    ifs.read(vb, 4);
    if (ifs.gcount() != 4) return false;
    // read salt
    ifs.read((char*)salt, SALT_BYTES);
    if (ifs.gcount() != (std::streamsize)SALT_BYTES) return false;
    // read rest (nonce + ciphertext)
    cipher.assign((std::istreambuf_iterator<char>(ifs)), {});
    return true;
}

// High-level: load vault (prompt for master password, derive key, decrypt)
bool load_vault(const std::string &path, std::map<std::string, Entry> &out_vault) {
    unsigned char salt[SALT_BYTES];
    std::vector<unsigned char> cipher;
    if (!read_encrypted_file(path, salt, cipher)) {
        std::cerr << "Failed to read vault file or invalid format\n";
        return false;
    }
    std::string password = prompt_hidden("Master password: ");
    unsigned char key[KEY_BYTES];
    if (!derive_key_from_password(password, salt, key)) {
        std::cerr << "Key derivation failed\n";
        return false;
    }
    sodium_memzero((void*)password.data(), password.size());
    std::string plain;
    bool ok = aead_decrypt(cipher, key, plain);
    sodium_memzero(key, KEY_BYTES);
    if (!ok) {
        std::cerr << "Decryption failed (wrong password or corrupt file)\n";
        return false;
    }
    out_vault = deserialize_vault(plain);
    return true;
}

// High-level: save vault (prompt for master password used earlier? For safety, we will ask for password again to derive key)
// But to avoid double prompt on add, caller will pass the salt and password-derived key if available.
// We'll implement save_vault which takes salt and password (we will re-derive key inside)
bool save_vault(const std::string &path, const std::map<std::string, Entry> &vault, const unsigned char salt[SALT_BYTES]) {
    std::string data = serialize_vault(vault);
    std::string password = prompt_hidden("Master password (to re-encrypt): ");
    unsigned char key[KEY_BYTES];
    if (!derive_key_from_password(password, salt, key)) {
        std::cerr << "Key derivation failed\n";
        return false;
    }
    sodium_memzero((void*)password.data(), password.size());

    std::vector<unsigned char> cipher;
    if (!aead_encrypt(data, key, cipher)) {
        sodium_memzero(key, KEY_BYTES);
        std::cerr << "Encryption failed\n";
        return false;
    }
    sodium_memzero(key, KEY_BYTES);
    if (!write_encrypted_file(path, salt, cipher)) {
        std::cerr << "Failed to write vault file\n";
        return false;
    }
    return true;
}

// --- Commands ---

int cmd_init(const std::string &path) {
    if (file_exists(path)) {
        std::cerr << "Error: file exists\n";
        return 1;
    }
    unsigned char salt[SALT_BYTES];
    randombytes_buf(salt, SALT_BYTES);
    // create empty vault
    std::map<std::string, Entry> empty;
    // save: this will prompt for master password (to derive key)
    if (!save_vault(path, empty, salt)) return 1;
    std::cout << "Initialized encrypted vault: " << path << "\n";
    return 0;
}

int cmd_add(const std::string &path, const std::string &name) {
    if (!file_exists(path)) {
        std::cerr << "Vault missing. Run init first.\n";
        return 1;
    }
    // read salt + cipher and decrypt (load_vault will prompt for master password)
    unsigned char salt[SALT_BYTES];
    std::vector<unsigned char> cipher;
    if (!read_encrypted_file(path, salt, cipher)) { std::cerr << "Read failed\n"; return 1; }

    // ask password once and derive key to decrypt
    std::string password = prompt_hidden("Master password: ");
    unsigned char key[KEY_BYTES];
    if (!derive_key_from_password(password, salt, key)) { std::cerr << "KDF failed\n"; return 1; }
    sodium_memzero((void*)password.data(), password.size());

    std::string plain;
    if (!aead_decrypt(cipher, key, plain)) { sodium_memzero(key, KEY_BYTES); std::cerr << "Decrypt failed\n"; return 1; }
    // parse vault
    auto vault = deserialize_vault(plain);

    // get new entry fields
    std::string user, pass, notes;
    std::cout << "Username: "; std::getline(std::cin, user);
    std::cout << "Password: "; std::getline(std::cin, pass);
    std::cout << "Notes: "; std::getline(std::cin, notes);

    vault[name] = {user, pass, notes};

    // re-encrypt with fresh nonce using same key
    std::vector<unsigned char> new_cipher;
    if (!aead_encrypt(serialize_vault(vault), key, new_cipher)) {
        sodium_memzero(key, KEY_BYTES);
        std::cerr << "Encrypt failed\n";
        return 1;
    }
    sodium_memzero(key, KEY_BYTES);

    // write file: header (magic/version/salt) + new_cipher
    if (!write_encrypted_file(path, salt, new_cipher)) {
        std::cerr << "Write failed\n";
        return 1;
    }
    std::cout << "Added entry '" << name << "'\n";
    return 0;
}

int cmd_list(const std::string &path) {
    std::map<std::string, Entry> vault;
    if (!load_vault(path, vault)) return 1;
    if (vault.empty()) { std::cout << "Vault empty\n"; return 0; }
    std::cout << "Entries:\n";
    for (auto &kv : vault) std::cout << " - " << kv.first << "\n";
    return 0;
}

int cmd_get(const std::string &path, const std::string &name) {
    std::map<std::string, Entry> vault;
    if (!load_vault(path, vault)) return 1;
    auto it = vault.find(name);
    if (it == vault.end()) { std::cerr << "Not found\n"; return 1; }
    std::cout << "Name: " << name << "\n";
    std::cout << "User: " << std::get<0>(it->second) << "\n";
    std::cout << "Password: " << std::get<1>(it->second) << "\n";
    std::cout << "Notes: " << std::get<2>(it->second) << "\n";
    return 0;
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return 1;
    }
    if (argc < 3) {
        std::cerr << "Usage: pwman <vaultfile> <command> [name]\n";
        std::cerr << "Commands: init, add <name>, list, get <name>\n";
        return 1;
    }
    std::string path = argv[1];
    std::string cmd = argv[2];

    if (cmd == "init") return cmd_init(path);
    if (cmd == "add") { if (argc < 4) { std::cerr << "add requires name\n"; return 1; } return cmd_add(path, argv[3]); }
    if (cmd == "list") return cmd_list(path);
    if (cmd == "get") { if (argc < 4) { std::cerr << "get requires name\n"; return 1; } return cmd_get(path, argv[3]); }
    if (cmd == "cpy") {
        if (argc < 4) {
            std::cerr << "Usage: " << argv[0] << " <vault> cpy <name>\n";
            return 1;
        }
        std::string vault_file = argv[1];
        std::string name = argv[3];

    // 1. Load vault from file (same as you do for "get")
    // 2. Prompt for master password (same as in "get")
    // 3. Decrypt vault (same as in "get")
        std::map<std::string, Entry> vault;
        if (!load_vault(path, vault)) return 1;

        auto it = vault.find(name); // same vault map/dictionary you use in "get"
        if (it == vault.end()) {
            std::cerr << "No entry named '" << name << "'\n";
            return 1;
        }

        const std::string& password = std::get<1>(it->second); // assuming tuple<username, password, notes>
        copy_to_clipboard(password);
        std::cout << "Password for '" << name << "' copied to Windows clipboard.\n";
        return 0;
    }
    std::cerr << "Unknown command\n";
    return 1;
}
