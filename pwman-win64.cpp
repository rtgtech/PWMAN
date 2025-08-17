#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <tuple>
#include <vector>
#include <sys/stat.h>
#include "libsodium-win64/include/sodium.h"
#include <conio.h>
using namespace std;

using Entry = tuple<string, string, string>;

//  compilation: g++ pwman-win64.cpp -Ilibsodium-win64/include libsodium-win64/lib/libsodium.a -o pwman-w64.exe
const string MAGIC = "PWVN";
const uint32_t VERSION = 1;

constexpr size_t SALT_BYTES = crypto_pwhash_SALTBYTES;
constexpr size_t KEY_BYTES = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
constexpr size_t NONCE_BYTES = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

const uint64_t OPSLIMIT = crypto_pwhash_OPSLIMIT_MODERATE;
const size_t MEMLIMIT = crypto_pwhash_MEMLIMIT_MODERATE;

static bool file_exists(const string &path)
{
    struct stat st;
    return (stat(path.c_str(), &st) == 0);
}
void copy_to_clipboard(const string &text)
{
    string command = "echo " + text + "| clip.exe";
    system(command.c_str());
}

string prompt_hidden(const string &msg)
{
    cout << msg;
    string input;
    char ch;

    while ((ch = _getch()) != '\r')
    { 
        if (ch == '\b')
        { 
            if (!input.empty())
            {
                input.pop_back();
                cout << "\b \b";  // Erase character on screen
            }
        }
        else
        {
            input += ch;
             cout << '*';  // Optional: mask input
        }
    }

    cout << endl;
    return input;
}

static string escape_field(const string &s)
{
    string out;
    out.reserve(s.size());
    for (char c : s)
    {
        if (c == '\\')
            out += "\\\\";
        else if (c == '\n')
            out += "\\n";
        else if (c == '\t')
            out += "\\t";
        else
            out += c;
    }
    return out;
}
static string unescape_field(const string &s)
{
    string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] == '\\' && i + 1 < s.size())
        {
            char nxt = s[++i];
            if (nxt == 'n')
                out += '\n';
            else if (nxt == 't')
                out += '\t';
            else if (nxt == '\\')
                out += '\\';
            else
                out += nxt;
        }
        else
            out += s[i];
    }
    return out;
}

static string serialize_vault(const map<string, Entry> &vault)
{
    ostringstream oss;
    for (auto &kv : vault)
    {
        oss << escape_field(kv.first) << '\t'
            << escape_field(get<0>(kv.second)) << '\t'
            << escape_field(get<1>(kv.second)) << '\t'
            << escape_field(get<2>(kv.second)) << '\n';
    }
    return oss.str();
}
static map<string, Entry> deserialize_vault(const string &data)
{
    map<string, Entry> vault;
    istringstream iss(data);
    string line;
    while (getline(iss, line))
    {
        if (line.empty())
            continue;
        vector<string> parts;
        string cur;
        istringstream lss(line);
        while (getline(lss, cur, '\t'))
            parts.push_back(cur);
        string name = parts.size() > 0 ? unescape_field(parts[0]) : "";
        string user = parts.size() > 1 ? unescape_field(parts[1]) : "";
        string pass = parts.size() > 2 ? unescape_field(parts[2]) : "";
        string notes = parts.size() > 3 ? unescape_field(parts[3]) : "";
        if (!name.empty())
            vault[name] = {user, pass, notes};
    }
    return vault;
}

bool derive_key_from_password(const string &password, const unsigned char salt[SALT_BYTES], unsigned char out_key[KEY_BYTES])
{
    if (password.empty())
        return false;
    if (crypto_pwhash(out_key, KEY_BYTES,
                      password.c_str(), password.size(),
                      salt,
                      OPSLIMIT, MEMLIMIT,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        return false;
    }
    return true;
}

bool aead_encrypt(const string &plaintext, const unsigned char key[KEY_BYTES], vector<unsigned char> &out)
{
    unsigned char nonce[NONCE_BYTES];
    randombytes_buf(nonce, NONCE_BYTES);

    unsigned long long clen = 0;
    out.resize(NONCE_BYTES + plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    memcpy(out.data(), nonce, NONCE_BYTES);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            out.data() + NONCE_BYTES, &clen,
            (const unsigned char *)plaintext.data(), plaintext.size(),
            nullptr, 0,
            nullptr, nonce, key) != 0)
    {
        return false;
    }
    out.resize(NONCE_BYTES + (size_t)clen);
    return true;
}

bool aead_decrypt(const vector<unsigned char> &in, const unsigned char key[KEY_BYTES], string &out_plain)
{
    if (in.size() < NONCE_BYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES)
        return false;
    const unsigned char *nonce = in.data();
    const unsigned char *c = in.data() + NONCE_BYTES;
    size_t clen = in.size() - NONCE_BYTES;
    vector<unsigned char> m(clen);
    unsigned long long mlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            m.data(), &mlen,
            nullptr,
            c, clen,
            nullptr, 0,
            nonce, key) != 0)
    {
        return false;
    }
    out_plain.assign((char *)m.data(), (size_t)mlen);
    return true;
}

bool write_encrypted_file(const string &path, const unsigned char salt[SALT_BYTES], const vector<unsigned char> &cipher)
{
    ofstream ofs(path, ios::binary | ios::trunc);
    if (!ofs)
        return false;

    ofs.write(MAGIC.data(), 4);
    uint32_t v = VERSION;
    unsigned char vb[4];
    vb[0] = (v >> 24) & 0xFF;
    vb[1] = (v >> 16) & 0xFF;
    vb[2] = (v >> 8) & 0xFF;
    vb[3] = (v) & 0xFF;
    ofs.write((char *)vb, 4);
    ofs.write((char *)salt, SALT_BYTES);
    ofs.write((char *)cipher.data(), cipher.size());
    return ofs.good();
}

bool read_encrypted_file(const string &path, unsigned char salt[SALT_BYTES], vector<unsigned char> &cipher)
{
    ifstream ifs(path, ios::binary);
    if (!ifs)
        return false;
    char magicbuf[4];
    ifs.read(magicbuf, 4);
    if (ifs.gcount() != 4)
        return false;
    if (string(magicbuf, 4) != MAGIC)
        return false;
    char vb[4];
    ifs.read(vb, 4);
    if (ifs.gcount() != 4)
        return false;
    ifs.read((char *)salt, SALT_BYTES);
    if (ifs.gcount() != (streamsize)SALT_BYTES)
        return false;
    cipher.assign((istreambuf_iterator<char>(ifs)), {});
    return true;
}

bool load_vault(const string &path, map<string, Entry> &out_vault)
{
    unsigned char salt[SALT_BYTES];
    vector<unsigned char> cipher;
    if (!read_encrypted_file(path, salt, cipher))
    {
        cerr << "Failed to read vault file or invalid format\n";
        return false;
    }
    string password = prompt_hidden("Master password: ");
    unsigned char key[KEY_BYTES];
    if (!derive_key_from_password(password, salt, key))
    {
        cerr << "Key derivation failed\n";
        return false;
    }
    sodium_memzero((void *)password.data(), password.size());
    string plain;
    bool ok = aead_decrypt(cipher, key, plain);
    sodium_memzero(key, KEY_BYTES);
    if (!ok)
    {
        cerr << "Decryption failed (wrong password or corrupt file)\n";
        return false;
    }
    out_vault = deserialize_vault(plain);
    return true;
}

bool save_vault(const string &path, const map<string, Entry> &vault, const unsigned char salt[SALT_BYTES])
{
    string data = serialize_vault(vault);
    string password = prompt_hidden("Master password :");
    unsigned char key[KEY_BYTES];
    if (!derive_key_from_password(password, salt, key))
    {
        cerr << "Key derivation failed\n";
        return false;
    }
    sodium_memzero((void *)password.data(), password.size());

    vector<unsigned char> cipher;
    if (!aead_encrypt(data, key, cipher))
    {
        sodium_memzero(key, KEY_BYTES);
        cerr << "Encryption failed\n";
        return false;
    }
    sodium_memzero(key, KEY_BYTES);
    if (!write_encrypted_file(path, salt, cipher))
    {
        cerr << "Failed to write vault file\n";
        return false;
    }
    return true;
}

int cmd_init(const string &path)
{
    if (file_exists(path))
    {
        cerr << "Error: file exists\n";
        return 1;
    }
    unsigned char salt[SALT_BYTES];
    randombytes_buf(salt, SALT_BYTES);
    map<string, Entry> empty;
    if (!save_vault(path, empty, salt))
        return 1;
    cout << "Initialized encrypted vault: " << path << "\n";
    return 0;
}

int cmd_add(const string &path, const string &name)
{
    if (!file_exists(path))
    {
        cerr << "Vault missing. Run init first.\n";
        return 1;
    }
    unsigned char salt[SALT_BYTES];
    vector<unsigned char> cipher;
    if (!read_encrypted_file(path, salt, cipher))
    {
        cerr << "Read failed\n";
        return 1;
    }

    string password = prompt_hidden("Master password: ");
    unsigned char key[KEY_BYTES];
    if (!derive_key_from_password(password, salt, key))
    {
        cerr << "KDF failed\n";
        return 1;
    }
    sodium_memzero((void *)password.data(), password.size());

    string plain;
    if (!aead_decrypt(cipher, key, plain))
    {
        sodium_memzero(key, KEY_BYTES);
        cerr << "Decrypt failed\n";
        return 1;
    }
    auto vault = deserialize_vault(plain);

    string user, pass, notes;
    cout << "Username: ";
    getline(cin, user);
    cout << "Password: ";
    getline(cin, pass);
    cout << "Notes: ";
    getline(cin, notes);

    vault[name] = {user, pass, notes};

    vector<unsigned char> new_cipher;
    if (!aead_encrypt(serialize_vault(vault), key, new_cipher))
    {
        sodium_memzero(key, KEY_BYTES);
        cerr << "Encrypt failed\n";
        return 1;
    }
    sodium_memzero(key, KEY_BYTES);

    if (!write_encrypted_file(path, salt, new_cipher))
    {
        cerr << "Write failed\n";
        return 1;
    }
    cout << "Added entry '" << name << "'\n";
    return 0;
}

int cmd_list(const string &path)
{
    map<string, Entry> vault;
    if (!load_vault(path, vault))
        return 1;
    if (vault.empty())
    {
        cout << "Vault empty\n";
        return 0;
    }
    cout << "Entries:\n";
    for (auto &kv : vault)
        cout << " - " << kv.first << "\n";
    return 0;
}

int cmd_get(const string &path, const string &name)
{
    map<string, Entry> vault;
    if (!load_vault(path, vault))
        return 1;
    auto it = vault.find(name);
    if (it == vault.end())
    {
        cerr << "Not found\n";
        return 1;
    }
    cout << "Name: " << name << "\n";
    cout << "User: " << get<0>(it->second) << "\n";
    cout << "Password: " << get<1>(it->second) << "\n";
    cout << "Notes: " << get<2>(it->second) << "\n";
    return 0;
}

int main(int argc, char **argv)
{
    if (sodium_init() < 0)
    {
        cerr << "libsodium init failed\n";
        return 1;
    }

    if (argc < 3)
    {
        cerr << "Usage: pwman <vaultfile> <command> [name]\n";
        cerr << "Commands: init, add <name>, list, get <name>, cpy\n";
        return 1;
    }
    string path = argv[1];
    string cmd = argv[2];

    if (cmd == "init")
        return cmd_init(path);
    if (cmd == "add")
    {
        if (argc < 4)
        {
            cerr << "add requires name\n";
            return 1;
        }
        return cmd_add(path, argv[3]);
    }
    if (cmd == "list")
        return cmd_list(path);
    if (cmd == "get")
    {
        if (argc < 4)
        {
            cerr << "get requires name\n";
            return 1;
        }
        return cmd_get(path, argv[3]);
    }
    if (cmd == "cpy")
    {
        if (argc < 4)
        {
            cerr << "Usage: " << argv[0] << " <vault> cpy <name>\n";
            return 1;
        }
        string vault_file = argv[1];
        string name = argv[3];

        map<string, Entry> vault;
        if (!load_vault(path, vault))
            return 1;

        auto it = vault.find(name);
        if (it == vault.end())
        {
            cerr << "No entry named '" << name << "'\n";
            return 1;
        }

        const string &password = get<1>(it->second);
        copy_to_clipboard(password);
        cout << "Password for '" << name << "' copied to Windows clipboard.\n";
        return 0;
    }
    cerr << "Unknown command\n";
    return 0;
}
