#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <tuple>
#include <vector>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sodium.h>
#include <termios.h>
#include <unistd.h>

using namespace std;

using Entry = tuple<string, string, string>;

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
    return stat(path.c_str(), &st) == 0;
}

static bool is_wsl()
{
    const char *distro = getenv("WSL_DISTRO_NAME");
    if (distro && *distro)
        return true;

    ifstream release("/proc/sys/kernel/osrelease");
    string text;
    getline(release, text);
    return text.find("Microsoft") != string::npos || text.find("microsoft") != string::npos;
}

static bool write_to_command_stdin(const char *command, const string &text)
{
    FILE *pipe = popen(command, "w");
    if (!pipe)
        return false;

    size_t written = fwrite(text.data(), 1, text.size(), pipe);
    int status = pclose(pipe);
    return written == text.size() && status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

bool copy_to_clipboard(const string &text)
{
    vector<const char *> commands;
    if (is_wsl())
        commands.push_back("clip.exe");

    commands.push_back("wl-copy");
    commands.push_back("xclip -selection clipboard");
    commands.push_back("xsel --clipboard --input");

    for (const char *command : commands)
    {
        if (write_to_command_stdin(command, text))
            return true;
    }
    return false;
}

string prompt_hidden(const string &msg)
{
    cout << msg;

    termios oldt{};
    if (tcgetattr(STDIN_FILENO, &oldt) != 0)
    {
        string input;
        getline(cin, input);
        return input;
    }

    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    string input;
    getline(cin, input);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    cout << "\n";
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
        {
            out += s[i];
        }
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
            reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size(),
            nullptr, 0,
            nullptr, nonce, key) != 0)
    {
        return false;
    }
    out.resize(NONCE_BYTES + static_cast<size_t>(clen));
    return true;
}

bool aead_decrypt(const vector<unsigned char> &in, const unsigned char key[KEY_BYTES], string &out_plain)
{
    if (in.size() < NONCE_BYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES)
        return false;

    const unsigned char *nonce = in.data();
    const unsigned char *ciphertext = in.data() + NONCE_BYTES;
    size_t clen = in.size() - NONCE_BYTES;
    vector<unsigned char> plain_bytes(clen);
    unsigned long long plain_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plain_bytes.data(), &plain_len,
            nullptr,
            ciphertext, clen,
            nullptr, 0,
            nonce, key) != 0)
    {
        return false;
    }

    out_plain.assign(reinterpret_cast<char *>(plain_bytes.data()), static_cast<size_t>(plain_len));
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
    vb[3] = v & 0xFF;
    ofs.write(reinterpret_cast<char *>(vb), 4);
    ofs.write(reinterpret_cast<const char *>(salt), SALT_BYTES);
    ofs.write(reinterpret_cast<const char *>(cipher.data()), cipher.size());
    return ofs.good();
}

bool read_encrypted_file(const string &path, unsigned char salt[SALT_BYTES], vector<unsigned char> &cipher)
{
    ifstream ifs(path, ios::binary);
    if (!ifs)
        return false;

    char magicbuf[4];
    ifs.read(magicbuf, 4);
    if (ifs.gcount() != 4 || string(magicbuf, 4) != MAGIC)
        return false;

    char vb[4];
    ifs.read(vb, 4);
    if (ifs.gcount() != 4)
        return false;

    ifs.read(reinterpret_cast<char *>(salt), SALT_BYTES);
    if (ifs.gcount() != static_cast<streamsize>(SALT_BYTES))
        return false;

    cipher.assign(istreambuf_iterator<char>(ifs), {});
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
    sodium_memzero(password.data(), password.size());

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
    string password = prompt_hidden("Master password: ");
    unsigned char key[KEY_BYTES];
    if (!derive_key_from_password(password, salt, key))
    {
        cerr << "Key derivation failed\n";
        return false;
    }
    sodium_memzero(password.data(), password.size());

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

static bool unlock_vault_for_edit(const string &path, unsigned char salt[SALT_BYTES], unsigned char key[KEY_BYTES], map<string, Entry> &vault)
{
    vector<unsigned char> cipher;
    if (!read_encrypted_file(path, salt, cipher))
    {
        cerr << "Read failed\n";
        return false;
    }

    string password = prompt_hidden("Master password: ");
    if (!derive_key_from_password(password, salt, key))
    {
        cerr << "KDF failed\n";
        return false;
    }
    sodium_memzero(password.data(), password.size());

    string plain;
    if (!aead_decrypt(cipher, key, plain))
    {
        sodium_memzero(key, KEY_BYTES);
        cerr << "Decrypt failed\n";
        return false;
    }

    vault = deserialize_vault(plain);
    return true;
}

static bool save_unlocked_vault(const string &path, const unsigned char salt[SALT_BYTES], unsigned char key[KEY_BYTES], const map<string, Entry> &vault)
{
    vector<unsigned char> cipher;
    if (!aead_encrypt(serialize_vault(vault), key, cipher))
    {
        sodium_memzero(key, KEY_BYTES);
        cerr << "Encrypt failed\n";
        return false;
    }
    sodium_memzero(key, KEY_BYTES);

    if (!write_encrypted_file(path, salt, cipher))
    {
        cerr << "Write failed\n";
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
    unsigned char salt[SALT_BYTES];
    unsigned char key[KEY_BYTES];
    map<string, Entry> vault;
    if (!unlock_vault_for_edit(path, salt, key, vault))
        return 1;

    string user, pass, notes;
    cout << "Username: ";
    getline(cin, user);
    cout << "Password: ";
    getline(cin, pass);
    cout << "Notes: ";
    getline(cin, notes);

    vault[name] = {user, pass, notes};

    if (!save_unlocked_vault(path, salt, key, vault))
        return 1;

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

int cmd_cpy(const string &path, const string &name)
{
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
    if (!copy_to_clipboard(password))
    {
        cerr << "Failed to copy password to the clipboard. Install wl-copy, xclip, or xsel, or use WSL clip.exe.\n";
        return 1;
    }

    cout << "Password for '" << name << "' copied to the clipboard.\n";
    return 0;
}

int cmd_delete(const string &path, const string &name)
{
    unsigned char salt[SALT_BYTES];
    unsigned char key[KEY_BYTES];
    map<string, Entry> vault;
    if (!unlock_vault_for_edit(path, salt, key, vault))
        return 1;

    auto it = vault.find(name);
    if (it == vault.end())
    {
        cout << "The Entry does not exist";
        sodium_memzero(key, KEY_BYTES);
        return 0;
    }

    vault.erase(it);
    if (!save_unlocked_vault(path, salt, key, vault))
        return 1;

    cout << "Deleted entry '" << name << "'\n";
    return 0;
}

int cmd_modify(const string &path, const string &name)
{
    unsigned char salt[SALT_BYTES];
    unsigned char key[KEY_BYTES];
    map<string, Entry> vault;
    if (!unlock_vault_for_edit(path, salt, key, vault))
        return 1;

    auto it = vault.find(name);
    if (it == vault.end())
    {
        cout << "Name not found";
        sodium_memzero(key, KEY_BYTES);
        return 0;
    }

    string user, pass, notes;
    cout << "<!>Leave empty if you dont want to change any of the following\n";
    cout << "Username: ";
    getline(cin, user);
    cout << "Password: ";
    getline(cin, pass);
    cout << "Notes: ";
    getline(cin, notes);

    Entry current = it->second;
    get<0>(it->second) = user.empty() ? get<0>(current) : user;
    get<1>(it->second) = pass.empty() ? get<1>(current) : pass;
    get<2>(it->second) = notes.empty() ? get<2>(current) : notes;

    if (!save_unlocked_vault(path, salt, key, vault))
        return 1;

    cout << "Modified entry '" << name << "'\n";
    return 0;
}

static bool is_command_name(const string &value)
{
    return value == "init" || value == "add" || value == "list" || value == "get" ||
           value == "cpy" || value == "modify" || value == "del";
}

int main(int argc, char **argv)
{
    if (sodium_init() < 0)
    {
        cerr << "libsodium init failed\n";
        return 1;
    }

    if (argc < 2)
    {
        cerr << "Usage: pwman [vaultfile] <command> [name]\n";
        cerr << "Default vault: vault.bin\n";
        cerr << "Commands: init, add <name>, list, get <name>, cpy <name>, modify <name>, del <name>\n";
        return 1;
    }

    string path = "vault.bin";
    string cmd;
    int arg_offset = 1;

    if (is_command_name(argv[1]))
    {
        cmd = argv[1];
    }
    else
    {
        if (argc < 3)
        {
            cerr << "Usage: pwman [vaultfile] <command> [name]\n";
            cerr << "Default vault: vault.bin\n";
            return 1;
        }
        path = argv[1];
        cmd = argv[2];
        arg_offset = 2;
    }

    if (cmd == "init")
        return cmd_init(path);

    if (!file_exists(path))
    {
        cerr << "Vault does not exist. Run init command!\n";
        return 1;
    }

    if (cmd == "add")
    {
        if (argc < arg_offset + 2)
        {
            cerr << "add requires name\n";
            return 1;
        }
        return cmd_add(path, argv[arg_offset + 1]);
    }
    if (cmd == "list")
        return cmd_list(path);
    if (cmd == "get")
    {
        if (argc < arg_offset + 2)
        {
            cerr << "get requires name\n";
            return 1;
        }
        return cmd_get(path, argv[arg_offset + 1]);
    }
    if (cmd == "cpy")
    {
        if (argc < arg_offset + 2)
        {
            cerr << "Usage: " << argv[0] << " [vaultfile] cpy <name>\n";
            return 1;
        }
        return cmd_cpy(path, argv[arg_offset + 1]);
    }
    if (cmd == "modify")
    {
        if (argc < arg_offset + 2)
        {
            cerr << "Usage: " << argv[0] << " [vaultfile] modify <name>\n";
            return 1;
        }
        return cmd_modify(path, argv[arg_offset + 1]);
    }
    if (cmd == "del")
    {
        if (argc < arg_offset + 2)
        {
            cerr << "Usage: " << argv[0] << " [vaultfile] del <name>\n";
            return 1;
        }
        return cmd_delete(path, argv[arg_offset + 1]);
    }

    cerr << "Unknown command\n";
    return 1;
}
