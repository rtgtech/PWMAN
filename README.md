# PWMAN

A Command line based password manager for linux. Built in C++ using Libsodium library.

### Options
- **init** : initialize a new vault file.
- **add** : add a new entry.
- **get** : get the password for a particular entry.
- **list** : display the list of all entries.
- **cpy** : copy the password of an entry to the clipboard. (Windows Only)
- **modify** : modify the entry.
- **del** : delete a password entry.

*Usage:*
```
$./pwman vault.bin init         #initialize a vault file.

$./pwman vault.bin add _entry   #add a password for entry "_entry"

$./pwman vault.bin get _entry   #get the data stored in entry "_entry"

$./pwman vault.bin list         #list all entries

#Windows only

$./pwman vault.bin cpy _entry   #copy the password of "_entry" to clipboard.

$./pwman vault.bin modify _entry   #modify the contents of "_entry".

$./pwman vault.bin del _entry   #delete "_entry".
```

*Install dependency (Windows):*

Download a libsodium release:

[List of all official releases](https://download.libsodium.org/libsodium/releases/)

Download the release used in this project (libsodium-1.0.19):

[libsodium-1.0.19-stable-mingw.tar.gz](https://download.libsodium.org/libsodium/releases/libsodium-1.0.19-stable-mingw.tar.gz)
```
Directory structure:
..
|--- pwman-win64.cpp
|---\libsodium-win64
    |---\bin
    |---\include
    |---\lib
```

*Install dependency (Linux/WSL):*
```
$sudo apt install libsodium-dev
```

*Build (Windows):*

> <!> Libsodium is statically linked here.

```
$g++ pwman-win64.cpp -Ilibsodium-win64/include libsodium-win64/lib/libsodium.a -o pwman-w64.exe
```

*Build (Linux/WSL):*
```
$clang++ -std=c++17 -O2 pwman-linux.cpp -lsodium -o pwman
#OR
$g++ -std=c++17 -O2 pwman-linux.cpp -lsodium -o pwman
```

