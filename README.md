# PWMAN

A Command line based password manager for linux. Built in C++ using Libsodium library.

> Tool is in its initial stage of development. Look at notes at the bottom before using.

### Options
- **init** : initialize a new vault file.
- **add** : add a new entry.
- **get** : get the password for a particular entry.
- **list** : display the list of all entries.
- **cpy** : copy the password of an entry to the clipboard.
- **modify** : update an existing entry.
- **del** : delete an existing entry.

*Usage:*
```
$./pwman init         #initialize the default vault file: vault.bin

$./pwman add _entry   #add a password for entry "_entry" in vault.bin

$./pwman get _entry   #get the data stored in entry "_entry"

$./pwman list         #list all entries

$./pwman cpy _entry   #copy the password of "_entry" to clipboard.

$./pwman modify _entry   #modify the data stored in entry "_entry"

$./pwman del _entry      #delete the data stored in entry "_entry"

$./pwman custom.bin list   #use a non-default vault file when needed
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
```
$g++ pwman-win64.cpp -Ilibsodium-win64/include libsodium-win64/lib/libsodium.a -o pwman-w64.exe
```

*Build (Linux/WSL):*
```
$clang++ -std=c++17 -O2 pwman-linux.cpp -lsodium -o pwman
#OR
$g++ -std=c++17 -O2 pwman-linux.cpp -lsodium -o pwman
```

> Notes:
> All options work on Windows subsystem for Linux (WSL Ubuntu-24.04).
> `cpy` uses `clip.exe` in WSL and falls back to `wl-copy`, `xclip`, or `xsel` on Linux.
