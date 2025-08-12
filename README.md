# PWMAN

A Command line based password manager for linux. Built in C++ using Libsodium library.

> Tool is in its initial stage of development. Look at notes at the bottom before using.

### Options
- **init** : initialize a new vault file.
- **add** : add a new entry.
- **get** : get the password for a particular entry.
- **list** : display the list of all entries.
- **cpy** : copy the password of an entry to the clipboard. (Accessibility not gauranteed)

*Usage:*
```
$./pwman vault.bin init         #initialize a vault file.

$./pwman vault.bin add _entry   #add a password for entry "_entry"

$./pwman vault.bin get _entry   #get the data stored in entry "_entry"

$./pwman vault.bin list         #list all entries

$./pwman vault.bin cpy _entry   #copy the password of "_entry" to clipboard
```

> Notes:
> All options work on Windows subsystem for Linux (WSL Ubuntu-24.04).
> "cpy" option's compatability with other systems has not been established.
