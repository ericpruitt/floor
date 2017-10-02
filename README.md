Floor
=====

Floor is a front-end for LUKS encrypted volumes that are stored as disk images
on existing file systems and mounted as loopback devices. Its key feature is
its deterministic password generation; volume keys are derived from a private
secret and the UUID of each volume which is part of the unencrypted LUKS
header. This means that backups of the secret do not need to be updated
whenever a new volume is created.

The script is layer built on dm-**crypt**. A crypt is a chamber beneath the
**floor** of a building; and thus the tool was so named.

Demonstration
-------------

This terminal session demonstrates configuring Floor for the first time,
creating a new volume, mounting then using the volume and finally, unmounting
the volume.

    ~$ floor setup
    768B written to ~/.floor.secret
    ~$ floor new disks/test.img 100M
    UUID: 250c4e14-6c72-4ef6-9f77-f63ad1d7d1f7
    creating disk image...
    configuring LUKS...
    formatting device with mkfs.ext4...
    finished creating disks/test.img
    ~$ floor mount disks/test.img mounts/test/
    ~$ floor ls
    MOUNTPOINT  DEVICE          LOOPBACK  FILENAME
    ~/mnt/test  floor-test.img  loop4     ~/disks/test.img
    ~$ vi mounts/test/A_FILE
    ~$ ls -l mounts/test/
    total 165
    -rw------- 1 user user 165 Aug 29 21:32 A_FILE
    ~$ floor unmount disks/test.img
    ~$ ls mounts/test/
    total 0
    ~$ floor ls
    MOUNTPOINT  DEVICE  LOOPBACK  FILENAME
    ~$

Supported Systems
-----------------

The shell script syntax is POSIX-compliant, and any commands used by the script
that are also prescribed by POSIX are only invoked with POSIX-specified command
line arguments / features. The tool should have no problem handling filenames
that contain spaces or start with "-"; please send reports of any such issues.
Floor has been explicitly tested with the following tools on Debian Linux:

Shells:
- [Bash][bash]
- [Debian Almquist Shell (dash)][dash]
- [KornShell][ksh]
- [Z shell][zsh]

Userland Utilities:
- [BusyBox][busybox]
- [GNU Core Utilities][coreutils]
- Suckless [sbase][sbase] and [ubase][ubase]
- [util-linux][util-linux]

Most of the non-POSIX commands invoked by Floor are available by default on
many popular Linux distributions. Commands implemented by more than one
supported toolset have the providers listed after the command name from most to
least commonly available via distro package managers:

- _cryptsetup(8)_
- _dmsetup(8)_
- _mkfs.ext4(8)_ by default but _mkfs.ext2(8)_ and _mkfs.ext3(8)_ can be used.
- _mount(8)_ (util-linux, busybox, ubase)
- _mountpoint(1)_ (util-linux, sbase)
- _openssl(1ssl)_ or _sha512sum(1)_ (coreutils, busybox, sbase)
- _sudo(8)_
- _umount(8)_ (util-linux, busybox, sbase)

Floor has the ability to create a packaged version of itself that includes the
secret. [GNU Privacy Guard (GPG)][gpg] must be installed to encrypt the secret
before baking it into the script, and any system running the packaged script
will need to have GPG installed to decrypt the secret.

  [bash]: https://www.gnu.org/software/bash/
  [dash]: http://gondor.apana.org.au/~herbert/dash/
  [ksh]: http://www.kornshell.org/
  [zsh]: http://www.zsh.org/
  [busybox]: https://busybox.net/
  [coreutils]: https://www.gnu.org/software/coreutils/coreutils.html
  [sbase]: https://core.suckless.org/sbase
  [ubase]: https://core.suckless.org/ubase
  [util-linux]: https://git.kernel.org/pub/scm/utils/util-linux/util-linux.git/
  [gpg]: https://www.gnupg.org/

Installation and Other Make Targets
-----------------------------------

Run `sudo make install` to install the sudoers rules and run the
post-installation tests. The script itself ("floor.sh") can be copied to any
folder in `$PATH`.

Other targets:
- **uninstall:** Delete the sudoers file and the "floorusers" group.
- **post-install-tests:** If the "SUDO_USER" environment variable is not empty,
  run tests as that user that depend on the "install" target. If the "install"
  target has not been run, it will **not** be executed implicitly, and the
  tests will most likely fail.

<!--                            make README.md:                             -->

Usage
-----

Synopsis: `floor COMMAND [OPTION]... [...]`

### Commands ###

#### help [COMMAND_OR_OPTION]... ####

Display documentation and exit. If any command or option names are given as
arguments, only relevant documentation will be displayed. For example, "floor
help package --secret" will display documentation for the "package" command and
the "--secret" option.

#### setup ####

Generate the secret. This command fails if the secret file already exists. This
must be run once before new volumes can be created.

#### sanity ####

Validate the checksum of the secret.

#### new _FILENAME_ _SIZE_ ####

Create a new encrypted volume of a given size. A valid size is an integer with
an optional unit. Valid units are B, K (or k), M, G and T. Images used for loop
devices should have a whole number of 512-byte sectors, so the suffixes are
powers of 1024.

#### key _UUID_OR_FILENAME_ ####

Display the LUKS key for a given UUID or encrypted volume. A newline is only
added if standard output is a TTY making this command suitable for cryptsetup's
"--key-file" option. The user will be prompted for a password if the UUID
version is 0.

#### mount _FILENAME_ _MOUNT_POINT_ ####

Open and mount an encrypted volume.

#### list, ls ####

Display information about all mounted volumes managed by Floor.

#### unmount _IDENTIFIER_, umount _…_ ####

Unmount a volume. The IDENTIFIER can be a loopback device, a /dev/mapper/*
file, mount point or volume path. For loopback and /dev/mapper/* devices, only
the basename needs to be specified, but full paths are also accepted.

#### package _EXPORT_METHOD_ _OUTPUT_FILENAME_ ####

Create a Floor script that has the secret built into it but otherwise functions
like the canonical script. The export method controls how the secret is saved
in the script. Supported methods are "password" which uses GNU Privacy Guard
(GPG) to encrypt the secret with a symmetric key, "gpg" which also uses GPG,
but with arguments defined with "--gpg-args" and "plain" which stores the
secret in unencrypted plain-text.

### Options (and Defaults) ###

#### --help ####

Display documentation and exit. If this option appears after the name of a
command, only the documentation for that command and any other user-supplied
options is displayed. For example, "floor new --password --help" will show the
documentation for the "new" command and the "--password" option.

#### --gpg-args=_ARGUMENTS_ ("--encrypt") ####

Set the command line arguments used with GPG by "package gpg ...".

#### --mkfs=_COMMAND_ ("mkfs.ext4") ####

Command used to create the filesystem of new volumes. Supported values are
"mkfs.ext2", "mkfs.ext3" and "mkfs.ext4".

#### --password ####

In addition to the secret, use a password — effectively a user-provided salt —
when generating a new volume key. The version of the UUIDs of volumes created
with this option enabled will be set to 0 which denotes the use of a password.

#### --random=_FILENAME_ ("/dev/urandom") ####

Source of random data used to generate the secret and UUIDs for new volumes.

#### --root-owner=_UID:GID_ (`$UID:$GID`) ####

Owner of the root directory of newly created volumes. This defaults to the UID
and GID of the current user.

#### --secret=_FILENAME_ (`$HOME/.floor.secret`) ####

File used to store the secret used to generate volume keys. If the value of
this option is an empty string — the default for scripts created with "package"
— or the file does not exist, any operations that depend on the secret will use
the packaged secret if one is defined.

#### --secret-size=_BYTES_ (768) ####

Size in bytes of the secret. This value is only used when the "setup" command
is run. The minimum is 50.

#### --sha512=_COMMAND_ ####

Command for generating SHA-512 hashes. The command must accept data via
standard input and write the hash to standard output. When this option is not
set, the script will set the default value by searching for common programs
that could be used to generate hashes.
