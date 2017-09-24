#!/bin/sh
usage() {
printf "%s" \
"Usage: $SELF COMMAND [OPTION]... [...]

Commands:
  help  Display this documentation and exit.
  setup
        Generate the secret. This command fails if the secret file already
        exists. This must be run once before new volumes can be created.
  sanity
        Validate the checksum of the secret.
  new FILENAME SIZE
        Create a new encrypted volume of a given size. A valid size is an
        integer with an optional unit. Valid units are B, K (or k), M, G and T.
        Images used for loop devices should have a whole number of 512-byte
        sectors, so the suffixes are powers of 1024.
  key UUID_OR_FILENAME
        Display the LUKS key for a given UUID or encrypted volume. A newline is
        only added if standard output is a TTY making this command suitable for
        cryptsetup's \"--key-file\" option. The user will be prompted for a
        password if the UUID version is $UUID_VERSION_IF_NEEDS_PASSWORD.
  mount FILENAME MOUNT_POINT
        Open and mount an encrypted volume.
  list, ls
        Display information about all mounted volumes managed by Floor.
  unmount IDENTIFIER, umount ...
        Unmount a volume. The IDENTIFIER can be a loopback device, a
        /dev/mapper/* file, mount point or volume path. For loopback and
        /dev/mapper/* devices, only the basename needs to be specified, but
        full paths are also accepted.
  package EXPORT_METHOD OUTPUT_FILENAME
        Create a Floor script that has the secret built into it but otherwise
        functions like the canonical script. The export method controls how the
        secret is saved in the script. Supported methods are \"password\" which
        uses GNU Privacy Guard (GPG) to encrypt the secret with a symmetric
        key, \"gpg\" which also uses GPG, but with arguments defined with
        \"--gpg-args\" and \"plain\" which stores the secret in unencrypted
        plain-text.

Options (and Defaults):
  --help
        Display this documentation and exit.
  --gpg-args=ARGUMENTS ($DEFAULT_GPG_ARGS)
        Set the command line arguments used with GPG by \"package gpg ...\".
  --mkfs=COMMAND ($DEFAULT_MKFS)
        Command used to create the filesystem of new volumes. Supported values
        are \"mkfs.ext2\", \"mkfs.ext3\" and \"mkfs.ext4\".
  --password
        In addition to the secret, use a password -- effectively a
        user-provided salt -- when generating a new volume key. The version of
        the UUIDs of volumes created with this option enabled will be set to
        $UUID_VERSION_IF_NEEDS_PASSWORD which denotes the use of a password.
  --random=FILENAME ($DEFAULT_RANDOM)
        Source of random data used to generate the secret and UUIDs for new
        volumes.
  --root-owner=UID:GID (\$UID:\$GID)
        Owner of the root directory of newly created volumes. This defaults to
        the UID and GID of the current user.
  --secret=FILENAME ($(short_home "$DEFAULT_SECRET"))
        File used to store the secret used to generate volume keys. If the
        value of this option is an empty string -- the default for scripts
        created with \"package\" -- or the file does not exist, any operations
        that depend on the secret will use the packaged secret if one is
        defined.
  --secret-size=BYTES ($DEFAULT_SECRET_SIZE)
        Size in bytes of the secret. This value is only used when the \"setup\"
        command is run. The minimum is $MINIMUM_SECRET_SIZE.
  --sha512=COMMAND
        Command for generating SHA-512 hashes. The command must accept data via
        standard input and write the hash to standard output. When this option
        is not set, the script will set the default value by searching for
        common programs that could be used to generate hashes.
"
}

test "${ZSH_NAME:-sh}" = "sh" || exec -a sh /proc/self/exe "$0" "$@"
set -e -u
export LC_ALL="C"
umask 0077

# Some of the commands used by this script are located in folders generally
# reserved for superuser commands even though some of their features can be
# used without being root.
PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"

# Miscellaneous variables that should generally never be changed:
#
# - This text is added to filenames to indicate they are used by or managed by
#   this script.
readonly FILENAME_PREFIX="floor"
# - The size used for the generating secret cannot be set below this value. The
#   UUID consists of 118 bits of randomly generated data, and a secret of 50
#   bytes totals 518 bits of entropy which is about the same length as the
#   512-bit LUKS master key.
readonly MINIMUM_SECRET_SIZE=50
# - Options used when mounting a volume.
readonly MOUNT_OPTIONS="-o noauto,nodev,nosuid"
# - Checksum of the secret packaged with this script. This will be an empty
#   string if there is no packaged secret.
readonly SECRET_CHECKSUM=""
# - Command used to invoke this script.
readonly SELF="${0##*/}"
# - Volumes that have passwords have the UUID version set to this value so
#   Floor knows to prompt for a password when mounting the volume. This value
#   should not be changed since existing volumes would need their UUIDs
#   updated.
readonly UUID_VERSION_IF_NEEDS_PASSWORD=0
# - This is used as a test vector to verify that the "checksum" function works
#   as expected.
readonly ZERO_LENGTH_INPUT_SHA512="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
# - User ID and group ID. Since the shell may set these, they are only set if
#   they are not already defined.
test "${GID+defined}" || readonly GID="$(id -g)"
test "${UID+defined}" || readonly UID="$(id -u)"

# When the script has been packaged with a secret, it should be used by
# default, so the default value of "--secret" is changed to an empty string.
test "$SECRET_CHECKSUM" || DEFAULT_SECRET="$HOME/.$FILENAME_PREFIX.secret"

# In the descriptions below, let `$SUFFIX` be a command line option
# capitalized, stripped of its leading dashes and any remaining dashes replaced
# with underscores:
#
# - Variables for options that require arguments use the form `OPTION_$SUFFIX`.
#   These can be initialized with any value including empty strings.
OPTION_GPG_ARGS="${DEFAULT_GPG_ARGS:=--encrypt}"
OPTION_MKFS="${DEFAULT_MKFS:=mkfs.ext4}"
OPTION_RANDOM="${DEFAULT_RANDOM:=/dev/urandom}"
OPTION_ROOT_OWNER="$UID:$GID"
OPTION_SECRET="${DEFAULT_SECRET:=}"
OPTION_SECRET_SIZE="${DEFAULT_SECRET_SIZE:=768}"
OPTION_SHA512=""
#
# - For other all options, the variables use the form `IS_SET_$SUFFIX`. The
#   IS_SET_... variables should only be initialized as empty strings.
IS_SET_HELP=""
IS_SET_PASSWORD=""

#                                     ---

# Write a message to standard error with the program name prepended then finish
# with a non-zero return code.
#
# Arguments:
# - $@: Optional message to display. If this argument is not specified or is a
#   zero-length string, the program will exit silently but still
#   unsuccessfully.
#
die()
{
    test -z "${1:-}" || say "$SELF:" "$@" >&2 && exit 1
}

# Display a message without adding a terminating newline.
#
# $1: Message to display.
#
raw()
{
    printf "%s" "$1"
}

# Display text. This works like echo, but it does not support any command line
# options (e.g. "-e" or "-n") or escape sequences.
#
say()
{
    case "$#" in
      0) printf "\n" ;;
      1) printf "%s\n" "$1" ;;
      *) printf "%s" "$1" && shift && printf " %s" "$@" && printf "\n" ;;
    esac
}

# Generate and display a shell-safe representation of a string. The new string
# is **not** quoted, just munged.
#
# Arguments:
# - $1: String to be munged.
#
munge()
(
    name="$1"

    test -n "$name" || die "cannot munge empty string"
    name="$(raw "$name" | tr -d " \t\r\n" | sed "s/^-*//")"
    say "${name:-x}"
)

# Quieter version of _dd(1)_ that only writes to standard error if there is a
# problem. This should only be used with an "of" operand that is not standard
# output.
#
# Arguments:
# - $@: See _dd(1)_.
#
dd()
(
    stderr="$(command dd "$@" 2>&1 >/dev/null)" && return
    dd_exit_status="$?"
    printf "%s\n" "$stderr" >&2
    return "$dd_exit_status"
)

# Helper function for defining commands that should run when a shell exits. It
# suppresses all output and loosens error checking since failures in the
# cleanup process are generally unimportant.
#
# Arguments:
# - $1: Shell command / script to execute at exit.
#
atexit()
{
    test "${1:--}" = "-" && trap - EXIT INT && return
    trap "set +e +u; exec >/dev/null 2>&1; { ${1%;}; } || true" EXIT INT
}

# Compute the SHA-512 hash of a file and display it.
#
# Arguments:
# - $1: Optional argument that is the name of the file to be hashed. When this
#   argument is unspecified, data is read from standard input.
#
checksum()
(
    if [ "${1:--}" = "-" ]; then
        test -t 0 && die "checksum: standard input is a terminal"
    elif ! [ -e "$1" ]; then
        die "checksum: $1: file not found"
    elif [ -d "$1" ]; then
        die "checksum: $1: argument cannot be a folder"
    fi

    eval "cat $(test -z "${1-}" || say '"$1"')" \
    | sh -c " $OPTION_SHA512" \
    | awk -v SHA512="$OPTION_SHA512" '
        BEGIN {
            exit_status = 1
        }

        {
            for (i = 1; i <= NF; i++) {
                if (length($i) == 128 && $i ~ /^[a-fA-F0-9]+$/) {
                    printf "%s", tolower($i)
                    exit_status = 0
                    break
                }
            }
        }

        END {
            if (!exit_status) {
                exit
            }

            print "checksum: no hash in output of \"" SHA512 "\"" > "/dev/fd/2"
            close("/dev/fd/2")
            exit exit_status
        }
    '
)

# Write the contents of the packaged secret to standard output. If no secret
# has been packaged with the script, this function will fail.
#
packaged_secret()
{
    test "$SECRET_CHECKSUM" || die "$0: no secret packaged with script"
}

# Write the secret data to standard output. If "OPTION_SECRET" a non-empty
# string, the contents of the file it names are used as the secret data. If
# "OPTION_SECRET" is an empty string, the secret packaged with the script is
# used. This function will fail if "OPTION_SECRET" names a file that does not
# exist and there is no packaged secret or if the checksum of the secret data
# does not match the expected value.
#
get_secret()
{
    if [ -e "$OPTION_SECRET" ]; then
        if [ "$(checksum "$OPTION_SECRET")" = \
          "$(cat "$OPTION_SECRET.checksum")" ]; then
            cat "$OPTION_SECRET"
        else
            die "$OPTION_SECRET: secret checksum does not match expected value"
        fi
    elif [ -z "$SECRET_CHECKSUM" ]; then
        die "missing secret file, and no packaged secret found"
    elif [ "$(packaged_secret | checksum)" = "$SECRET_CHECKSUM" ]; then
        packaged_secret
    else
        die "packaged secret's checksum does not match expected value"
    fi
}

# Make secret that will be used used for generating volume key.
#
# Arguments:
# - $1: File containing random data.
#
make_secret()
(
    test -d "$OPTION_SECRET" && die "$OPTION_SECRET: secret cannot be a folder"
    test ! -e "$OPTION_SECRET" || die "$OPTION_SECRET: file already exists"

    if [ -z "${OPTION_SECRET_SIZE##*[!0-9]*}" ] ||
      [ "$OPTION_SECRET_SIZE" -lt "$MINIMUM_SECRET_SIZE" ]; then
        die "invalid secret size; need an integer >= $MINIMUM_SECRET_SIZE"
    fi

    atexit 'rm -f "$temp_file"'
    temp_file="$OPTION_SECRET.tmp"
    dd if="$OPTION_RANDOM" of="$temp_file" bs="$OPTION_SECRET_SIZE" count=1

    size="$(ls -l "$temp_file" | awk '{print $5}')"
    if ! [ "${size##*[!0-9]*}" ] || [ "$size" -ne "$OPTION_SECRET_SIZE" ]; then
        die "generated secret was ${size}B instead of ${OPTION_SECRET_SIZE}B"
    fi

    checksum "$temp_file" > "$OPTION_SECRET.checksum"
    mv "$temp_file" "$OPTION_SECRET"
)

# Normalize a UUID by deleting dashes, newlines and making all letters
# lowercase then display the result.
#
# Arguments:
# - $1: UUID. If this argument is not a valid UUID, this function will fail.
#
normalize_uuid()
(
    maybe_uuid="$1"

    uuid="$(say "$maybe_uuid" | tr "A-F" "a-f" | tr -d "-")"

    case "$uuid" in
      *[!0-9a-f]*)
        die "$maybe_uuid: not a UUID; one or more invalid characters found"
      ;;
      ????????????????????????????????)
        say "$uuid"
      ;;
      *)
        die "$maybe_uuid: not a UUID; incorrect length"
      ;;
    esac
)

# Generate a random UUID and display it.
#
# Arguments:
# - $1: Value used for the UUID version. This function is technically only
#   capable of generating version 4 UUIDs, but the value is allowed to be
#   overridden as a means of embedding metadata. The version cannot be 1, 2, 3
#   or 5, versions of commonly used / standardized means of generating UUIDs.
#
uuid()
(
    version="$1"

    if [ -z "${version##*[!0-9]*}" ] || [ "$version" -lt 0 ] ||
      [ "$version" -gt 15 ]; then
        die "uuid: the UUID version must be an integer 0 through 15, inclusive"
    fi

    case "$((version))" in
      [1235])
        die "uuid: this function cannot generate version $version UUIDs"
      ;;
    esac

    chunk_number=0
    uuid=""
    version="$((version * 4096))"

    for bytes in 4 2 2 2 6; do
        chunk_number="$((chunk_number + 1))"
        chunk="$(printf %02x $(od -A n -N "$bytes" -t u1 -v "$OPTION_RANDOM"))"
        case "$chunk_number" in
          # Set UUID version.
          3)
            chunk="$(printf "%04x" "$((0x$chunk & 0x0fff | version))")"
          ;;
          # Set UUID variant to 1.
          4)
            chunk="$(printf "%x" "$((0x$chunk & 0x3fff | 0x8000))")"
          ;;
        esac

        uuid="$uuid$chunk"
        test "$chunk_number" -eq 5 || uuid="$uuid-"
    done

    normalize_uuid "$uuid" >/dev/null || die "uuid: generated invalid UUID"
    say "$uuid"
)

# Display the version of a given UUID.
#
# Arguments:
# - $1: UUID.
#
uuid_version()
(
    uuid="$(normalize_uuid "$1")"

    say "$((0x$(say "$uuid" | cut -b 13) & 0xf))"
)

# Get a password (user-provided salt) and write it to standard output.
#
#
# Arguments:
# - $1: Mode of operation:
#   - If the mode is "noop", this function generates no output.
#   - If standard input is not a terminal, the data from standard input is
#     copied to standard output verbatim.
#   - If standard input is a terminal and the mode is "prompt", the user is
#     prompted to enter the password once. If the mode is "confirm", the user
#     will be asked to enter the password a second time to confirm the choice.
#
getpass()
(
    mode="$1"

    case "$mode" in
      prompt|confirm|noop) ;;
      *)
        die "getpass: \"$mode\" is not a recognized mode"
      ;;
    esac

    test "$mode" = "noop" && return
    test -t 0 || exec cat
    atexit "stty $(stty -g)"

    stty -echo
    raw "Password: " >&2
    read -r password
    say >&2
    test -n "$password" || die "no password entered"

    if [ "$mode" = "confirm" ]; then
        raw "Re-enter password to confirm: " >&2
        read -r password2
        say >&2
        test "$password" = "$password2" || die "the passwords did not match"
    fi

    raw "$password"
)

# Compute the key for a given UUID and display it.
#
# Arguments:
# - $1: UUID.
# - $2: Boolean value indicating if a new volume is being created. This affects
#   if and how the user is prompted for a password.
#
key_for_uuid()
(
    uuid="$(normalize_uuid "$1")"
    is_new="$2"

    uuid_version="$(uuid_version "$uuid")"

    case "$is_new:$uuid_version" in
      0:$UUID_VERSION_IF_NEEDS_PASSWORD)    getpass_mode="prompt" ;;
      1:$UUID_VERSION_IF_NEEDS_PASSWORD)    getpass_mode="confirm" ;;
      [01]:[0-9]|[01]:1[0-5])               getpass_mode="noop" ;;
      *)
        die "invalid UUID version ($uuid_version) / newness ($is_new)"
      ;;
    esac

    if [ "$getpass_mode" != "noop" ]; then
        no_password="$({ raw "$uuid" && get_secret; } | checksum)"
    fi

    no_secret="$(raw "$uuid" | checksum)"
    key="$({ raw "$uuid" && getpass "$getpass_mode" && get_secret
           } | checksum)"

    if [ "$key" = "$no_secret" ]; then
        die "could not generate volume key"
    elif [ "$key" = "${no_password:-}" ]; then
        die "password read from standard input was empty"
    fi

    raw "$key"
)

# Create a new encrypted volume.
#
# Arguments:
# - $1: Volume filename. If the file already exists, this function will fail.
# - $2: Volume size with an optional unit. Valid units are B, K (or k), M, G
#   and T.
#
create_volume()
(
    path="$1"
    size="$2"

    case "$OPTION_MKFS" in
      mkfs.ext[234]) ;;
      *)
        die "$OPTION_MKFS: unsupported filesystem type"
      ;;
    esac

    case "${size%[BKkMGT]}" in
      *[!0-9]*|"")
        die "$size: not a valid size"
      ;;
    esac

    # POSIX specifies that "only signed long integer arithmetic is required"
    # for shells, and section 5.2.4.2.1 of ISO/IEC 9899:1999 (C99) specifies
    # that LONG_MAX must be at least (2^31 - 1). The comments after each unit
    # conversion show the largest file size that each suffix can represent on
    # systems that **minimally** conform to those standards; most modern,
    # 64-bit systems can support much larger sizes.
    count="${size%[BKkMGT]}"
    suffix="${size#"$count"}"
    case "${suffix:=B}" in
      B)    test "$((count % 512))" -eq 0 || die "$size: not a multiple 512B"
                                                       # TiB GiB MiB
                                                       # --- --- ---~,
            bs=512;   count="$((count / bs))"       ;; #       2,047 /   2G[G!]
     [Kk])  bs=1024;                                ;; #   2,097,151 /   2T
      M)    bs=65536; count="$((count * 16))"       ;; # 134,217,727 / 134T
      G)    bs=65536; count="$((count * 16384))"    ;; # 131,071     / 131T
      T)    bs=65536; count="$((count * 16777216))" ;; # 127         / 127T
    esac

    test "$count" -ge 0 || die "the size \"$size\" caused an integer overflow"
    (set -o noclobber && > "$path")
    atexit 'rm -f "$path" "$symlink"
            sudo -n cryptsetup close "$dm_device"
            sudo -n losetup --detach="$loopback"'

    uuid="$(uuid $((IS_SET_PASSWORD ? UUID_VERSION_IF_NEEDS_PASSWORD : 4)))"
    key="$(key_for_uuid "$uuid" 1)"
    say "UUID: $uuid"

    say "creating disk image..."
    dd if="/dev/urandom" of="$path" bs="$bs" count="$count"

    # If the volume path contains spaces, create a symlink to it immediately
    # under $HOME. The symlink is always deleted since losetup will resolve it
    # to its real path as part of the mounting process.
    symlink="$HOME/.$FILENAME_PREFIX.tmp-$$-$uuid"
    case "$path" in
      /*[[:space:]]*)   ln -s "$path" "$symlink" ;;
      *[[:space:]]*)    ln -s "$PWD/$path" "$symlink" ;;
      *)                unset symlink ;;
    esac

    loopback="$(sudo -n losetup --find --nooverlap --show "${symlink:-$path}")"

    say "configuring LUKS..."
    raw "$key" \
    | sudo -n cryptsetup --key-file="-" --key-size=512 --uuid="$uuid" \
        luksFormat "$loopback"

    say "formatting device with $OPTION_MKFS..."
    basename="$(basename "$path")"
    dm_device="$FILENAME_PREFIX-$uuid"
    raw "$key" \
    | sudo -n cryptsetup --key-file="-" --type="luks" \
        open "$loopback" "$dm_device"

    sudo -n "$OPTION_MKFS" -E root_owner="$OPTION_ROOT_OWNER" -m 0 -q \
        "/dev/mapper/$dm_device"

    displayed_path="$(short_home "$path")"
    unset path
    say "finished creating $displayed_path"
)

# Open and mount an encrypted volume.
#
# - $1: Volume filename.
# - $2: Mount point.
#
mount_volume()
(
    path="$1"
    mount_point="$2"

    volume_basename="$(munge "$(basename "$path")")"
    device_prefix="$FILENAME_PREFIX-$volume_basename"

    test -e "$mount_point" || die "$mount_point: path does not exist"
    test -d "$mount_point" || die "$mount_point: not a directory"
    mountpoint -q "$mount_point" && die "$mount_point: already a mount"

    atexit 'rm -f "$symlink"
            sudo -n cryptsetup close "$dm_device"
            sudo -n losetup --detach="$loopback"'

    # Support volume paths with whitespace. Copied from new_volume; see
    # comments there for details.
    symlink="$HOME/.$FILENAME_PREFIX.tmp-$$-$volume_basename"
    case "$path" in
      /*[[:space:]]*)   ln -s "$path" "$symlink" ;;
      *[[:space:]]*)    ln -s "$PWD/$path" "$symlink" ;;
      *)                unset symlink ;;
    esac

    loopback="$(sudo -n losetup --find --nooverlap --show "${symlink:-$path}")"
    volume_action status "$loopback" && die "$path: volume is already open"

    uuid="$(cryptsetup luksUUID "$path")"
    key="$(key_for_uuid "$uuid" 0)"

    # These suffixes are used to resolve name conflicts when multiple mounted
    # volumes have the same basename.
    suffixes="
        .2 .3
        $(printf "\055${LOGNAME:-${USER:-$UID}}.%d " 4 5 6)
        $(date "+.%Y-%m-%dT%H:%M:%S%Z")
    "

    # Support mount points paths with whitespace.
    rm -f "${symlink:-}"
    symlink="$HOME/.$FILENAME_PREFIX.tmp-$$-$volume_basename-mount"
    case "$mount_point" in
      /*[[:space:]]*)   ln -s "$mount_point" "$symlink" ;;
      *[[:space:]]*)    ln -s "$PWD/$mount_point" "$symlink" ;;
      *)                unset symlink ;;
    esac

    for suffix in "" $suffixes; do
        test -e "/dev/mapper/$device_prefix$suffix" && continue

        cryptsetup_exit_status=0
        dm_device="$device_prefix$suffix"
        raw "$key" \
        | sudo -n cryptsetup --key-file="-" --type="luks" \
            open "$loopback" "$dm_device" || cryptsetup_exit_status="$?"

        # Exit status 5 is "device already exists" which generally means
        # there's a name conflict, so a new suffix should be tried. Run "unset
        # dm_device" so the existing device won't be closed by the atexit code.
        test "$cryptsetup_exit_status" -eq 5 && unset dm_device && continue

        test "$cryptsetup_exit_status" -eq 0 || return
        sudo -n mount $MOUNT_OPTIONS "/dev/mapper/$dm_device" \
            "${symlink:-$mount_point}"
        unset dm_device
        return
    done

    die "unable to generate a unique device name for $(short_home "$path")"
)

# Check to see if two paths represent the same file. This function fails if the
# files are not the same or if there was an error. If the "test" command
# supports the "-ef" (exists and is the same file) operator, it will be used to
# do the file comparisons. Otherwise, files are considered the same if they
# have the same inode number, size and modification time based on information
# reported by _ls(1)_ which has the potential return false positives.
#
# Arguments:
# - $1: Filename.
# - $2: Filename.
#
same_file()
(
    path_1="$1"
    path_2="$2"

    if test / -ef / >/dev/null 2>&1; then
        test "$path_1" -ef "$path_2" && exit || exit
    fi

    # The "sub(/, +/)" gets rid of spaces in <device info> which is
    # implementation-defined by POSIX but is "<major>, <minor>" device numbers
    # in popular ls(1) implementations.
    ls -d -H -i -L -n -- "$path_1" "$path_2" 2>/dev/null \
    | awk '{sub(/, +/, ","); stats[++files] = $1 " " $6 " " $7 " " $8 " " $9}
           END {exit files != 2 || stats[1] != stats[2]}'
)

# Replace a leading `$HOME/` with "~/" in a filename and display the result.
# Filenames that don't begin with `$HOME/` will be displayed unmodified.
#
# Arguments:
# - $1: Filename.
#
short_home()
(
    path="$1"

    HOME="${HOME%/}/"
    test -n "${path##"$HOME"*}" && say "$path" || say "~/${path#"$HOME"}"
)

# Generate a copy of this script that has the secret built into it.
#
# Arguments:
# - $1: Secret export method which controls how the secret is stored inside the
#   new script. This can be "plain" (unencrypted plain-text) "password"
#   (encrypted with a user-defined password) or "gpg" (encrypted with GPG using
#   with user-configurable flags).
# - $2: Output path for the generated script.
#
package()
(
    secret_export_method="$1"
    path="$2"

    case "$secret_export_method" in
      gpg)      filter='| gpg --quiet $OPTION_GPG_ARGS' ;;
      password) filter="| gpg --quiet --symmetric --no-default-recipient" ;;
      plain)    filter="" ;;

      *)
        die "dump_secret: unknown export method \"$secret_export_method\""
      ;;
    esac

    (set -o noclobber && > "$path")
    atexit 'rm -f "$path"'
    chmod 700 "$path"

    checksum="$(get_secret >/dev/null && get_secret | checksum)"
    bytes="$(eval "get_secret $filter | od -A n -t u1 -v")"
    test -n "$bytes"

    command="printf '$(printf '\\\\%03o' $bytes)'"
    case "$filter" in
      *gpg*)
        command="$command | gpg --decrypt --quiet"
      ;;
    esac

    sed -f /dev/fd/0 "$0" > "$path" << ____SED
    # Fill in the value of SECRET_CHECKSUM.
    s/^\\(readonly SECRET_CHECKSUM=\\).*$/\\1"$checksum"/

    # Add the command for writing the secret to packaged_secret.
    /^packaged_secret()$/,/^[})]$/ {
        /printf/d
        / die /{
            a\\
            $command
        }
    }
____SED

    chmod 500 "$path"
    uuid="$(uuid 4)"
    expected_key="$(key_for_uuid "$uuid" 0)"
    displayed_path="$(short_home "$path")"

    atexit -
    say "testing the packaged script..."
    test -z "${path##*/*}" || path="$PWD/$path"
    key="$("$path" --secret="" key "$uuid")"

    if [ "$key" != "$expected_key" ]; then
        die "sanity check error: the key generated by the original script" \
            "and the new script for UUID $uuid differ; the broken script" \
            "will not be deleted since it may be needed to debug the problem"
    fi

    say "no problems detected; packaged script written to $displayed_path"
)

# Check to see if a block device is mounted. If the device is mounted, this
# function returns successfully and fails otherwise.
#
# Arguments:
# - $1: Path to the block device.
#
device_mounted()
(
    device="$1"

    ! awk -v device="$device" '$1 == device {exit 1}' /proc/self/mounts
)

# Search for a volume and potentially do something with it.
#
# Arguments:
# - $1: Action / mode of operation. This can be "unmount" to unmount a volume
#   or "status" which will make function silently finish successfully if the
#   volume is mounted and fail otherwise.
# - $2: A filename, mount point, LVM device name or loopback device name for
#   the volume being closed.
#
volume_action()
(
    action="$1"
    identifier="$2"

    case "$action" in
      unmount)
        error="no mounted volumes associated with \"$identifier\" were found"
      ;;
      status)
        error=""
      ;;
      *)
        die "volume_action: unknown action \"$action\""
      ;;
    esac

    list_mounted_volumes 0 | (
      while read -r mountpoint device loopback filename; do
        # Use printf to handle procfs's octal escapes.
        mountpoint="$(printf "$mountpoint\n")"

        device="/dev/mapper/$device"
        loopback="/dev/$loopback"

        if same_file "$identifier" "$filename" ||
           same_file "$identifier" "$mountpoint" ||
           same_file "/dev/mapper/$identifier" "$device" ||
           same_file "$identifier" "$device" ||
           same_file "/dev/$identifier" "$loopback" ||
           same_file "$identifier" "$loopback"; then

            if [ "$action" = "unmount" ]; then
                device_mounted "$device" && sudo -n umount "$device"
                test -e "$device" && sudo -n cryptsetup close "$device"
            fi

            exit 255
        fi
      done
    ) && die "$error" || test "$?" -eq 255
)

# Display information about all mounted volumes.
#
# Arguments:
# - $1: When this value is non-zero, headers are added to the output, and paths
#   relative to the user's home directory will be abbreviated with "~/".
#
list_mounted_volumes()
(
    formatted="$1"

    exec \
     awk -v filename_prefix="$FILENAME_PREFIX" -v formatted="$formatted" '
      BEGIN {
        DMSETUP_LS = "sudo -n dmsetup ls --target=crypt"
        HOME = length(ENVIRON["HOME"]) ? ENVIRON["HOME"] : "/dev/null"
        sub("/*$", "/", HOME)

        while ((getline < "/proc/self/mounts") == 1) {
            if (formatted && index($2, HOME) == 1) {
                $2 = "~" substr($2, length(HOME))
            }
            MOUNTPOINTS[$1] = $2
        }

        # The first three fields are guaranteed to not contain whitespace, but
        # the that is not true for the filename. The filename is displayed last
        # so the read shell built-in is more likely to process it correctly.
        if (formatted) {
            lines[++lineno] = "MOUNTPOINT DEVICE LOOPBACK FILENAME"
        }

        while (DMSETUP_LS | getline) {
            if (!index($0, filename_prefix "-")) {
                continue
            }

            dm_device = $1
            cryptsetup_status = "sudo -n cryptsetup status " dm_device

            while (cryptsetup_status | getline) {
                if ($1 == "loop:") {
                    filename = substr($0, index($0, "/"))
                    if (formatted && index(filename, HOME) == 1) {
                        filename = "~" substr(filename, length(HOME))
                    }
                } else if ($1 == "device:") {
                    loopback = substr($2, 6)  # Strip "/dev/"
                }
            }

            close(cryptsetup_status)
            dev_mapper = "/dev/mapper/" dm_device
            mount = dev_mapper in MOUNTPOINTS ? MOUNTPOINTS[dev_mapper] : "?"
            lines[++lineno] = mount " " dm_device " " loopback " " filename
        }

        if (formatted) {
            for (lineno in lines) {
                $0 = lines[lineno]
                width[1] = width[1] < length($1) ? length($1) : width[1]
                width[2] = width[2] < length($2) ? length($2) : width[2]
                width[3] = width[3] < length($3) ? length($3) : width[3]
            }
            format = "%-" width[1] "s  %-" width[2] "s  %-" width[3] "s  %s\n"
        } else {
            format = "%s %s %s %s\n"
        }

        for (lineno in lines) {
            $0 = lines[lineno]
            printf format, $1, $2, $3, substr($0, length($1 $2 $3) + 4)
        }

        close(DMSETUP_LS)
        exit
    }'
)

# Verify that a command is called with the correct number of non-empty
# arguments and assign the ARGV... values to user-friendly variable names.
#
# Arguments:
# - $@: Argument descriptions. These are transformed into a variable name with
#   `printf "%s" "$1" | tr "A-Z -" "a-z__"`.
#
check_usage()
{
    if [ "$ARGN" -ne "$#" ]; then
        die "Usage: $SELF $ARGV0" $(printf "%s\n" "$@" | tr "a-z -" "A-Z__") \
            "-- $# argument$(test "$#" -eq 1 || say "s") needed, not $ARGN"
    fi

    while [ "$#" -gt 0 ]; do
        eval 'test "$ARGV'$((ARGN - $# + 1))'"' || die "$1 cannot be empty"
        eval "$(say "$1" | tr "A-Z -" "a-z__")=\"\$ARGV$((ARGN - $# + 1))\""
        shift
    done
}

# Parse the command line arguments and set the corresponding script variables.
#
argparse()
{
    ARGC=0

    while [ "$#" -gt 0 ]; do
        arg="$1" && shift

        case "${options_done:-}$arg" in
          [!-]*|"") eval "ARGV$ARGC="'"$arg"'
                    ARGC="$((ARGC + 1))"
                    continue ;;
          --)       options_done=1; continue ;;
          --?*=*)   no_arg=""; flag="${arg%%=*}" ;;
          *)        no_arg=1; flag="$arg" ;;
        esac

        # This generate a whitespace separated list of the valid flag names
        # with options that take arguments ending in "=" while toggles end in
        # "?" e.g. "OPTION_ABC IS_SET_XYZ" become "--abc= --xyz?".
        test "${optspec+defined}" || optspec="$(
            set \
            | sed -n -e 's/^OPTION_\([^=]*\)=.*/--\1=/p' \
                     -e 's/^IS_SET_\([^=]*\)=.*/--\1?/p' \
            | tr "A-Z_\n" "a-z- "
        )"

        # The value of "$no_arg" causes certain patterns to (not) much which is
        # used to determine if a flag is valid and how to handle setting its
        # value.
        suffix="$(say "${flag#??}" | tr a-z- A-Z_)"
        case " $optspec " in
          *" $flag$no_arg? "*)  die "$flag: no argument required" ;;
          *" $flag? "*)         eval "IS_SET_$suffix=1"; continue ;;
          *" $flag$no_arg= "*)  value="${arg#--*=}" ;;
          *" $flag= "*)
            test "$#" -gt 0 || die "$flag: missing argument"
            value="$1" && shift
          ;;
          *) die "$flag: unrecognized option" ;;
        esac

        case "$value" in
          -*)
            value="./$value"
          ;;
        esac

        eval "OPTION_$suffix="'"$value"'
    done

    ARGN="$((ARGC - 1))"
    unset arg flag no_arg options_done optspec suffix value
    test "$IS_SET_HELP" || return 0
    usage
}

main()
(
    argparse "$@"

    test "$ARGC" -ge 1 || die "no command given; try \"$SELF help\""

    if [ -n "$OPTION_SHA512" ]; then
        : # User provided an SHA-512 command.
    elif command -v openssl >/dev/null 2>&1; then
        OPTION_SHA512="openssl dgst -sha512"
    elif command -v sha512sum >/dev/null 2>&1; then
        OPTION_SHA512="sha512sum"
    fi

    if [ "$(printf "" | checksum)" != "$ZERO_LENGTH_INPUT_SHA512" ]; then
        die "\"$OPTION_SHA512\" did not output correct hash for test vector"
    fi

    case "$ARGV0" in
      help)
        usage
      ;;

      setup)
        check_usage

        make_secret
        say "${OPTION_SECRET_SIZE}B written to $(short_home "$OPTION_SECRET")"
      ;;

      sanity)
        check_usage

        get_secret > /dev/null
        if [ "$OPTION_SECRET" ]; then
            say "$OPTION_SECRET: no problems detected"
        else
            say "no problems detected with packaged secret"
        fi
      ;;

      new)
        check_usage "volume path" "size"

        if [ -z "$OPTION_SECRET" ] && [ "$SECRET_CHECKSUM" ]; then
            say "$SELF: WARNING: This volume will be created using a secret" \
                 "that has been packaged into $(short_home "$0")" >&2
        fi
        create_volume "$volume_path" "$size"
      ;;

      key)
        check_usage "UUID or filename"

        if ! [ -e "$uuid_or_filename" ]; then
            uuid="$uuid_or_filename"
        elif ! uuid="$(cryptsetup luksUUID "$uuid_or_filename")"; then
            text="$uuid_or_filename: unable to retrieve LUKS UUID"
            test -r "$uuid_or_filename" && text="$text; is it a LUKS volume?"
            die "$text"
        fi

        key_for_uuid "$uuid" 0
        test ! -t 1 || say
      ;;

      mount)
        check_usage "volume path" "mount point"

        mount_volume "$volume_path" "$mount_point"
      ;;

      list|ls)
        check_usage

        list_mounted_volumes 1
      ;;

      umount|unmount)
        check_usage "identifier"

        volume_action unmount "$identifier"
      ;;

      package)
        check_usage "export method" "output filename"

        package "$export_method" "$output_filename"
      ;;

      *)
        die "$ARGV0: unknown command"
      ;;
    esac
)

# Run the main function if $MAIN is true or unset.
! "${MAIN:-true}" || main "$@"
