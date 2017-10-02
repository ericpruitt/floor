.POSIX:
.SILENT: install README.md test-illegal-sudo-commands uninstall

FLOOR = floor.sh

SUDOERS = sudoers

# Users in this group will be allowed to run commands needed by Floor without a
# password. See the WARNING at the top of the "sudoers" file for more
# information.
FLOOR_USERS_GROUP = floorusers

#                                     ---

# Awk script used to update the README.md using Floor's "--help" output.
USAGE_TO_MD_AWK = usage-to-md.awk

# Recipes executed to install Floor.
INSTALL_TARGETS = \
	/etc/sudoers.d/000-floor \

POST_INSTALL_TESTS = \
	test-illegal-sudo-commands \

# The convention used for these commands is that groups of capital "X"s are
# used for arguments or constructs that are invalid to make it easier to
# determine at a glance which parts of the commands are supposed to cause the
# sudoers rules to reject a command.
ILLEGAL_SUDO_COMMANDS = \
	'mount -o noauto,nodev,nosuid /dev/mapper/floor-abc XXX XXX' \
	'mount -o noauto,nodev,nosuid "/dev/mapper/floor- XXX" abc' \
	'mount -o noauto,nodev,nosuid /dev/mapper/floor-abc -XXX' \
	'umount "/dev/mapper/floor- -X"' \
	'umount /dev/mapper/floor- -X' \
	'cryptsetup close XXX XXX' \
	'cryptsetup --key-file=- --key-size=XXX --uuid=12345678-90ab-cdef-0123-4567890abcde luksFormat /dev/loop000' \
	'cryptsetup --key-file=- --key-size=000 --uuid=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX luksFormat /dev/loop000' \
	'cryptsetup --key-file=- --key-size=000 --uuid=12345678-90ab-cdef-0123-4567890abcde luksFormat /dev/loopXXX' \
	'cryptsetup --key-file=- --type=luks open /dev/loop000 XXX XXX' \
	'cryptsetup --key-file=- --type=luks open /dev/loop000 -XXX' \
	'cryptsetup --key-file=- --type=luks open /dev/loopXXX /some/path' \
	'losetup --associated="XXX XXX" --noheadings --output=NAME' \
	'losetup --detach=/dev/loopXXX' \
	'losetup --find --nooverlap --show XXX XXX' \
	'losetup --find --nooverlap --show -XXX' \
	'mkfs.ext4 -E root_owner=XXX:XXX -m 1 -q /dev/mapper/floor-new.abc' \
	'mkfs.ext4 -E root_owner=0:0 -m "XXX XXX" -q /dev/mapper/floor-new.abc' \
	'mkfs.ext4 -E root_owner=0:0 -m 1 -q "/dev/mapper/floor-new-XXX XXX"' \

install:
	if $(MAKE) -q $(INSTALL_TARGETS); then \
		echo "$@: already installed; nothing to do"; \
	else \
		$(MAKE) $(INSTALL_TARGETS); \
		test -n "$(SUDO_USER)" || exit 0; \
		su -c 'sudo -k && $(MAKE) post-install-tests' $(SUDO_USER); \
	fi

uninstall:
	for target in $(INSTALL_TARGETS); do \
		test -e "$$target" || continue; \
		echo "- $$target"; \
		rm "$$target"; \
	done
	if getent group "$(FLOOR_USERS_GROUP)" >/dev/null; then \
		echo "- groupdel $(FLOOR_USERS_GROUP)"; \
		groupdel "$(FLOOR_USERS_GROUP)"; \
	fi

ALWAYS_BUILD:

/etc/sudoers.d/000-floor: $(FLOOR) $(SUDOERS)
	@if ! fgrep -e "%$(FLOOR_USERS_GROUP)" -q -w $(SUDOERS); then \
		echo "$@: no references to the Floor users group" \
		     "(%$(FLOOR_USERS_GROUP)) found in $(SUDOERS)" >&2; \
		exit 1; \
	fi
	groupadd -f "$(FLOOR_USERS_GROUP)"
	@sed "$$(MAIN=false . ./$(FLOOR) && set | ./replacer.sed)" $(SUDOERS) \
	| EDITOR="tee" visudo -f $@
	@$(MAKE) -q $@
	usermod -a -G "$(FLOOR_USERS_GROUP)" "$(SUDO_USER)"

test-illegal-sudo-commands:
	for command in $(ILLEGAL_SUDO_COMMANDS) ; do \
		if eval "LC_ALL=C sudo -k -n $$command" </dev/null 2>&1 \
		  | grep -q 'a password is required\|not allowed'; then \
			echo "PASS: $$command"; \
		else \
			echo "FAIL: $$command" >&2; \
			trap 'exit 1' EXIT; \
		fi; \
	done

post-install-tests: $(POST_INSTALL_TESTS)

README.md: ALWAYS_BUILD
	sed '/^Usage$$/,$$d' README.md > $@.tmp
	(./$(FLOOR) help && echo "EOF") \
	| sed "s:$(FLOOR):floor:g" \
	| awk -f $(USAGE_TO_MD_AWK) >> $@.tmp
	diff -u $@ $@.tmp && echo "$@: file not changed" || mv $@.tmp $@
	rm -f $@.tmp

docs: README.md
