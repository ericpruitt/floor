#!/bin/sed -nf
# This script generates sed commands that replace variables in the sudoers
# template.
s/^\([A-Z0-9_]*\)=["']*\([a-zA-Z0-9._:, -]*\)["']*$/s|(\1)|\2|g/
/^s|/ {
    s/\([:,]\)/\\\\\1/g
    p
}
