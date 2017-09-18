#!/usr/bin/awk -f
# This script updates README.md using the scripts "help" output. A typical
# invocation looks something like this:
#   $ sed '/^Usage$/,$d' README.md > README.md.tmp
#   $ (... --help && echo "EOF") | awk usage-to-md.awk >> README.md.tmp
#   $ mv README.md.tmp README.md
#
BEGIN {
    MAX_LINE_WIDTH = 79

    print "Usage"
    print "-----"
    print ""
}

# A line indented by two spaces marks the beginning of a command or option
# description, and a line that is not indented at all marks a new section.
/^(  [^ ]|[^ ]|EOF$)/ {
    if (length(description)) {
        print "####", header, "####"
        print ""

        # Print the description wrapped after MAX_LINE_WIDTH characters.
        original_line = $0
        $0 = description

        for (width = word = 0; word++ < NF;) {
            # Replace double dashes that aren't parts of flag names with
            # em-dashes.
            if ($word == "--") {
                $word = "—"
            }

            if (!width && length($word) >= MAX_LINE_WIDTH) {
                print $word
            } else {
                width = width + length($word)
                if (word == 1 || width >= MAX_LINE_WIDTH) {
                    width = length($word)
                    if (word != 1) {
                        print ""
                    }
                    printf "%s", $word
                } else {
                    width = width + 1
                    printf " %s", $word
                }
                if (word == NF) {
                    print ""
                }
            }
        }

        # Restore the line to its original value once the wrapping is done.
        $0 = original_line

        if (/^EOF$/) {
            exit
        }

        printf "\n"
        description = ""
    }

    if (/^[^ ]/) {
        if (/^Usage:/) {
            print "Synopsis: `" substr($0, 8) "`"
        } else {
            gsub(/:$/, "")
            print "###", $0, "###"
        }
        print ""
        next
    }

    if (/^  .*  /) {
        # If there are consecutive spaces after the initial indent, that
        # indicates that the section header is on the same line as the first
        # line of its description.
        header = substr($0, 1, 8)
        description = substr($0, 9)
    } else {
        header = $0
    }

    $0 = header

    # Add some formatting to variables and default values in the section
    # headers to make them stand out.
    for (c = 1; c <= NF; c++) {
        comma = ""
        if ($c ~ /,$/) {
            comma = ","
            $c = substr($c, 1, length($c) - 1)
        }

        # Variables that are meant to be replaced are italicized.
        if ($c ~ /^([A-Z0-9_:]+|\.\.\.)$/) {
            $c = "_" $c "_"
        } else if (match($c, /=[A-Z0-9_:]+$/)) {
            $c = substr($c, 1, RSTART) "_" substr($c, RSTART + 1) "_"

        } else if (c == NF && $c ~ /^[(].*[^0-9].*[)]$/) {
            # Strings that refer to the home directory with "~" are changed to
            # backticks and "~" substituted with a shell variable.
            string = substr($c, 2, length($c) - 2)
            if (string ~ /^~\//) {
                $c = "(`$HOME" substr(string, 2) "`)"

            # Strings with shell variables are quoted with backticks.
            } else if (string ~ /\$/) {
                $c = "(`" string "`)"

            # All other strings get quoted.
            } else {
                $c = "(\"" string "\")"
            }
        }

        $c = ($c == "_..._" ? "_…_" : $c) comma
    }

    header = $0
    gsub(/^ +| +$/, "", header)
    next
}

{
    gsub(/^ +| +$/, "")
    description = length(description) ? description " " $0 : $0
}
