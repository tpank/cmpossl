#!/usr/bin/perl

$line_length_limit = 81;
$hanging_col = -1;
$line = 0;
$line_with_open_brace_at_end = 0;

while(<>) {
    $line++;

    if(m/[\x09]/) {
        print "$ARGV:$line:TAB: $_";
    }
    if(m/[\x0d]/) {
        print "$ARGV:$line:CR: $_";
    }
    if(m/[\x00-\x08\x0B-\x0C\x0E-\x1F]/) {
        print "$ARGV:$line:non-printable: $_";
    }
    if(m/[\x7F-\xFF]/) {
        print "$ARGV:$line:non-ascii: $_";
    }

    if(length($_) - 1 > $line_length_limit) {
        print "$ARGV:$line:len>$line_length_limit: $_";
    }
    if(m/\s\n$/) {
        print "$ARGV:$line:space\@EOL: $_";
    }

    if(m/[^\s]\s*\{\s*$/ && !m/\}/) {
        $line_with_open_brace_at_end = $line;
        $contents_2_before = $_;
    }
    if(m/\}\s*$/) {
        my $line_2_before = $line-2;
        if($line_with_open_brace_at_end &&
           $line_with_open_brace_at_end == $line_2_before) {
            print "$ARGV:$line_2_before:{1}: $contents_2_before";
        }
        $line_with_open_brace_at_end = 0;
    }

    m/^(\s*)(.?)(.?)/;
    my $count = length($1);
    $count-- if ($2 eq ""); # empty line
    $count = 0 if ($2 eq "\\" && $3 eq ""); # ignore indent on line containing just '\'
    $count = 0 if ($2 eq "/" && $3 eq "*"); # ignore indent on line starting '/*'
    $indent = $count;
    if ($hanging_col == -1) {
        $count-- if (m/^(\s*)([a-z_0-9]+):/ && $2 ne "default"); # label
    }
    if($count %4 != 0 && $indent != $hanging_col) { # well, does not indentation that is off by multiples of 4
        print "$ARGV:$line:indent: $_";
    }

    $offset = 0;
    if (m/^(\s*)\*\/(.*)$/) { # ending '*/'
        $offset = length($1) + 2;
        $_ = $2;
        $hanging_col = -1;
    }
    if (m/^(\s*)\/\*(.*)$/) { # starting '/*'
        $head = $1;
        $tail = $2;
        if ($tail =~ m/\*\/(.*)$/) { # ending */
            $offset = length($head) + 2 + length($tail) - length($1);
            $_ = $1;
            goto NEXT_PAREN;
        } else {
            $hanging_col = length($head) + 1;
        }
    } else {
      NEXT_PAREN:
        if (m/^(.*\S)\(([^\(]*)$/) { # last '('
            $head = $1;
            $tail = $2;
            if ($tail =~ m/\)/) { # ignore matching '(' ')'
                $_ = $head;
                goto NEXT_PAREN;
            }
            $hanging_col = $offset + length($head) + 1;
        } elsif ($indent != $hanging_col) {
            $hanging_col = -1;
        }
    }

    $line = 0 if eof;
}
