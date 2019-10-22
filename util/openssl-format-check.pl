#!/usr/bin/perl

use strict;

my $line_length_limit = 81;
my $hanging_col = -1;
my $multiline_comment = 0;
my $line = 0;
my $line_with_open_brace_at_end = 0;
my $contents_2_lines_before;

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

    if((length($_) - 1 > $line_length_limit) && !(m/\".*?\"\s*([,;]|\)+|\}+)\s*/)) {
        print "$ARGV:$line:len>$line_length_limit: $_";
    }
    if(m/\s\n$/) {
        print "$ARGV:$line:space\@EOL: $_";
    }
    if(m/[^\s]\s*\{\s*$/ && !m/\}/) {
        $line_with_open_brace_at_end = $line;
        $contents_2_lines_before = $_;
    }
    if(m/\}[\s;]*$/) {
        my $line_2_before = $line-2;
        if($line_with_open_brace_at_end &&
           $line_with_open_brace_at_end == $line_2_before) {
            print "$ARGV:$line_2_before:{1 line}: $contents_2_lines_before";
        }
        $line_with_open_brace_at_end = 0;
    }

    m/^(\s*)(.?)(.?)/;
    my $count = length($1);
    $count-- if ($2 eq ""); # empty line
    $count = 0 if ($2 eq "\\" && $3 eq ""); # ignore indent on line containing just '\'
#   $count = 0 if ($2 eq "/" && $3 eq "*"); # do not ignore indent on line starting comment: '/*'
    $count -= 4 if ($2 eq "&" && $3 eq "&"); # line starting with &&
    $count -= 4 if ($2 eq "|" && $3 eq "|"); # line starting with ||
    my $indent = $count;
    if ($hanging_col == -1) {
        $count-- if (m/^(\s*)([a-z_0-9]+):/ && $2 ne "default"); # label
    }
    if($count %4 != 0 && $indent != $hanging_col) { # well, does not detect indentation off by multiples of 4
        print "$ARGV:$line:indent: $_";
    }

    my $offset = 0;
    if (m/^(.*?)\*\/(.*)$/) { # ending comment: '*/'
        $offset = length($1) + 2;
        $_ = $2;
        $hanging_col = -1;
        $multiline_comment = 0;
    }
    if (m/^(\s*)\/\*-?(.*)$/) { # starting comment: '/*'
        my $head = $1;
        my $tail = $2;
        if ($tail =~ m/\*\/(.*)$/) { # ending comment: */
            $offset = length($head) + 2 + length($tail) - length($1);
            $_ = $1;
            goto NEXT_PAREN;
        } else {
            print "$ARGV:$line:multi-line comment: $_" if $tail =~ m/\S/;
            $hanging_col = length($head) + 1;
            $multiline_comment = 1;
        }
    } else {
      NEXT_PAREN:
        if (!$multiline_comment && m/^(.*)\(([^\(]*)$/) { # last '('
            my $head = $1;
            my $tail = $2;
            if ($tail =~ m/\)(.*)/) { # ignore matching '(' ')'
                $_ = $head.$1;
                goto NEXT_PAREN;
            }
            $hanging_col = $offset + length($head) + 1;
        } elsif ($indent != $hanging_col) {
            $hanging_col = -1; # reset hanging col
        }
    }
    if (!$multiline_comment && $hanging_col == -1 &&
        m/^(\s*)(((\w+|\*)\s*)+=\s*)[^;]*\s*$/) { # multi-line assignment: "[type] var = " without ;
        my $head = $1;
        my $var_eq = $2;
        $hanging_col = length($head) + length($var_eq);
    }

    $line = 0 if eof;
}
