#!/usr/bin/perl

use strict;

use constant INDENT_LEVEL => 4;
use constant MAX_LENGTH => 80;

my $line = 0;
my $line_opening_brace = 0;
my $contents_2_lines_before;
my $hanging_indent = -1;
my $in_multiline_comment = 0;

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
        print "$ARGV:$line:non-ASCII: $_";
    }

    if((length($_) - 1 > MAX_LENGTH) && !(m/\".*?\"\s*([,;]|\)+|\}+)\s*/)) {
        print "$ARGV:$line:len>".MAX_LENGTH.": $_";
    }
    if(m/\s\n$/) {
        print "$ARGV:$line:SPC\@EOL: $_";
    }
    if(!$in_multiline_comment && m/[^\s]\s*\{\s*$/ && !m/\}/) { # trailing ... {
        $line_opening_brace = $line;
        $contents_2_lines_before = $_;
    }
    if(!$in_multiline_comment && m/\}[\s;]*$/) { # trailing ... }
        my $line_2_before = $line-2;
        if($line_opening_brace &&
           $line_opening_brace == $line_2_before) {
            print "$ARGV:$line_2_before:{1 line}: $contents_2_lines_before";
        }
        $line_opening_brace = 0;
    }

    m/^(\s*)(.?)(.?)/;
    my $count = length($1);
    if (!$in_multiline_comment) {
        $count-- if ($2 eq ""); # empty line
        $count = 0 if ($2 eq "\\" && $3 eq ""); # ignore indent on line containing just '\'
#       $count = 0 if ($2 eq "/" && $3 eq "*"); # do not ignore indent on line starting comment: '/*'
        $count -= INDENT_LEVEL if ($2 eq "&" && $3 eq "&"); # line starting with &&
        $count -= INDENT_LEVEL if ($2 eq "|" && $3 eq "|"); # line starting with ||
    }
    my $indent = $count;
    if (!$in_multiline_comment && $hanging_indent == -1) {
        $count-- if (m/^(\s*)([a-z_0-9]+):/ && $2 ne "default"); # label
    }
    if($count %INDENT_LEVEL != 0 && $indent != $hanging_indent) { # well, does not detect indentation off by multiples of INDENT_LEVEL
        print "$ARGV:$line:indent: $_";
    }

    my $offset = 0;
    if (m/^(.*?)\*\/(.*)$/) { # ending comment: '*/'
        my $head = $1;
        my $tail = $2;
        if (!($head =~ m/\/\*/)) { # starting comment: '/*' handled below
            $offset = length($head) + 2;
            print "$ARGV:$line:... */: $_" if $head =~ m/\S/;
            $_ = $tail;
            $hanging_indent = -1;
            $in_multiline_comment = 0;
        }
    }
    if (m/^(.*?)\/\*-?(.*)$/) { # starting comment: '/*'
        my $head = $1;
        my $tail = $2;
        if ($tail =~ m/\*\/(.*)$/) { # ending comment: */
            $offset = length($head) + 2 + length($tail) - length($1);
            $_ = $1;
            goto NEXT_PAREN;
        } else {
            print "$ARGV:$line:/* ...: $_" if $tail =~ m/\S/;
            $hanging_indent = length($head) + 1;
            $in_multiline_comment = 1;
        }
    } else {
      NEXT_PAREN:
        if (!$in_multiline_comment && m/^(.*)\(([^\(]*)$/) { # last '('
            my $head = $1;
            my $tail = $2;
            if ($tail =~ m/\)(.*)/) { # ignore matching '(' ')'
                $_ = $head.$1;
                goto NEXT_PAREN;
            }
            $hanging_indent = $offset + length($head) + 1;
        } elsif ($indent != $hanging_indent) {
            $hanging_indent = -1; # reset hanging indent
        }
    }
    if (!$in_multiline_comment && $hanging_indent == -1 &&
        m/^(\s*)(((\w+|\*)\s*)+=\s*)[^;]*\s*$/) { # multi-line assignment: "[type] var = " without ;
        my $head = $1;
        my $var_eq = $2;
        $hanging_indent = length($head) + length($var_eq);
    }

    $line = 0 if eof;
}
