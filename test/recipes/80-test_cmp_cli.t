#! /usr/bin/env perl
# Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use POSIX;
use File::Spec::Functions qw/devnull catfile/;
use File::Copy;
use OpenSSL::Test qw/:DEFAULT with pipe srctop_dir/;
use OpenSSL::Test::Utils;

setup("test_cmp_cli");

plan skip_all => "CMP is not supported by this OpenSSL build"
    if disabled("cmp");


my @cmp_basic_tests = (
    [ "output help",
      [ "-help"],
      0
    ],
    [ "unknown CLI parameter",
      [ "-asdffdsa"],
      1
    ],
);

my $cmpdir=srctop_dir("test", "cmp-tests");
# TODO for CMP:
# 17 December 2012 so we don't get certificate expiry errors.
# my @check_time=("-attime", "1355875200");

sub test_cmp_cli {
    my $title = shift;
    my $params = shift;
    my $expected_exit = shift;

    with({ exit_checker => sub { return shift == $expected_exit; } },
         sub { ok(run(app(["openssl", "cmp", $params])),
                  $title); });
}

plan tests => 1;

subtest "CMP app CLI\n" => sub {
    plan tests => scalar @cmp_basic_tests;

    foreach (@cmp_basic_tests) {
      SKIP: {
                test_cmp_cli($$_[0], @{$$_[1]}, $$_[2]);
            }
    }
};
