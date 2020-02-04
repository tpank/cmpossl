#! /usr/bin/env perl
# Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
# Copyright Nokia 2007-2019
# Copyright Siemens AG 2015-2020
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use POSIX;

use OpenSSL::Test qw/:DEFAULT with data_file srctop_dir/;
use File::Spec::Functions qw/catfile/;
use OpenSSL::Test::Utils;
use Data::Dumper; # for debugging purposes only

setup("test_cmp_cli_server");

plan skip_all => "This test is not supported in a no-cmp build"
    if disabled("cmp");

my $datadir = srctop_dir("test", "recipes", "81-test_cmp_cli_server_data");
my $localport = 1700;

plan tests => 2;

sub start_mock_server {
    system ("LD_LIBRARY_PATH=../../ ../../apps/openssl cmp" .
            " -port $localport -srv_cert " . catfile($datadir, "server.crt") .
            " -srv_key " . catfile($datadir, "server.key") .
            " -accept_unprotected " .
            " -rsp_cert " . catfile($datadir, "client.crt") .
            " -certout /tmp/newcert.crt" .
            " $_[0] &"); # start in background
}

sub stop_mock_server {
    system ("kill `lsof -i | grep 'TCP .*:$localport' | awk '{ print \$2 }'`");
}

sub run_client {
    ok(run(app(["openssl", "cmp", "-server",
                "127.0.0.1:" . $localport, # 'localhost' does not always work
                "-cmd", "ir", "-cert", catfile($datadir, "client.crt"),
                "-key", catfile($datadir, "client.key"),
                "-certout", "/tmp/newcert.crt",
                "-trusted", catfile($datadir, "server.crt"),
                "-unprotectedrequests", "-unprotectederrors",
                "-no_check_time"])));
}

start_mock_server("");
run_client();
stop_mock_server();

start_mock_server("-poll_count 3 -checkafter 2");
run_client();
stop_mock_server();
