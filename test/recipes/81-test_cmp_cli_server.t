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
use File::Compare qw/compare_text/;
use OpenSSL::Test::Utils;
use Data::Dumper; # for debugging purposes only

setup("test_cmp_cli_server");

plan skip_all => "This test is not supported in a no-cmp build"
    if disabled("cmp");

my $datadir = srctop_dir("test", "recipes", "81-test_cmp_cli_server_data");
my $rsp_cert = catfile($datadir, "client.crt");
my $outfile = "newcert.crt";
my $localport = 1700;

plan tests => 3;

sub start_mock_server {
    system ("LD_LIBRARY_PATH=../../ ../../apps/openssl cmp" .
            # " -config ../../test/default.cnf" .
            " -port $localport" .
            " -srv_cert " . catfile($datadir, "server.crt") .
            " -srv_key " . catfile($datadir, "server.key") .
            # " -accept_unprotected " .
            " -srv_trusted " . catfile($datadir, "client.crt") .
            " -no_check_time" .
            " -rsp_cert " . $rsp_cert .
            " $_[0]" . # optionally further CLI arguments
            " &"); # start in background
}

sub stop_mock_server {
    my $pid = `lsof -i | grep 'TCP .*:$localport' | head -n 1 | awk '{ print \$2 }'`;
    system ("kill $pid") if $pid;
}

sub run_client {
    ok(run(app(["openssl", "cmp",
                # "-config", srctop_dir("test", "default.cnf"),
                "-server", "127.0.0.1:" . $localport, # better than 'localhost',
                "-no_proxy", "127.0.0.1",
                "-srvcert", catfile($datadir, "server.crt"),
                "-no_check_time",
                # "-unprotected_requests",
                "-cert", catfile($datadir, "client.crt"),
                "-key", catfile($datadir, "client.key"),
                "-cmd", "ir",
                "-certout", $outfile,
                "-unprotected_errors"]))
        && compare_text($outfile, $rsp_cert) == 0);
    unlink $outfile;
}

ok(run(app(["openssl", "cmp",
            "-config", srctop_dir("test", "default.cnf"), "-section", "\'\'",
            "-use_mock_srv", "-srv_ref", "mock server",
            "-srv_secret", "pass:test", "-poll_count", "1",
            "-rsp_cert", catfile($datadir, "client.crt"),
            "-cmd", "cr", "-subject", "/CN=any",
            "-newkey", catfile($datadir, "client.key"),
            "-recipient", "/CN=mock server",
            "-secret", "pass:test", "-ref", "client under test",
            "-certout" , $outfile]))
   && compare_text($outfile, $rsp_cert) == 0);
unlink $outfile;

start_mock_server("");
run_client();
stop_mock_server();

start_mock_server("-poll_count 2 -check_after 0");
run_client();
stop_mock_server();
