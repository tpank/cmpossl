#! /usr/bin/env perl
# Copyright OpenSSL 2007-2018
# Copyright Nokia 2007-2018
# Copyright Siemens AG 2015-2018
#
# Contents licensed under the terms of the OpenSSL license
# See https://www.openssl.org/source/license.html for details
#
# SPDX-License-Identifier: OpenSSL
#
# CMP tests by Martin Peylo, Tobias Pankert, and David von Oheimb.

use strict;
use warnings;

use POSIX;
use OpenSSL::Test qw/:DEFAULT with srctop_dir data_file/;
use OpenSSL::Test::Utils;
use Data::Dumper; # for debugging purposes only

my $proxy = '""';
$proxy = $ENV{http_proxy} if $ENV{http_proxy};
$proxy =~ s{http://}{};

setup("test_cmp_cli");

plan skip_all => "CMP is not supported by this OpenSSL build"
    if disabled("cmp");

my @cmp_basic_tests = (
    [ "output help",                      [ "-help"], 0 ],
    [ "unknown CLI parameter",            [ "-asdffdsa"], 1 ],
    [ "bad int syntax: non-digit",        [ "-msgtimeout", "a/" ], 1 ],
    [ "bad int syntax: float",            [ "-msgtimeout", "3.14" ], 1 ],
    [ "bad int syntax: trailing garbage", [ "-msgtimeout", "314_+" ], 1 ],
    [ "bad int: out of range",            [ "-msgtimeout", "2147483648" ], 1 ],
);

my $config_file = "../".data_file("test_config.cnf");

# the CA server configuration consists of:
#	The CA name (implies directoy with certs etc. and CA-specific section in config file)
#	The CA common name
#	The secret for PBM
#	The column number of the expected result
#	The time to sleep between two requests

my $insta_name = "Insta";
my $insta_cn = "/C=FI/O=Insta Demo/CN=Insta Demo CA";
my $insta_secret = "pass:insta";
my @insta_config = ($insta_name, $insta_cn, $insta_secret, 1, 2);

my $ejbca_name = "EJBCA";
my $ejbca_cn = "/CN=ECC Issuing CA v10/OU=For test purpose only/O=CMPforOpenSSL/C=DE";
my $ejbca_secret = "pass:SecretCmp";
my @ejbca_config = ($ejbca_name, $ejbca_cn, $ejbca_secret, 0, 0);

my @ca_configurations = (\@ejbca_config, \@insta_config);

my @all_aspects = ("connection", "verification", "credentials", "commands");

sub test_cmp_cli {
    my @args = @_;
    my $title = shift;
    my $params = shift;
    my $expected_exit = shift;
    my $configfile = shift;
    with({ exit_checker => sub {
        my $OK = shift == $expected_exit;
        print Dumper @args if !($ENV{HARNESS_VERBOSE} == 2 && $OK); # for debugging purposes only
        return $OK; } },
         sub { indir data_file(".") => # TODO: replace by data_dir() when available
         sub { ok(run(app(["openssl", "cmp", @$params,])),
                  $title); }});
}

plan tests => 1+@ca_configurations*@all_aspects;

subtest "CMP app CLI basic\n" => sub {
	plan tests => scalar @cmp_basic_tests;

	foreach (@cmp_basic_tests) {
	  SKIP: {
		test_cmp_cli($$_[0], $$_[1] ,$$_[2], $config_file);
		}
	}
};

# TODO: complete and thoroughly review _all_ of the around 500 test cases

foreach my $config (@ca_configurations) {
    foreach my $aspect (@all_aspects) {

	subtest "CMP app CLI ".$$config[0]." $aspect\n" => sub {
		my $tests = load_tests("test_$aspect.csv", @$config);
		my $sleep_time = $$config[-1];
		plan tests => scalar @$tests;
		foreach (@$tests) {
		  SKIP: {
			test_cmp_cli($$_[0], $$_[1] ,$$_[2], $config_file);
			sleep($sleep_time);
			}
		}
	};
    };
};

sub load_tests {
	my $file = data_file(shift);
	my $name = shift;
	my $cacn = shift;
	my $secret = shift;
	my $index = shift; 
	my $certdir = data_file($name); # TODO: replace by data_dir($name) when available
	my $section = $name;
	my @result;

	open(my $data, '<', $file) || die "Cannot load $file\n";
	LOOP: while (my $line = <$data>) {
		chomp $line;
		next LOOP if $line =~ m/TLS/i; # skip tests requiring TLS
		$line =~ s{\r\n}{\n}g; # adjust line endings
		$line =~ s{_CERTDIR}{../$certdir}g;
		$line =~ s{_ISSUINGCACN}{$cacn}g;
		$line =~ s{_SECRET}{$secret}g;
		$line =~ s{-section;}{-proxy;$proxy;-config;$config_file;-section;$section,};
		my @fields = grep /\S/, split ";", $line;
		my $expected_exit = $fields[$index];
		my $title = $fields[2];
		next LOOP if (!defined($expected_exit) or ($expected_exit ne 0 and $expected_exit ne 1));
		@fields = grep {$_ ne 'BLANK'} @fields[3..@fields-1];
		push @result, [$title, \@fields, $expected_exit];
	}
	return \@result;
}
