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

my $config_file = "../".data_file("test_config.cnf");

my $insta_certdir = data_file("INSTA");
my $insta_commonname = "/C=FI/O=Insta Demo/CN=Insta Demo CA";
my $insta_section = "insta";
#The credentials consist of:
#	The directory holding the certificates,
#	The CAs common name
#	The CA specific section in the config file
#	The config file
#	The column number of the expected result
#	The time to sleep between two requests
my @insta_credentials = ($insta_certdir, $insta_commonname, $insta_section, $config_file, 1, 2);
my $ejbca_certdir = data_file("EJBCA_AWS");
my $ejbca_commonname = "/CN=ECC Issuing CA v10/OU=For test purpose only/O=CMPforOpenSSL/C=DE";
my $ejbca_section = "ejbca";
my @ejbca_credentials = ($ejbca_certdir, $ejbca_commonname, $ejbca_section, $config_file, 0, 0);
my @all_credentials = (\@ejbca_credentials, \@insta_credentials);
sub test_cmp_cli {
    my @args = @_;
    my $title = shift;
    my $params = shift;
    my $expected_exit = shift;
    my $config = shift;
    with({ exit_checker => sub {
        my $OK = shift == $expected_exit;
        print Dumper @args if !($ENV{HARNESS_VERBOSE} == 2 && $OK); # for debugging purposes only
        return $OK; } },
         sub { indir data_file(".") =>
         sub { ok(run(app(["openssl", "cmp", @$params,])),
                  $title); }});
}

plan tests => 1+4*@all_credentials;

subtest "CMP app CLI\n" => sub {
		plan tests => scalar @cmp_basic_tests;

		foreach (@cmp_basic_tests) {
		  SKIP: {
					test_cmp_cli($$_[0], $$_[1] ,$$_[2], $config_file);
				}
	}
};
foreach my $credentials (@all_credentials) {
	subtest "CMP connection CLI\n" => sub {
		my $connection_tests = load_tests("test_connection.csv", @$credentials);
		my $sleep_time = $$credentials[-1];
		plan tests => scalar @$connection_tests;
		foreach (@$connection_tests) {
		  SKIP: {
					test_cmp_cli($$_[0], $$_[1] ,$$_[2], $config_file);
					sleep($sleep_time);
				}
		}
	};
	subtest "CMP verification CLI\n" => sub {
		my $verification_tests = load_tests("test_verification.csv",  @$credentials);
		my $sleep_time = $$credentials[-1];
		plan tests => scalar @$verification_tests;
		foreach (@$verification_tests) {
		  SKIP: {
					test_cmp_cli($$_[0], $$_[1] ,$$_[2], $config_file);
					sleep($sleep_time);
				}
		}
	};
	subtest "CMP credentials CLI\n" => sub {
		my $credential_tests = load_tests("test_credentials.csv",  @$credentials);
		my $sleep_time = $$credentials[-1];
		plan tests => scalar @$credential_tests;
		foreach (@$credential_tests) {
		  SKIP: {
					test_cmp_cli($$_[0], $$_[1] ,$$_[2], $config_file);
					sleep($sleep_time);
				}
		}
	};
	subtest "CMP commands CLI\n" => sub {
		my $commands_tests = load_tests("test_commands.csv",  @$credentials);
		my $sleep_time = $$credentials[-1];
		plan tests => scalar @$commands_tests;
		 foreach (@$commands_tests) {
		  SKIP: {
					test_cmp_cli($$_[0], $$_[1] ,$$_[2], $config_file);
					sleep($sleep_time);
				}
		}
	};
};

sub load_tests {
	my $file = data_file(shift);
	my $dir = shift;
	my $cacn = shift;
	my $section = shift;
	my $config = shift;
	my $index = shift; 
	my @result;

	open(my $data, '<', $file) or die "Cannot load $file\n";
	LOOP: while (my $line = <$data>) {
		chomp $line;
		next LOOP if (index($line, "tls") ne -1); #skip tests requiring tls 
		$line =~ s{\r\n}{\n}; #Adjust line endings
		$line =~ s{_CERTDIR}{../$dir}g;
		$line =~ s{_ISSUINGCACN}{$cacn}g;
		$line =~ s{-section;}{-batch;-config;$config;-section;$section,};
		my @fields = grep /\S/, split ";", $line;
		my $expected_exit = $fields[$index];
		my $title = $fields[2];
		next LOOP if (!defined($expected_exit) or ($expected_exit ne 0 and $expected_exit ne 1));
		@fields = grep {$_ ne 'BLANK' and $_ ne ""} @fields[3..@fields-1];
		push @result, [$title, \@fields, $expected_exit];
	}
	return \@result;
}
