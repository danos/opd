#!/usr/bin/perl
#
# Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
#
# Copyright (c) 2013, 2015, Brocade Communication Systems, Inc.
# All Rights Reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

use strict;
use warnings;
use lib '/opt/vyatta/share/perl5';
use JSON;
use Vyatta::Config;
use v5.14;

# Vyatta config
my $config = new Vyatta::Config;

# ruleset file name
my $rulesetfile = "/opt/vyatta/etc/opruleset.txt";

my $path = "system acm operational-ruleset";

# defaults
sub get_defaults {
	my $ed = $config->returnValue("system acm exec-default");
	if (!defined($ed)) {
		$ed = "allow";
	}
	return $ed;
}

# no 0 (false) allowed
my %actions = (
	'deny' => 1,
	'allow' => 2,
	);
sub conv_action {
	my ($act) = @_;
	return ($actions{$act} || $act);
}

# no 0 (false) allowed
my %operations = (
	'create' => 1,
	'read' => 2,
	'update' => 4,
	'delete' => 8,
	'exec' => 16
	);
sub conv_operation {
	my ($op) = @_;
	return ($operations{$op} || $op);
}

sub conv_log {
	my ($log) = @_;
	if ($log) {
		$log = JSON::true;
	} else {
		$log = JSON::false;
	}
	return $log;
}

sub read_rules {
	if (!$config->exists("$path")) {
		return undef;
	}
	my $ruleset = [];
	my @rules = $config->listNodes("$path rule");
	foreach my $rule (@rules) {
		my $cmd = $config->returnValue("$path rule " . $rule . " command");
		my @groups = $config->returnValues("$path rule " . $rule . " group");
		my $log = $config->exists("$path rule " . $rule . " log");
		my $operation = "exec";
		my $action = $config->returnValue("$path rule " . $rule . " action");
		my $rule = {
			"path"   => $cmd,
			"groups" => \@groups,
			"log"    => conv_log($log),
			"perm"   => conv_operation($operation),
			"action" => conv_action($action)
		};
		$ruleset = [@{$ruleset}, $rule];
	}
	return $ruleset;
}

sub build_ruleset {
	my $enabled = $config->exists("system acm enable");
	if ($enabled) {
		$enabled = JSON::true;
	} else {
		$enabled = JSON::false;
	}
	my $ed = get_defaults();
	my $rules = read_rules();
	my $ruleset = {
		"enabled"        => $enabled,
		"exec-default"   => conv_action($ed),
		"rules"          => $rules
	};
	return $ruleset;
}

my $ruleset = build_ruleset();
open (my $MYFILE, '>', $rulesetfile);
print $MYFILE to_json($ruleset, { 'pretty' => 1 });
close $MYFILE;
system("invoke-rc.d vyatta-opd reload");
