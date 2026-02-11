#!/usr/bin/env perl

use strict;
use warnings;
use Carp;

my %tests=();
my $debug=0;
# each test will have a shell to run under, a command to run, and an expected output. 
# If the command, run under the shell, does not produce the expected output
# then the test fails.

$tests{AdminAccounts}={
    'type' => "file",
    'file' => "/etc/passwd",
    'split' => ":",
    'field' => 3,
    'search' => '^0$',
    'returnfield' => '0',
    'returnmatch' => ["root"],
};
$tests{ShadowPasswords}={
    'type' => "file",
    'file' => "/etc/passwd",
    'split' => ":",
    'field' => 1,
    'search' => '^[^x]+$',
    'returnfield' => '0',
    'returnmatch' => [],
};
$tests{StrongHash}={
    'type' => "file",
    'file' => "/etc/login.defs",
    'split' => '\s+',
    'field' => 1,
    'search' => "(DES|MD5)",
    'returnfield' => '0',
    'returnmatch' => [],
};
my $pampasswdfile = "/doesnotexist";
my $pamauthfile = "/doesnotexist";
$pampasswdfile = "/etc/pam.d/password-auth-ac" if (-f "/etc/pam.d/password-auth-ac");
$pampasswdfile = "/etc/pam.d/common-password" if (-f "/etc/pam.d/common-password");
$pamauthfile = "/etc/pam.d/password-auth-ac" if (-f "/etc/pam.d/password-auth-ac");
$pamauthfile = "/etc/pam.d/common-auth" if (-f "/etc/pam.d/common-auth");
$tests{StrongPasswordPolicy}={
    'type' => "file",
    'file' => $pampasswdfile,
    'split' => '\s+',
    'field' => '2',
    'search' => '(pam_cracklib|pam_pwhistory|pam_pwcheck)',
    'returnfield' => '2',
    'returnmatch' => [".*"],
}; 

$tests{AccountLockoutPolicies}={
    'type' => "file",
    'file' => $pamauthfile,
    'split' => '\s+',
    'field' => '2',
    'search' => '(pam_tally|pam_faillock)',
    'returnfield' => '2',
    'returnmatch' => [".*"],
}; 
foreach my $test (keys(%tests)) {
    if ($tests{$test}->{'type'} eq "file") {
        $debug && print("Testing file $tests{$test}->{'file'} for $tests{$test}->{'search'}.\n");
        my $result=testfile($tests{$test});
        if (ref($result) eq "ARRAY") {
            if (@$result ne @{$tests{$test}->{'returnmatch'}}) {
                print "Test $test failed with result: \n";
                print join(" ", @$result), "\n";
            } else {
                print "Test $test passed.\n";
            }
        } elsif (ref($result) eq "HASH") {
            print "DO NOT HANDLE HASH RETURN YET!\n";
        } else {
            print "DO NOT HANDLE RETURN TYPE: ".ref($result)." yet!!\n";
        }
    }
}

sub testfile {
    my $test=shift;
    my $file=$test->{'file'};
    my $split=$test->{'split'};
    my $field=$test->{'field'};
    my $search=$test->{'search'};
    my $return=$test->{'returnfield'};
    my $match=$test->{'returnmatch'};
    open(my $fh, "<", "$file") or die "Can't read $file!";
    if (not defined($search) or ($search eq "")) {
        confess("Passed an invalid search parameter!!");
    }
    my @result=();
    while (<$fh>) {
        next if ($_=~/^[\s]*[#;]/); #skip comment lines
        next if ($_=~/^[\s]*$/); #skip blank lines
        my @fields=split(/$split/, $_);
        if (defined($fields[$field])) {
            if ($fields[$field]=~/$search/) {
                push(@result, $fields[$return])
            } else {
                $debug && print("Field $field does not match '$search'\n");
            }
        } else {
            $debug && print ("Field $field is empty: $_");
            if ($search) {
                # then we have an undefined field, and an expectation of a match, so this is a failure
                push(@result, $fields[$return]);
            } else {
                $debug && print ("empty field is ok.\n");
            }
        }
    }
    if (@result ne $match) {
        return \@result;
    } else {
        return \();
    }
}



