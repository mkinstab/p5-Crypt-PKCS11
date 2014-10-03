#!/usr/bin/env perl

use strict;
use warnings;
use Carp;

sub camelize {
    my $string = shift || confess;
    my $camelize = "";
    my @parts = split(/_/o, $string);

    $camelize = shift(@parts);
    unless ($camelize eq 'get' or $camelize eq 'set') {
        $camelize = ucfirst($camelize);
    }
    foreach my $part (@parts) {
        $camelize .= ucfirst($part);
    }
    return $camelize;
}

unless (-r 'pkcs11t.h') {
    confess;
}

open(HEADER, 'pkcs11t.h') || confess;
while (<HEADER>) {
    s/[\r\n]+$//o;
    
    if (/#define CKA_(\S+)/o) {
        my $attribute = $1;
        my $camelize = camelize(lc($attribute));

        print 'package Crypt::PKCS11::Attribute::'.$camelize.';
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

';
    }
}
close(HEADER);
