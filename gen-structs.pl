#!/usr/bin/env perl

use strict;
use warnings;
use Carp;
use Getopt::Long;

my %SKIP = (
    CK_VERSION => 1,
    CK_INFO => 1,
    CK_SLOT_INFO => 1,
    CK_TOKEN_INFO => 1,
    CK_SESSION_INFO => 1,
    CK_ATTRIBUTE => 1,
    CK_DATE => 1,
    CK_MECHANISM => 1,
    CK_MECHANISM_INFO => 1,
    CK_C_INITIALIZE_ARGS => 1
);

my $xs = 0;
my $c = 0;
my $h = 0;
my $typemap = 0;

unless (GetOptions('xs' => \$xs, 'c'  => \$c, 'h' => \$h, 'typemap' => \$typemap)
    and ($xs or $c or $h or $typemap))
{
    print "usage: gen-structs.pl [--xs|--c|--h|--typemap]\n";
    exit;
}

my $struct;
my @types;
my $in_struct = 0;
my $in_comment = 0;

open(HEADER, 'pkcs11t.h') || die;
while (<HEADER>) {
    if ($in_comment) {
        unless (/\*\//o) {
            next;
        }
        s/.*\*\///o;
    }
    if ($in_struct) {
        s/\/\*.*\*\///o;
        
        if (/\/\*/o) {
            s/\/\*.*//o;
            $in_comment = 1;
        }
        if (/}/o) {
            my @_types;

            foreach my $type (@types) {
                if ($type->{type} eq 'CK_ULONG' and $type->{name} =~ /^ul(\w+)Len$/o) {
                    my $name = 'p'.$1;
                    
                    foreach my $type2 (@_types, @types) {
                        if ($type2->{name} eq $name) {
                            $type2->{len} = $type->{name};
                            last;
                        }
                    }
                    next;
                }
                elsif ($type->{type} eq 'CK_ULONG' and $type->{name} eq 'length') {
                    my $found = 0;
                    foreach my $type2 (@_types, @types) {
                        if ($type2->{name} eq 'pData') {
                            $type2->{len} = $type->{name};
                            $found = 1;
                            last;
                        }
                    }
                    if ($found) {
                        next;
                    }
                }
                push(@_types, $type);
            }

            if ($xs) {
                gen_xs($struct, \@_types);
            }
            elsif ($c) {
                gen_c($struct, \@_types);
            }
            elsif ($h) {
                gen_h($struct, \@_types);
            }
            elsif ($typemap) {
                gen_typemap($struct, \@_types);
            }
            
            $struct = undef;
            @types = ();
            $in_struct = 0;
        }
        elsif (/(\w+)\s+(\w+)(?:\[.+\])?;/o) {
            push(@types, { type => $1, name => $2 });
        }
        next;
    }
    if (/typedef\s+struct\s+(\S+)\s*{/o) {
        $struct = $1;

        if (exists $SKIP{$struct}) {
            next;
        }

        $in_struct = 1;
    }
}
close(HEADER);

sub gen_xs {
    my ($struct, $types) = @_;
    my $lc_struct = lc($struct);

    print 'MODULE = Crypt::PKCS11::'.$struct.'  PACKAGE = Crypt::PKCS11::'.$struct.'  PREFIX = crypt_pkcs11_'.$lc_struct.'_

PROTOTYPES: ENABLE

Crypt::PKCS11::'.$struct.'*
crypt_pkcs11_'.$lc_struct.'_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::'.$struct.'  PACKAGE = Crypt::PKCS11::'.$struct.'Ptr  PREFIX = crypt_pkcs11_'.$lc_struct.'_

PROTOTYPES: ENABLE

void
crypt_pkcs11_'.$lc_struct.'_DESTROY(object)
    Crypt::PKCS11::'.$struct.'* object
PROTOTYPE: $

';
    foreach (@$types) {
        print 'CK_RV
crypt_pkcs11_'.$lc_struct.'_get_'.$_->{name}.'('.$_->{name}.')
    SV* '.$_->{name}.'
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_'.$lc_struct.'_set_'.$_->{name}.'('.$_->{name}.')
    SV* '.$_->{name}.'
PROTOTYPE: $
OUTPUT:
    RETVAL

';
    }
}

sub gen_c {
    my ($struct, $types) = @_;
}

sub gen_h {
    my ($struct, $types) = @_;
}

sub gen_typemap {
    my ($struct, $types) = @_;

    print 'Crypt::PKCS11::'.$struct.'* T_PTROBJ
';
}
