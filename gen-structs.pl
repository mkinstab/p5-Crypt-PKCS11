#!/usr/bin/env perl

use strict;
use warnings;
use Carp;

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

my $struct;
my @types;
my $in_struct = 0;
my $in_comment = 0;

open(HEADER, 'pkcs11t.h') || die;
open(XS, '>pkcs11_struct.xs') || die;
print XS '/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS\'\' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "crypt_pkcs11_struct.h"

';
open(C, '>crypt_pkcs11_struct.c') || die;
print C '/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS\'\' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "crypt_pkcs11_struct.h"

#include <stdlib.h>

';
open(H, '>crypt_pkcs11_struct.h') || die;
print H '/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS\'\' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "cryptoki.h"

';
open(TYPEMAP, '>typemap.struct') || die;
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

            gen_xs($struct, \@_types);
            gen_c($struct, \@_types);
            gen_h($struct, \@_types);
            gen_typemap($struct, \@_types);
            
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
close(XS);
close(C);
close(H);
close(TYPEMAP);
close(HEADER);
exit;

sub gen_xs {
    my ($struct, $types) = @_;
    my $lc_struct = lc($struct);

    print XS 'MODULE = Crypt::PKCS11::'.$struct.'  PACKAGE = Crypt::PKCS11::'.$struct.'  PREFIX = crypt_pkcs11_'.$lc_struct.'_

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
        print XS 'CK_RV
crypt_pkcs11_'.$lc_struct.'_get_'.$_->{name}.'(object, '.$_->{name}.')
    Crypt::PKCS11::'.$struct.'* object
    SV* '.$_->{name}.'
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_'.$lc_struct.'_set_'.$_->{name}.'(object, '.$_->{name}.')
    Crypt::PKCS11::'.$struct.'* object
    SV* '.$_->{name}.'
PROTOTYPE: $
OUTPUT:
    RETVAL

';
    }
}

sub gen_c {
    my ($struct, $types) = @_;
    my $c_struct = 'Crypt::PKCS11::'.$struct;
    $c_struct =~ s/:/_/go;
    my $lc_struct = lc($struct);

    print C $c_struct.'* crypt_pkcs11_'.$lc_struct.'_new(const char* class) {
    '.$c_struct.'* object = calloc(1, sizeof('.$c_struct.'));
    if (!object) {
        croak("Memory allocation error");
    }
    return object;
}

void crypt_pkcs11_'.$lc_struct.'_DESTROY('.$c_struct.'* object) {
    free(object);
}

';
    foreach (@$types) {
        print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$_->{name}.'('.$c_struct.'* object, SV* '.$_->{name}.') {
    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$_->{name}.'('.$c_struct.'* object, SV* '.$_->{name}.') {
    return CKR_OK;
}

';
    }
}

sub gen_h {
    my ($struct, $types) = @_;
    my $c_struct = 'Crypt::PKCS11::'.$struct;
    $c_struct =~ s/:/_/go;
    my $lc_struct = lc($struct);

    print H 'typedef '.$struct.' '.$c_struct.';
'.$c_struct.'* crypt_pkcs11_'.$lc_struct.'_new(const char* class);
void crypt_pkcs11_'.$lc_struct.'_DESTROY('.$c_struct.'* object);
';
    foreach (@$types) {
        print H 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$_->{name}.'('.$c_struct.'* object, SV* '.$_->{name}.');
CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$_->{name}.'('.$c_struct.'* object, SV* '.$_->{name}.');
';
    }
    print H '
';
}

sub gen_typemap {
    my ($struct, $types) = @_;

    print TYPEMAP 'Crypt::PKCS11::'.$struct.'* T_PTROBJ
';
}
