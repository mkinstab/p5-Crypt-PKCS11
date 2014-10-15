#!/usr/bin/env perl

use strict;
use warnings;
use Carp;

my %SKIP = (
#    CK_VERSION => 1,
    CK_INFO => 1,
    CK_SLOT_INFO => 1,
    CK_TOKEN_INFO => 1,
    CK_SESSION_INFO => 1,
    CK_ATTRIBUTE => 1,
    CK_DATE => 1,
#    CK_MECHANISM => 1,
    CK_MECHANISM_INFO => 1,
    CK_C_INITIALIZE_ARGS => 1
);
my %SKIP_VAR = (
    CK_KEA_DERIVE_PARAMS => {
        ulRandomLen => 1,
    },
    CK_SKIPJACK_PRIVATE_WRAP_PARAMS => {
        ulPAndGLen => 1,
        ulQLen => 1,
        ulRandomLen => 1,
    },
    CK_SKIPJACK_RELAYX_PARAMS => {
        ulOldRandomLen => 1,
        ulNewRandomLen => 1,
    },
);
my %LEN = (
    CK_KEA_DERIVE_PARAMS => {
        pRandomA => 'ulRandomLen',
        pRandomB => 'ulRandomLen',
    },
    CK_SKIPJACK_PRIVATE_WRAP_PARAMS => {
        pPrimeP => 'ulPAndGLen',
        pBaseG => 'ulPAndGLen',
        pSubprimeQ => 'ulQLen',
        pRandomA => 'ulRandomLen',
    },
    CK_SKIPJACK_RELAYX_PARAMS => {
        pOldRandomA => 'ulOldRandomLen',
        pNewRandomA => 'ulNewRandomLen',
    },
);
my %ND = (
);

my $struct;
my @types;
my $in_struct = 0;
my $in_comment = 0;
my %base;
my %T = (
    CK_BYTE => \&ck_byte_or_ulong,
    CK_BYTE_PTR => \&ck_byte_ptr,
    CK_ULONG => \&ck_byte_or_ulong,
    CK_BBOOL => \&ck_bbool,
    CK_CHAR_PTR => \&unimplemented,
    CK_UTF8CHAR_PTR => \&unimplemented,
    CK_VOID_PTR => \&ck_byte_ptr,
    CK_VERSION_PTR => \&unimplemented,
    CK_MECHANISM_PTR => \&unimplemented,
    CK_SSL3_RANDOM_DATA => \&unimplemented,
    CK_SSL3_KEY_MAT_OUT_PTR => \&unimplemented,
    CK_WTLS_RANDOM_DATA => \&unimplemented,
    CK_WTLS_KEY_MAT_OUT_PTR => \&unimplemented,
    CK_OTP_PARAM_PTR => \&unimplemented,
);
my %TT = (
    CK_PBE_PARAMS => {
        pInitVector => \&CK_PBE_PARAMS_pInitVector,
    },
    CK_SSL3_KEY_MAT_OUT => {
        pIVClient => \&CK_SSL3_KEY_MAT_OUT_pIVClient,
        pIVServer => \&CK_SSL3_KEY_MAT_OUT_pIVServer,
    },
    CK_WTLS_MASTER_KEY_DERIVE_PARAMS => {
        pVersion => \&CK_WTLS_MASTER_KEY_DERIVE_PARAMS_pVersion,
    },
    CK_WTLS_KEY_MAT_OUT => {
        pIV => \&CK_WTLS_KEY_MAT_OUT_pIV,
    },
);

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

extern int crypt_pkcs11_xs_SvUOK(SV* sv);

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
                if (exists $SKIP_VAR{$struct} and exists $SKIP_VAR{$struct}->{$type->{name}}) {
                    next;
                }

                if ($type->{type} eq 'CK_ULONG' and $type->{name} =~ /^ul(\w+)Len(\w*)$/o) {
                    my $name = 'p'.$1.$2;
                    foreach my $type2 (@_types, @types) {
                        if ($type2->{name} eq $name) {
                            $type2->{len} = $type->{name};
                            last;
                        }
                    }
                    next;
                }
                elsif ($type->{type} eq 'CK_ULONG' and $type->{name} =~ /^(?:length|ulLen)$/) {
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
                if ($type->{type} eq 'CK_ULONG_PTR' and $type->{name} =~ /^p?ul(\w+)Len(\w*)$/o) {
                    my $name = 'p'.$1.$2;

                    foreach my $type2 (@_types, @types) {
                        if ($type2->{name} eq $name) {
                            $type2->{outLen} = $type->{name};
                            last;
                        }
                    }
                    next;
                }

                if (exists $LEN{$struct} and exists $LEN{$struct}->{$type->{name}}) {
                    $type->{len} = $LEN{$struct}->{$type->{name}};
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
        elsif (/(\w+)\s+(\w+)((?:\[\d+\]))?;/o) {
            my $type = { type => $1, name => $2, ($3 ? (size => $3) : ()) };
            if (exists $type->{size}) {
                $type->{size} =~ s/[\]\[]+//go;
                $type->{size} += 0;
            }
            push(@types, $type);
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
    elsif (/typedef\s+(\w+)\s+(\w+);/o) {
        $base{$2} = $1;
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
crypt_pkcs11_'.$lc_struct.'_get_'.$_->{name}.'(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    SV* sv
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_'.$lc_struct.'_set_'.$_->{name}.'(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    SV* sv
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
';
    if (exists $ND{$struct}) {
        print C '    }
    else {
';
        $ND{$struct}->(1);
    }
print C '    }
    return object;
}

void crypt_pkcs11_'.$lc_struct.'_DESTROY('.$c_struct.'* object) {
    if (object) {
';
    if (exists $ND{$struct}) {
        $ND{$struct}->();
    }
print C '        free(object);
    }
}

';
    foreach (@$types) {
        if (exists $TT{$struct} and exists $TT{$struct}->{$_->{name}}) {
            $TT{$struct}->{$_->{name}}->($struct, $c_struct, $lc_struct, $_);
            next;
        }
        my $type = $_->{type};
        while (1) {
            if (exists $T{$type}) {
                $T{$type}->($struct, $c_struct, $lc_struct, $_);
                last;
            }
            unless (exists $base{$type}) {
                print STDERR "$struct: Unhandled type $type\n";
                last;
            }
            $type = $base{$type};
        }
    }
}

sub gen_h {
    my ($struct, $types) = @_;
    my $c_struct = 'Crypt::PKCS11::'.$struct;
    $c_struct =~ s/:/_/go;
    my $lc_struct = lc($struct);

    # TODO: Add own struct around struct to be able to add own data within
    print H 'typedef struct '.$struct.' '.$c_struct.';
'.$c_struct.'* crypt_pkcs11_'.$lc_struct.'_new(const char* class);
void crypt_pkcs11_'.$lc_struct.'_DESTROY('.$c_struct.'* object);
';
    foreach (@$types) {
        print H 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$_->{name}.'('.$c_struct.'* object, SV* sv);
CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$_->{name}.'('.$c_struct.'* object, SV* sv);
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

sub unimplemented {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    croak("Unimplemented");
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    croak("Unimplemented");
}

';
}

sub ck_byte_or_ulong {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    if (exists $type->{size}) {
        # TODO
        unimplemented(@_);
        return;
    }

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->'.$type->{name}.');
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->'.$type->{name}.' = SvUV(sv);

    return CKR_OK;
}

';
}

sub ck_bbool {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->'.$type->{name}.');
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (SvUV(sv)) {
        object->'.$type->{name}.' = CK_TRUE;
    }
    else {
        object->'.$type->{name}.' = CK_FALSE;
    }

    return CKR_OK;
}

';
}

sub ck_byte_ptr {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    if (exists $type->{outLen}) {
        # TODO
        unimplemented(@_);
        return;
    }

    unless (exists $type->{len}) {
        croak $struct.'->'.$type->{name}.': Invalid CK_BYTE_PTR, missing len',"\n";
    }

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->'.$type->{name}.', object->'.$type->{len}.');
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    object->'.$type->{name}.' = p;
    object->'.$type->{len}.' = l;

    return CKR_OK;
}

';
}

sub CK_PBE_PARAMS_pInitVector {
    # TODO
    unimplemented(@_);
}

sub CK_SSL3_KEY_MAT_OUT_pIVClient {
    # TODO
    unimplemented(@_);
}

sub CK_SSL3_KEY_MAT_OUT_pIVServer {
    # TODO
    unimplemented(@_);
}

sub CK_WTLS_MASTER_KEY_DERIVE_PARAMS_pVersion {
    # TODO
    unimplemented(@_);
}

sub CK_WTLS_KEY_MAT_OUT_pIV {
    # TODO
    unimplemented(@_);
}
