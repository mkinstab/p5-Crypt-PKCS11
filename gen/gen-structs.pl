#!/usr/bin/env perl
#
# Copyright (c) 2015 Jerry Lundström <lundstrom.jerry@gmail.com>
# Copyright (c) 2015 .SE (The Internet Infrastructure Foundation)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
my %HEADER_ALLOC_DESTORY = (
    CK_PBE_PARAMS => \&CK_PBE_PARAMS,
    CK_WTLS_MASTER_KEY_DERIVE_PARAMS => \&CK_WTLS_MASTER_KEY_DERIVE_PARAMS,
    CK_SSL3_KEY_MAT_OUT => \&CK_SSL3_KEY_MAT_OUT,
    CK_WTLS_KEY_MAT_OUT => \&CK_WTLS_KEY_MAT_OUT,
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
    CK_CHAR_PTR => \&ck_char_ptr,
    CK_UTF8CHAR_PTR => \&ck_char_ptr,
    CK_VOID_PTR => \&ck_byte_ptr,
    CK_VERSION_PTR => \&ck_version_ptr,
    CK_MECHANISM_PTR => \&ck_mechanism_ptr,
    CK_SSL3_RANDOM_DATA => \&ck_ssl3_random_data,
    CK_SSL3_KEY_MAT_OUT_PTR => \&ck_ssl3_key_mat_out_ptr,
    CK_WTLS_RANDOM_DATA => \&ck_wtls_random_data,
    CK_WTLS_KEY_MAT_OUT_PTR => \&ck_wtls_key_mat_out_ptr,
    CK_OTP_PARAM_PTR => \&ck_otp_param_ptr,
);
my %NEW = (
    CK_VERSION_PTR => \&ck_type_ptr_new,
    CK_MECHANISM_PTR => \&ck_type_ptr_new,
    CK_SSL3_KEY_MAT_OUT_PTR => \&ck_type_ptr_new,
    CK_WTLS_KEY_MAT_OUT_PTR => \&ck_type_ptr_new,
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
    CK_CMS_SIG_PARAMS => {
        pContentType => \&CK_CMS_SIG_PARAMS_pContentType,
    },
    CK_OTP_PARAMS => {
        ulCount => \&CK_OTP_PARAMS_ulCount,
    },
    CK_OTP_SIGNATURE_INFO => {
        ulCount => \&CK_OTP_SIGNATURE_INFO_ulCount,
    },
);
my %D = (
    CK_BYTE => undef,
    CK_BYTE_PTR => \&ck_byte_ptr_DESTROY,
    CK_ULONG => undef,
    CK_BBOOL => undef,
    CK_CHAR_PTR => \&ck_char_ptr_DESTROY,
    CK_UTF8CHAR_PTR => \&ck_char_ptr_DESTROY,
    CK_VOID_PTR => \&ck_byte_ptr_DESTROY,
    CK_VERSION_PTR => undef,
    CK_MECHANISM_PTR => \&ck_mechanism_ptr_DESTROY,
    CK_SSL3_RANDOM_DATA => \&ck_ssl3_random_data_DESTROY,
    CK_SSL3_KEY_MAT_OUT_PTR => \&ck_ssl3_key_mat_out_ptr_DESTROY,
    CK_WTLS_RANDOM_DATA => \&ck_wtls_random_data_DESTROY,
    CK_WTLS_KEY_MAT_OUT_PTR => \&ck_wtls_key_mat_out_ptr_DESTROY,
    CK_OTP_PARAM_PTR => \&ck_otp_param_ptr_DESTROY,
);
my %DD = (
    CK_PBE_PARAMS => {
        pInitVector => \&CK_PBE_PARAMS_pInitVector_DESTROY,
    },
    CK_WTLS_MASTER_KEY_DERIVE_PARAMS => {
        pVersion => \&CK_WTLS_MASTER_KEY_DERIVE_PARAMS_pVersion_DESTROY,
    },
);
my %H = (
    CK_BYTE => undef,
    CK_BYTE_PTR => \&ck_out_ptr_len,
    CK_ULONG => undef,
    CK_BBOOL => undef,
    CK_CHAR_PTR => \&ck_out_ptr_len,
    CK_UTF8CHAR_PTR => \&ck_out_ptr_len,
    CK_VOID_PTR => \&ck_out_ptr_len,
    CK_VERSION_PTR => \&ck_version_ptr_h,
    CK_MECHANISM_PTR => \&ck_mechanism_ptr_h,
    CK_SSL3_RANDOM_DATA => undef,
    CK_SSL3_KEY_MAT_OUT_PTR => \&ck_ssl3_key_mat_out_ptr_h,
    CK_WTLS_RANDOM_DATA => undef,
    CK_WTLS_KEY_MAT_OUT_PTR => \&ck_wtls_key_mat_out_ptr_h,
    CK_OTP_PARAM_PTR => undef,
);
my %HH = (
    CK_VERSION_PTR => \&ck_version_ptr_hh,
    CK_MECHANISM_PTR => \&ck_mechanism_ptr_hh,
    CK_SSL3_RANDOM_DATA => \&ck_ssl3_random_data_hh,
    CK_SSL3_KEY_MAT_OUT_PTR => \&ck_ssl3_key_mat_out_ptr_hh,
    CK_WTLS_RANDOM_DATA => \&ck_wtls_random_data_hh,
    CK_WTLS_KEY_MAT_OUT_PTR => \&ck_wtls_key_mat_out_ptr_hh,
    CK_OTP_PARAM_PTR => \&ck_otp_param_ptr_hh,
);
my %XS = (
    CK_VERSION_PTR => \&ck_version_ptr_xs,
    CK_MECHANISM_PTR => \&ck_mechanism_ptr_xs,
    CK_SSL3_RANDOM_DATA => \&ck_ssl3_random_data_xs,
    CK_SSL3_KEY_MAT_OUT_PTR => \&ck_ssl3_key_mat_out_ptr_xs,
    CK_WTLS_RANDOM_DATA => \&ck_wtls_random_data_xs,
    CK_WTLS_KEY_MAT_OUT_PTR => \&ck_wtls_key_mat_out_ptr_xs,
    CK_OTP_PARAM_PTR => \&ck_otp_param_ptr_xs,
);
my %XSXS = (
);
my %FB = (
    CK_SSL3_KEY_MAT_OUT => \&not_supported_fromBytes,
    CK_SSL3_KEY_MAT_PARAMS => \&not_supported_fromBytes,
    CK_WTLS_KEY_MAT_OUT => \&not_supported_fromBytes,
    CK_WTLS_KEY_MAT_PARAMS => \&not_supported_fromBytes,
);
my %FB_T = (
    CK_BYTE_PTR => \&ck_byte_ptr_fromBytes,
    CK_CHAR_PTR => \&ck_char_ptr_fromBytes,
    CK_UTF8CHAR_PTR => \&ck_char_ptr_fromBytes,
    CK_VOID_PTR => \&ck_byte_ptr_fromBytes,
    CK_VERSION_PTR => \&ck_version_ptr_fromBytes,
    CK_MECHANISM_PTR => \&ck_mechanism_ptr_fromBytes,
    CK_SSL3_RANDOM_DATA => \&ck_ssl3_random_data_fromBytes,
    CK_WTLS_RANDOM_DATA => \&ck_wtls_random_data_fromBytes,
    CK_OTP_PARAM_PTR => \&ck_otp_param_ptr_fromBytes,
);
my %FB_TT = (
    CK_PBE_PARAMS => {
        pInitVector => \&CK_PBE_PARAMS_pInitVector_fromBytes,
    },
    CK_WTLS_MASTER_KEY_DERIVE_PARAMS => {
        pVersion => \&CK_WTLS_MASTER_KEY_DERIVE_PARAMS_pVersion_fromBytes,
    },
    CK_CMS_SIG_PARAMS => {
        pContentType => \&CK_CMS_SIG_PARAMS_pContentType_fromBytes,
    },
);

open(HEADER, 'pkcs11t.h') || die;
open(XS, '>pkcs11_struct.xs') || die;
print XS '/*
 * Copyright (c) 2015 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2015 .SE (The Internet Infrastructure Foundation)
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "crypt_pkcs11_struct.h"

MODULE = Crypt::PKCS11::STRUCT_XS  PACKAGE = Crypt::PKCS11::STRUCT_XS  PREFIX = crypt_pkcs11_struct_xs_

#ifdef TEST_DEVEL_COVER

int
crypt_pkcs11_struct_xs_test_devel_cover()
PROTOTYPE: DISABLE

#endif

';
open(C, '>crypt_pkcs11_struct.c') || die;
print C '/*
 * Copyright (c) 2015 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2015 .SE (The Internet Infrastructure Foundation)
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "crypt_pkcs11_struct.h"

#include <stdlib.h>
#include <string.h>

#ifdef TEST_DEVEL_COVER
int __test_devel_cover_calloc_always_fail = 0;
#define myNewxz(a,b,c) if (__test_devel_cover_calloc_always_fail) { a = 0; } else { Newxz(a, b, c); }
#define __croak(x) return 0
/* uncoverable begin */
int crypt_pkcs11_struct_xs_test_devel_cover(void) {
    {
        Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object = 0;
        myNewxz(object, 1, Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT);
        if (!object) { return __LINE__; };
        myNewxz(object->private.pIVClient, 1, char);
        if (!object->private.pIVClient) { return __LINE__; }
        myNewxz(object->private.pIVServer, 1, char);
        if (!object->private.pIVServer) { return __LINE__; }
        crypt_pkcs11_ck_ssl3_key_mat_out_DESTROY(object);
    }
    {
        Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object = 0;
        myNewxz(object, 1, Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS);
        if (!object) { return __LINE__; };
        myNewxz(object->pReturnedKeyMaterial.pIVClient, 1, char);
        if (!object->pReturnedKeyMaterial.pIVClient) { return __LINE__; }
        myNewxz(object->pReturnedKeyMaterial.pIVServer, 1, char);
        if (!object->pReturnedKeyMaterial.pIVServer) { return __LINE__; }
        crypt_pkcs11_ck_ssl3_key_mat_params_DESTROY(object);
    }
    {
        Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object = 0;
        myNewxz(object, 1, Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT);
        if (!object) { return __LINE__; };
        myNewxz(object->private.pIV, 1, char);
        if (!object->private.pIV) { return __LINE__; }
        crypt_pkcs11_ck_wtls_key_mat_out_DESTROY(object);
    }
    {
        Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object = 0;
        myNewxz(object, 1, Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS);
        if (!object) { return __LINE__; };
        myNewxz(object->pReturnedKeyMaterial.pIV, 1, char);
        if (!object->pReturnedKeyMaterial.pIV) { return __LINE__; }
        crypt_pkcs11_ck_wtls_key_mat_params_DESTROY(object);
    }
    return 0;
}
/* uncoverable end */
#else
#define myNewxz Newxz
#define __croak(x) croak(x)
#endif

extern int crypt_pkcs11_xs_SvUOK(SV* sv);

';
open(H, '>crypt_pkcs11_struct.h') || die;
print H '/*
 * Copyright (c) 2015 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2015 .SE (The Internet Infrastructure Foundation)
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "cryptoki.h"

#ifdef TEST_DEVEL_COVER
int crypt_pkcs11_struct_xs_test_devel_cover(void);
#endif

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
print XS 'MODULE = Crypt::PKCS11::structs  PACKAGE = Crypt::PKCS11::structs

';
close(XS);
close(C);
close(H);
close(TYPEMAP);
close(HEADER);
exit;

sub gen_xs {
    my ($struct, $types) = @_;
    my $c_struct = 'Crypt::PKCS11::'.$struct;
    $c_struct =~ s/:/_/go;
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

SV*
crypt_pkcs11_'.$lc_struct.'_toBytes(object)
    Crypt::PKCS11::'.$struct.'* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_'.$lc_struct.'_fromBytes(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

';
    foreach (@$types) {
        if (exists $XSXS{$struct} and exists $XSXS{$struct}->{$_->{name}}) {
            $XSXS{$struct}->{$_->{name}}->($struct, $c_struct, $lc_struct, $_);
            next;
        }
        my $type = $_->{type};
        while (1) {
            if (exists $XS{$type}) {
                $XS{$type}->($struct, $c_struct, $lc_struct, $_);
                last;
            }
            unless (exists $base{$type}) {
        print XS 'CK_RV
crypt_pkcs11_'.$lc_struct.'_get_'.$_->{name}.'(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_'.$lc_struct.'_'.$_->{name}.'(object)
    Crypt::PKCS11::'.$struct.'* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_'.$lc_struct.'_get_'.$_->{name}.'(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_'.$lc_struct.'_set_'.$_->{name}.'(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

';
                last;
            }
            $type = $base{$type};
        }
    }
}

sub gen_c {
    my ($struct, $types) = @_;
    my $c_struct = 'Crypt::PKCS11::'.$struct;
    $c_struct =~ s/:/_/go;
    my $lc_struct = lc($struct);

    print C $c_struct.'* crypt_pkcs11_'.$lc_struct.'_new(const char* class) {
    '.$c_struct.'* object = 0;
    myNewxz(object, 1, '.$c_struct.');

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
';
    my $else = 1;
    if (exists $HEADER_ALLOC_DESTORY{$struct}) {
        print C '    }
    else {
';
        $else = 0;
        $HEADER_ALLOC_DESTORY{$struct}->(1);
    }
    foreach (@$types) {
        my $type = $_->{type};
        while (1) {
            if (exists $NEW{$type}) {
                if (defined $NEW{$type}) {
                    if ($else) {
        print C '    }
    else {
';
        $else = 0;
                    }
                    $NEW{$type}->($struct, $c_struct, $lc_struct, $_);
                }
                last;
            }
            unless (exists $base{$type}) {
                last;
            }
            $type = $base{$type};
        }
    }
print C '    }
    return object;
}

SV* crypt_pkcs11_'.$lc_struct.'_toBytes('.$c_struct.'* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof('.$struct.'));
}

';
if (exists $FB{$struct}) {
    $FB{$struct}->($struct, $c_struct, $lc_struct);
}
else {
print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_fromBytes('.$c_struct.'* object, SV* sv) {
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
        || l != sizeof('.$struct.'))
    {
        return CKR_ARGUMENTS_BAD;
    }

';
    foreach (@$types) {
        if (exists $FB_TT{$struct} and exists $FB_TT{$struct}->{$_->{name}}) {
            $FB_TT{$struct}->{$_->{name}}->(0, $struct, $c_struct, $lc_struct, $_);
            next;
        }
        my $type = $_->{type};
        while (1) {
            if (exists $FB_T{$type}) {
                if (defined $FB_T{$type}) {
                    $FB_T{$type}->(0, $struct, $c_struct, $lc_struct, $_);
                }
                last;
            }
            unless (exists $base{$type}) {
                last;
            }
            $type = $base{$type};
        }
    }
print C '    Copy(p, &(object->private), l, char);

';
    foreach (@$types) {
        if (exists $FB_TT{$struct} and exists $FB_TT{$struct}->{$_->{name}}) {
            $FB_TT{$struct}->{$_->{name}}->(1, $struct, $c_struct, $lc_struct, $_);
            next;
        }
        my $type = $_->{type};
        while (1) {
            if (exists $FB_T{$type}) {
                if (defined $FB_T{$type}) {
                    $FB_T{$type}->(1, $struct, $c_struct, $lc_struct, $_);
                }
                last;
            }
            unless (exists $base{$type}) {
                last;
            }
            $type = $base{$type};
        }
    }
print C '    return CKR_OK;
}

';
}
print C 'void crypt_pkcs11_'.$lc_struct.'_DESTROY('.$c_struct.'* object) {
    if (object) {
';
    foreach (@$types) {
        if (exists $DD{$struct} and exists $DD{$struct}->{$_->{name}}) {
            $DD{$struct}->{$_->{name}}->($struct, $c_struct, $lc_struct, $_);
            next;
        }
        my $type = $_->{type};
        while (1) {
            if (exists $D{$type}) {
                if (defined $D{$type}) {
                    $D{$type}->($struct, $c_struct, $lc_struct, $_);
                }
                last;
            }
            unless (exists $base{$type}) {
                print STDERR "$struct: Unhandled DESTROY type $type\n";
                last;
            }
            $type = $base{$type};
        }
    }
    if (exists $HEADER_ALLOC_DESTORY{$struct}) {
        $HEADER_ALLOC_DESTORY{$struct}->(0);
    }
print C '        Safefree(object);
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

    print H 'typedef struct '.$c_struct.' {
    '.$struct.' private;
';
    foreach (@$types) {
        my $type = $_->{type};
        while (1) {
            if (exists $H{$type}) {
                if (defined $H{$type}) {
                    $H{$type}->($struct, $c_struct, $lc_struct, $_);
                }
                last;
            }
            unless (exists $base{$type}) {
                print STDERR "$struct: Unhandled HEADER type $type\n";
                last;
            }
            $type = $base{$type};
        }
    }
    if (exists $HEADER_ALLOC_DESTORY{$struct}) {
        $HEADER_ALLOC_DESTORY{$struct}->(2);
    }
    print H '} '.$c_struct.';
'.$c_struct.'* crypt_pkcs11_'.$lc_struct.'_new(const char* class);
void crypt_pkcs11_'.$lc_struct.'_DESTROY('.$c_struct.'* object);
SV* crypt_pkcs11_'.$lc_struct.'_toBytes('.$c_struct.'* object);
CK_RV crypt_pkcs11_'.$lc_struct.'_fromBytes('.$c_struct.'* object, SV* sv);
';
    foreach (@$types) {
        my $type = $_->{type};
        if (exists $HH{$type}) {
            $HH{$type}->($struct, $c_struct, $lc_struct, $_);
            last;
        }
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

sub not_supported_fromBytes {
    my ($struct, $c_struct, $lc_struct) = @_;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_fromBytes('.$c_struct.'* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

';
}

sub ck_byte_or_ulong {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    if (exists $type->{size}) {
        print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.'.$type->{name}.', '.$type->{size}.' * sizeof('.$type->{type}.'));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    char* p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        Zero(object->private.'.$type->{name}.', '.$type->{size}.', '.$type->{type}.');
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }
    if (l != ('.$type->{size}.' * sizeof('.$type->{type}.'))) {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, object->private.'.$type->{name}.', '.$type->{size}.', '.$type->{type}.');

    return CKR_OK;
}

';
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
    sv_setuv(sv, object->private.'.$type->{name}.');
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
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.'.$type->{name}.' = SvUV(sv);

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
    sv_setuv(sv, object->private.'.$type->{name}.');
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
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (SvUV(sv)) {
        object->private.'.$type->{name}.' = CK_TRUE;
    }
    else {
        object->private.'.$type->{name}.' = CK_FALSE;
    }

    return CKR_OK;
}

';
}

sub ck_byte_ptr {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    if (exists $type->{outLen}) {
        # For out variables:
        # 1. $obj = STRUCT->new
        # 2. Do 2a or 2b
        # 2a. $obj->set_outval(undef);
        #     This will reset the internal structure to be able to get the size
        #     of the output variable
        # 2b. $obj->set_outval($intval);
        #     This will reset the internal structure and allocate memory for the
        #     output variable based on the integer value given.
        # 3. Use $obj in a call, continue with 4 if 2a was done otherwise 6
        # 4. $obj->get_outval(undef);
        #    This will now allocate memory based on what the call returned
        # 5. Do the call again
        # 6. $obj->get_outval($val);
        #    Retreive the value

        print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (!object->'.$type->{outLen}.') {
            return CKR_FUNCTION_FAILED;
        }

        /* uncoverable branch 1 */
        if (object->private.'.$type->{name}.') {
            Safefree(object->private.'.$type->{name}.');
        }

        object->private.'.$type->{name}.' = 0;
        myNewxz(object->private.'.$type->{name}.', object->'.$type->{outLen}.', CK_BYTE);
        /* uncoverable branch 0 */
        if (!object->private.'.$type->{name}.') {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
        return CKR_OK;
    }

    /* uncoverable branch 3 */
    if (object->private.'.$type->{name}.' && object->'.$type->{outLen}.') {
        sv_setpvn(sv, object->private.'.$type->{name}.', object->'.$type->{outLen}.' * sizeof(CK_BYTE));
    }
    else {
        sv_setsv(sv, &PL_sv_undef);
    }
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    UV l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.'.$type->{name}.') {
            Safefree(object->private.'.$type->{name}.');
            object->private.'.$type->{name}.' = 0;
        }
        object->private.'.$type->{outLen}.' = &(object->'.$type->{outLen}.');
        object->'.$type->{outLen}.' = 0;
        return CKR_OK;
    }

    if (!crypt_pkcs11_xs_SvUOK(sv)
        || !(l = SvUV(sv)))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.'.$type->{name}.') {
        Safefree(object->private.'.$type->{name}.');
    }

    object->private.'.$type->{name}.' = 0;
    myNewxz(object->private.'.$type->{name}.', l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!object->private.'.$type->{name}.') {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    object->private.'.$type->{outLen}.' = &(object->'.$type->{outLen}.');
    object->'.$type->{outLen}.' = l;

    return CKR_OK;
}

';
        return;
    }

    unless (exists $type->{len}) {
        croak $struct.'->'.$type->{name}.': Invalid CK_BYTE_PTR/CK_VOID_PTR, missing len',"\n";
    }

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.'.$type->{name}.', object->private.'.$type->{len}.' * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.'.$type->{name}.') {
            Safefree(object->private.'.$type->{name}.');
            object->private.'.$type->{name}.' = 0;
            object->private.'.$type->{len}.' = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l + 1, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.'.$type->{name}.') {
        Safefree(object->private.'.$type->{name}.');
    }
    object->private.'.$type->{name}.' = n;
    object->private.'.$type->{len}.' = l;

    return CKR_OK;
}

';
}

sub ck_byte_ptr_fromBytes {
    my ($what, $struct, $c_struct, $lc_struct, $type) = @_;

    unless ($what) {
    print C '    if (object->private.'.$type->{name}.') {
        Safefree(object->private.'.$type->{name}.');
    }
';
    }
    else {
        if (exists $type->{outLen}) {
    print C '    if (object->private.'.$type->{outLen}.') {
        object->'.$type->{outLen}.' = *(object->private.'.$type->{outLen}.');
    }
    object->private.'.$type->{outLen}.' = &(object->'.$type->{outLen}.');
    if (object->private.'.$type->{name}.') {
        CK_BYTE_PTR '.$type->{name}.' = 0;
        myNewxz('.$type->{name}.', object->'.$type->{outLen}.', CK_BYTE);
        /* uncoverable branch 0 */
        if (!'.$type->{name}.') {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.'.$type->{name}.', '.$type->{name}.', object->'.$type->{outLen}.', CK_BYTE);
        object->private.'.$type->{name}.' = '.$type->{name}.';
    }
';
            return;
        }
    unless (exists $type->{len}) {
        croak $struct.'->'.$type->{name}.': Invalid CK_BYTE_PTR/CK_VOID_PTR, missing len',"\n";
    }
    print C '    if (object->private.'.$type->{name}.') {
        CK_BYTE_PTR '.$type->{name}.' = 0;
        myNewxz('.$type->{name}.', object->private.'.$type->{len}.', CK_BYTE);
        /* uncoverable branch 0 */
        if (!'.$type->{name}.') {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.'.$type->{name}.', '.$type->{name}.', object->private.'.$type->{len}.', CK_BYTE);
        object->private.'.$type->{name}.' = '.$type->{name}.';
    }
';
    }
}

sub ck_byte_ptr_DESTROY {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C '        if (object->private.'.$type->{name}.') {
            Safefree(object->private.'.$type->{name}.');
        }
';
}

sub ck_char_ptr {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    if (exists $type->{outLen}) {
        print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (!object->'.$type->{outLen}.') {
            return CKR_FUNCTION_FAILED;
        }

        /* uncoverable branch 1 */
        if (object->private.'.$type->{name}.') {
            Safefree(object->private.'.$type->{name}.');
        }

        object->private.'.$type->{name}.' = 0;
        myNewxz(object->private.'.$type->{name}.', object->'.$type->{outLen}.', CK_CHAR);
        /* uncoverable branch 0 */
        if (!object->private.'.$type->{name}.') {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
        return CKR_OK;
    }

    /* uncoverable branch 3 */
    if (object->private.'.$type->{name}.' && object->'.$type->{outLen}.') {
        sv_setpvn(sv, object->private.'.$type->{name}.', object->'.$type->{outLen}.' * sizeof(CK_CHAR));
        sv_utf8_upgrade(sv);
    }
    else {
        sv_setsv(sv, &PL_sv_undef);
    }
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    UV l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.'.$type->{name}.') {
            Safefree(object->private.'.$type->{name}.');
            object->private.'.$type->{name}.' = 0;
        }
        object->private.'.$type->{outLen}.' = &(object->'.$type->{outLen}.');
        object->'.$type->{outLen}.' = 0;
        return CKR_OK;
    }

    if (!crypt_pkcs11_xs_SvUOK(sv)
        || !(l = SvUV(sv)))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.'.$type->{name}.') {
        Safefree(object->private.'.$type->{name}.');
    }

    object->private.'.$type->{name}.' = 0;
    myNewxz(object->private.'.$type->{name}.', l, CK_CHAR);
    /* uncoverable branch 0 */
    if (!object->private.'.$type->{name}.') {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    object->private.'.$type->{outLen}.' = &(object->'.$type->{outLen}.');
    object->'.$type->{outLen}.' = l;

    return CKR_OK;
}

';
        return;
    }

    unless (exists $type->{len}) {
        croak $struct.'->'.$type->{name}.': Invalid CK_CHAR_PTR/CK_UTF8CHAR_PTR, missing len',"\n";
    }

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.'.$type->{name}.', object->private.'.$type->{len}.' * sizeof(CK_CHAR));
    sv_utf8_upgrade_nomg(sv);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    CK_CHAR_PTR n = 0;
    CK_CHAR_PTR p;
    STRLEN l;
    SV* _sv;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.'.$type->{name}.') {
            Safefree(object->private.'.$type->{name}.');
            object->private.'.$type->{name}.' = 0;
            object->private.'.$type->{len}.' = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(_sv = newSVsv(sv))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }
    sv_2mortal(_sv);

    sv_utf8_downgrade(_sv, 0);
    if (!(p = SvPV(_sv, l))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }

    myNewxz(n, l + 1, CK_CHAR);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_CHAR);
    if (object->private.'.$type->{name}.') {
        Safefree(object->private.'.$type->{name}.');
    }
    object->private.'.$type->{name}.' = n;
    object->private.'.$type->{len}.' = l;

    return CKR_OK;
}

';
}

sub ck_char_ptr_fromBytes {
    my ($what, $struct, $c_struct, $lc_struct, $type) = @_;

    unless ($what) {
    print C '    if (object->private.'.$type->{name}.') {
        Safefree(object->private.'.$type->{name}.');
    }
';
    }
    else {
        if (exists $type->{outLen}) {
    print C '    if (object->private.'.$type->{outLen}.') {
        object->'.$type->{outLen}.' = *(object->private.'.$type->{outLen}.');
    }
    object->private.'.$type->{outLen}.' = &(object->'.$type->{outLen}.');
    if (object->private.'.$type->{name}.') {
        CK_CHAR_PTR '.$type->{name}.' = 0;
        myNewxz('.$type->{name}.', object->'.$type->{outLen}.', CK_CHAR);
        /* uncoverable branch 0 */
        if (!'.$type->{name}.') {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.'.$type->{name}.', '.$type->{name}.', object->'.$type->{outLen}.', CK_CHAR);
        object->private.'.$type->{name}.' = '.$type->{name}.';
    }
';
            return;
        }
    unless (exists $type->{len}) {
        croak $struct.'->'.$type->{name}.': Invalid CK_CHAR_PTR/CK_UTF8CHAR_PTR, missing len',"\n";
    }
    print C '    if (object->private.'.$type->{name}.') {
        CK_CHAR_PTR '.$type->{name}.' = 0;
        myNewxz('.$type->{name}.', object->private.'.$type->{len}.', CK_CHAR);
        /* uncoverable branch 0 */
        if (!'.$type->{name}.') {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.'.$type->{name}.', '.$type->{name}.', object->private.'.$type->{len}.', CK_CHAR);
        object->private.'.$type->{name}.' = '.$type->{name}.';
    }
';
    }
}

sub ck_char_ptr_DESTROY {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C '        if (object->private.'.$type->{name}.') {
            Safefree(object->private.'.$type->{name}.');
        }
';
}

sub ck_out_ptr_len {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    if (exists $type->{outLen}) {
        print H '    CK_ULONG '.$type->{outLen}.';
';
    }
}

sub ck_type_ptr_new {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C '        object->private.'.$type->{name}.' = &(object->'.$type->{name}.');
';
}

sub ck_version_ptr {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_VERSION* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    sv->private.major = object->'.$type->{name}.'.major;
    sv->private.minor = object->'.$type->{name}.'.minor;

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_VERSION* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    object->'.$type->{name}.'.major = sv->private.major;
    object->'.$type->{name}.'.minor = sv->private.minor;

    return CKR_OK;
}

';
}

sub ck_version_ptr_fromBytes {
    my ($what, $struct, $c_struct, $lc_struct, $type) = @_;

    unless ($what) {
        print C '    Zero(object->private.'.$type->{name}.', 1, CK_VERSION);

';
    }
    else {
        print C '    /* uncoverable branch 1 */
    if (object->private.'.$type->{name}.') {
        Copy(object->private.'.$type->{name}.', &(object->'.$type->{name}.'), 1, CK_VERSION);
    }
    object->private.'.$type->{name}.' = &(object->'.$type->{name}.');

';
    }
}

sub ck_version_ptr_h {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print H '    CK_VERSION '.$type->{name}.';
';
}

sub ck_version_ptr_hh {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print H 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$_->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_VERSION* sv);
CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$_->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_VERSION* sv);
';
}

sub ck_version_ptr_xs {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print XS 'CK_RV
crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    Crypt::PKCS11::CK_VERSION* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

Crypt::PKCS11::CK_VERSION*
crypt_pkcs11_'.$lc_struct.'_'.$type->{name}.'(object)
    Crypt::PKCS11::'.$struct.'* object
PROTOTYPE: $
CODE:
    RETVAL = crypt_pkcs11_ck_version_new("Crypt::PKCS11::CK_VERSION");
    crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    Crypt::PKCS11::CK_VERSION* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

';
}

sub ck_mechanism_ptr {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_MECHANISM* sv) {
    CK_VOID_PTR pParameter = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->'.$type->{name}.'.ulParameterLen) {
        myNewxz(pParameter, object->'.$type->{name}.'.ulParameterLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pParameter) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }

    if (pParameter) {
        Copy(object->'.$type->{name}.'.pParameter, pParameter, object->'.$type->{name}.'.ulParameterLen, CK_BYTE);
    }

    if (sv->private.pParameter) {
        Safefree(sv->private.pParameter);
    }
    sv->private.mechanism = object->'.$type->{name}.'.mechanism;
    sv->private.pParameter = pParameter;
    sv->private.ulParameterLen = object->'.$type->{name}.'.ulParameterLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_MECHANISM* sv) {
    CK_VOID_PTR pParameter = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (sv->private.ulParameterLen) {
        myNewxz(pParameter, sv->private.ulParameterLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pParameter) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }

    if (pParameter) {
        Copy(sv->private.pParameter, pParameter, sv->private.ulParameterLen, CK_BYTE);
    }

    if (object->'.$type->{name}.'.pParameter) {
        Safefree(object->'.$type->{name}.'.pParameter);
    }
    object->'.$type->{name}.'.mechanism = sv->private.mechanism;
    object->'.$type->{name}.'.pParameter = pParameter;
    object->'.$type->{name}.'.ulParameterLen = sv->private.ulParameterLen;

    return CKR_OK;
}

';
}

sub ck_mechanism_ptr_fromBytes {
    my ($what, $struct, $c_struct, $lc_struct, $type) = @_;

    unless ($what) {
        print C '    if (object->'.$type->{name}.'.pParameter) {
        Safefree(object->'.$type->{name}.'.pParameter);
    }
    Zero(&(object->'.$type->{name}.'), 1, CK_MECHANISM);
';
    }
    else {
        print C '    /* uncoverable branch 1 */
    if (object->private.'.$type->{name}.') {
        Copy(object->private.'.$type->{name}.', &(object->'.$type->{name}.'), 1, CK_MECHANISM);
        if (object->'.$type->{name}.'.pParameter) {
            CK_VOID_PTR pParameter = 0;
            myNewxz(pParameter, object->'.$type->{name}.'.ulParameterLen, CK_BYTE);
            /* uncoverable branch 0 */
            if (!pParameter) {
                /* uncoverable block 0 */
                __croak("memory allocation error");
            }
            Copy(object->'.$type->{name}.'.pParameter, pParameter, object->'.$type->{name}.'.ulParameterLen, CK_BYTE);
            object->'.$type->{name}.'.pParameter = pParameter;
        }
    }
    object->private.'.$type->{name}.' = &(object->'.$type->{name}.');

';
    }
}

sub ck_mechanism_ptr_DESTROY {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C '        if (object->'.$type->{name}.'.pParameter) {
            Safefree(object->'.$type->{name}.'.pParameter);
        }
';
}

sub ck_mechanism_ptr_h {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print H '    CK_MECHANISM '.$type->{name}.';
';
}

sub ck_mechanism_ptr_hh {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print H 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$_->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_MECHANISM* sv);
CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$_->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_MECHANISM* sv);
';
}

sub ck_mechanism_ptr_xs {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print XS 'CK_RV
crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    Crypt::PKCS11::CK_MECHANISM* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

Crypt::PKCS11::CK_MECHANISM*
crypt_pkcs11_'.$lc_struct.'_'.$type->{name}.'(object)
    Crypt::PKCS11::'.$struct.'* object
PROTOTYPE: $
CODE:
    RETVAL = crypt_pkcs11_ck_mechanism_new("Crypt::PKCS11::CK_MECHANISM");
    crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    Crypt::PKCS11::CK_MECHANISM* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

';
}

sub CK_PBE_PARAMS {
    if ($_[0] == 1) {
        print C '        object->private.pInitVector = 0;
        myNewxz(object->private.pInitVector, 8, CK_BYTE);
        /* uncoverable branch 0 */
        if (!object->private.pInitVector) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
';
    }
}

sub CK_PBE_PARAMS_pInitVector {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.'.$type->{name}.', 8 * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    char* p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        Zero(object->private.'.$type->{name}.', 8, CK_BYTE);
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }
    if (l != 8) {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, object->private.'.$type->{name}.', 8, CK_BYTE);

    return CKR_OK;
}

';
}

sub CK_PBE_PARAMS_pInitVector_DESTROY {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C '        /* uncoverable branch 1 */
        if (object->private.'.$type->{name}.') {
            Safefree(object->private.'.$type->{name}.');
        }
';
}

sub CK_PBE_PARAMS_pInitVector_fromBytes {
    my ($what, $struct, $c_struct, $lc_struct, $type) = @_;

    unless ($what) {
    print C '    /* uncoverable branch 1 */
    if (object->private.'.$type->{name}.') {
        Safefree(object->private.'.$type->{name}.');
    }
';
    }
    else {
    print C '    if (object->private.'.$type->{name}.') {
        CK_BYTE_PTR '.$type->{name}.' = 0;
        myNewxz('.$type->{name}.', 8, CK_BYTE);
        /* uncoverable branch 0 */
        if (!'.$type->{name}.') {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.'.$type->{name}.', '.$type->{name}.', 8, CK_BYTE);
        object->private.'.$type->{name}.' = '.$type->{name}.';
    }
    else {
        myNewxz(object->private.'.$type->{name}.', 8, CK_BYTE);
        /* uncoverable branch 0 */
        if (!object->private.'.$type->{name}.') {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
    }
';
    }
}

sub ck_ssl3_random_data {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_SSL3_RANDOM_DATA* sv) {
    CK_BYTE_PTR pClientRandom = NULL_PTR;
    CK_BYTE_PTR pServerRandom = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.'.$type->{name}.'.pClientRandom) {
        myNewxz(pClientRandom, object->private.'.$type->{name}.'.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }
    if (object->private.'.$type->{name}.'.pServerRandom) {
        myNewxz(pServerRandom, object->private.'.$type->{name}.'.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable begin */
            Safefree(pClientRandom);
            return CKR_HOST_MEMORY;
            /* uncoverable end */
        }
    }

    if (pClientRandom) {
        Copy(object->private.'.$type->{name}.'.pClientRandom, pClientRandom, object->private.'.$type->{name}.'.ulClientRandomLen, CK_BYTE);
    }
    if (pServerRandom) {
        Copy(object->private.'.$type->{name}.'.pServerRandom, pServerRandom, object->private.'.$type->{name}.'.ulServerRandomLen, CK_BYTE);
    }

    if (sv->private.pClientRandom) {
        Safefree(sv->private.pClientRandom);
    }
    if (sv->private.pServerRandom) {
        Safefree(sv->private.pServerRandom);
    }

    sv->private.pClientRandom = pClientRandom;
    sv->private.ulClientRandomLen = object->private.'.$type->{name}.'.ulClientRandomLen;
    sv->private.pServerRandom = pServerRandom;
    sv->private.ulServerRandomLen = object->private.'.$type->{name}.'.ulServerRandomLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_SSL3_RANDOM_DATA* sv) {
    CK_BYTE_PTR pClientRandom = NULL_PTR;
    CK_BYTE_PTR pServerRandom = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (sv->private.pClientRandom) {
        myNewxz(pClientRandom, sv->private.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }
    if (sv->private.pServerRandom) {
        myNewxz(pServerRandom, sv->private.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable begin */
            Safefree(pClientRandom);
            return CKR_HOST_MEMORY;
            /* uncoverable end */
        }
    }

    if (pClientRandom) {
        Copy(sv->private.pClientRandom, pClientRandom, sv->private.ulClientRandomLen, CK_BYTE);
    }
    if (pServerRandom) {
        Copy(sv->private.pServerRandom, pServerRandom, sv->private.ulServerRandomLen, CK_BYTE);
    }

    if (object->private.'.$type->{name}.'.pClientRandom) {
        Safefree(object->private.'.$type->{name}.'.pClientRandom);
    }
    if (object->private.'.$type->{name}.'.pServerRandom) {
        Safefree(object->private.'.$type->{name}.'.pServerRandom);
    }

    object->private.'.$type->{name}.'.pClientRandom = pClientRandom;
    object->private.'.$type->{name}.'.ulClientRandomLen = sv->private.ulClientRandomLen;
    object->private.'.$type->{name}.'.pServerRandom = pServerRandom;
    object->private.'.$type->{name}.'.ulServerRandomLen = sv->private.ulServerRandomLen;

    return CKR_OK;
}

';
}

sub ck_ssl3_random_data_fromBytes {
    my ($what, $struct, $c_struct, $lc_struct, $type) = @_;

    unless ($what) {
    print C '    if (object->private.'.$type->{name}.'.pClientRandom) {
        Safefree(object->private.'.$type->{name}.'.pClientRandom);
    }
    if (object->private.'.$type->{name}.'.pServerRandom) {
        Safefree(object->private.'.$type->{name}.'.pServerRandom);
    }
';
    }
    else {
    print C '    if (object->private.'.$type->{name}.'.pClientRandom) {
        CK_BYTE_PTR pClientRandom = 0;
        myNewxz(pClientRandom, object->private.'.$type->{name}.'.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.'.$type->{name}.'.pClientRandom, pClientRandom, object->private.'.$type->{name}.'.ulClientRandomLen, CK_BYTE);
        object->private.'.$type->{name}.'.pClientRandom = pClientRandom;
    }
    if (object->private.'.$type->{name}.'.pServerRandom) {
        CK_BYTE_PTR pServerRandom = 0;
        myNewxz(pServerRandom, object->private.'.$type->{name}.'.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.'.$type->{name}.'.pServerRandom, pServerRandom, object->private.'.$type->{name}.'.ulServerRandomLen, CK_BYTE);
        object->private.'.$type->{name}.'.pServerRandom = pServerRandom;
    }
';
    }
}

sub ck_ssl3_random_data_DESTROY {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C '        if (object->private.'.$type->{name}.'.pClientRandom) {
            Safefree(object->private.'.$type->{name}.'.pClientRandom);
        }
        if (object->private.'.$type->{name}.'.pServerRandom) {
            Safefree(object->private.'.$type->{name}.'.pServerRandom);
        }
';
}

sub ck_ssl3_random_data_hh {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print H 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$_->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_SSL3_RANDOM_DATA* sv);
CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$_->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_SSL3_RANDOM_DATA* sv);
';
}

sub ck_ssl3_random_data_xs {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print XS 'CK_RV
crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    Crypt::PKCS11::CK_SSL3_RANDOM_DATA* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

Crypt::PKCS11::CK_SSL3_RANDOM_DATA*
crypt_pkcs11_'.$lc_struct.'_'.$type->{name}.'(object)
    Crypt::PKCS11::'.$struct.'* object
PROTOTYPE: $
CODE:
    RETVAL = crypt_pkcs11_ck_ssl3_random_data_new("Crypt::PKCS11::CK_SSL3_RANDOM_DATA");
    crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    Crypt::PKCS11::CK_SSL3_RANDOM_DATA* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

';
}

sub CK_SSL3_KEY_MAT_OUT {
    if ($_[0] == 2) {
        print H '    CK_ULONG ulIVClient;
    CK_ULONG ulIVServer;
';
    }
}

sub CK_SSL3_KEY_MAT_OUT_pIVClient {
    my ($struct, $c_struct, $lc_struct, $type) = @_;
    my $ln = $type->{name};
    $ln =~ s/^p/ul/o;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.'.$type->{name}.', object->'.$ln.' * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

';
}

sub CK_SSL3_KEY_MAT_OUT_pIVServer {
    my ($struct, $c_struct, $lc_struct, $type) = @_;
    my $ln = $type->{name};
    $ln =~ s/^p/ul/o;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.'.$type->{name}.', object->'.$ln.' * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

';
}

sub ck_ssl3_key_mat_out_ptr {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* sv) {
    CK_BYTE_PTR pIVClient = NULL_PTR;
    CK_BYTE_PTR pIVServer = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((object->private.ulIVSizeInBits % 8)) {
        return CKR_GENERAL_ERROR;
    }

    if (object->private.ulIVSizeInBits) {
        myNewxz(pIVClient, object->private.ulIVSizeInBits / 8, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pIVClient) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }
    if (object->private.ulIVSizeInBits) {
        myNewxz(pIVServer, object->private.ulIVSizeInBits / 8, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pIVServer) {
            /* uncoverable begin */
            Safefree(pIVClient);
            return CKR_HOST_MEMORY;
            /* uncoverable end */
        }
    }

    /* uncoverable branch 2 */
    if (pIVClient && object->'.$type->{name}.'.pIVClient) {
        /* uncoverable block 0 */
        Copy(object->'.$type->{name}.'.pIVClient, pIVClient, (object->private.ulIVSizeInBits / 8), CK_BYTE);
    }
    /* uncoverable branch 2 */
    if (pIVServer && object->'.$type->{name}.'.pIVServer) {
        /* uncoverable block 0 */
        Copy(object->'.$type->{name}.'.pIVServer, pIVServer, (object->private.ulIVSizeInBits / 8), CK_BYTE);
    }

    if (sv->private.pIVClient) {
        Safefree(sv->private.pIVClient);
    }
    if (sv->private.pIVServer) {
        Safefree(sv->private.pIVServer);
    }

    sv->private.hClientMacSecret = object->'.$type->{name}.'.hClientMacSecret;
    sv->private.hServerMacSecret = object->'.$type->{name}.'.hServerMacSecret;
    sv->private.hClientKey = object->'.$type->{name}.'.hClientKey;
    sv->private.hServerKey = object->'.$type->{name}.'.hServerKey;
    sv->private.pIVClient = pIVClient;

    if (pIVClient) {
        sv->ulIVClient = (object->private.ulIVSizeInBits / 8) * sizeof(CK_BYTE);
    }
    else {
        sv->ulIVClient = 0;
    }
    sv->private.pIVServer = pIVServer;
    if (pIVServer) {
        sv->ulIVServer = (object->private.ulIVSizeInBits / 8) * sizeof(CK_BYTE);
    }
    else {
        sv->ulIVServer = 0;
    }

    return CKR_OK;
}

';
}

sub ck_ssl3_key_mat_out_ptr_DESTROY {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C '        if (object->'.$type->{name}.'.pIVClient) {
            Safefree(object->'.$type->{name}.'.pIVClient);
        }
        if (object->'.$type->{name}.'.pIVServer) {
            Safefree(object->'.$type->{name}.'.pIVServer);
        }
';
}

sub ck_ssl3_key_mat_out_ptr_h {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print H '    CK_SSL3_KEY_MAT_OUT '.$type->{name}.';
';
}

sub ck_ssl3_key_mat_out_ptr_hh {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print H 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$_->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* sv);
';
}

sub ck_ssl3_key_mat_out_ptr_xs {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print XS 'CK_RV
crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT*
crypt_pkcs11_'.$lc_struct.'_'.$type->{name}.'(object)
    Crypt::PKCS11::'.$struct.'* object
PROTOTYPE: $
CODE:
    RETVAL = crypt_pkcs11_ck_ssl3_key_mat_out_new("Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT");
    crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'(object, RETVAL);
OUTPUT:
    RETVAL

';
}

sub CK_WTLS_MASTER_KEY_DERIVE_PARAMS {
    if ($_[0] == 1) {
        print C '        object->private.pVersion = 0;
        myNewxz(object->private.pVersion, 1, CK_BYTE);
        /* uncoverable branch 0 */
        if (!object->private.pVersion) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
';
    }
}

sub CK_WTLS_MASTER_KEY_DERIVE_PARAMS_pVersion {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, *(object->private.'.$type->{name}.'));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

';
}

sub CK_WTLS_MASTER_KEY_DERIVE_PARAMS_pVersion_DESTROY {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C '        /* uncoverable branch 1 */
        if (object->private.'.$type->{name}.') {
            Safefree(object->private.'.$type->{name}.');
        }
';
}

sub CK_WTLS_MASTER_KEY_DERIVE_PARAMS_pVersion_fromBytes {
    my ($what, $struct, $c_struct, $lc_struct, $type) = @_;

    unless ($what) {
    print C '    /* uncoverable branch 1 */
    if (object->private.'.$type->{name}.') {
        Safefree(object->private.'.$type->{name}.');
    }
';
    }
    else {
    print C '    /* uncoverable branch 1 */
    if (object->private.'.$type->{name}.') {
        CK_BYTE_PTR '.$type->{name}.' = 0;
        myNewxz('.$type->{name}.', 1, CK_BYTE);
        /* uncoverable branch 0 */
        if (!'.$type->{name}.') {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.'.$type->{name}.', '.$type->{name}.', 1, CK_BYTE);
        object->private.'.$type->{name}.' = '.$type->{name}.';
    }
';
    }
}

sub ck_wtls_random_data {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_WTLS_RANDOM_DATA* sv) {
    CK_BYTE_PTR pClientRandom = NULL_PTR;
    CK_BYTE_PTR pServerRandom = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.'.$type->{name}.'.pClientRandom) {
        myNewxz(pClientRandom, object->private.'.$type->{name}.'.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }
    if (object->private.'.$type->{name}.'.pServerRandom) {
        myNewxz(pServerRandom, object->private.'.$type->{name}.'.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable begin */
            Safefree(pClientRandom);
            return CKR_HOST_MEMORY;
            /* uncoverable end */
        }
    }

    if (pClientRandom) {
        Copy(object->private.'.$type->{name}.'.pClientRandom, pClientRandom, object->private.'.$type->{name}.'.ulClientRandomLen, CK_BYTE);
    }
    if (pServerRandom) {
        Copy(object->private.'.$type->{name}.'.pServerRandom, pServerRandom, object->private.'.$type->{name}.'.ulServerRandomLen, CK_BYTE);
    }

    if (sv->private.pClientRandom) {
        Safefree(sv->private.pClientRandom);
    }
    if (sv->private.pServerRandom) {
        Safefree(sv->private.pServerRandom);
    }

    sv->private.pClientRandom = pClientRandom;
    sv->private.ulClientRandomLen = object->private.'.$type->{name}.'.ulClientRandomLen;
    sv->private.pServerRandom = pServerRandom;
    sv->private.ulServerRandomLen = object->private.'.$type->{name}.'.ulServerRandomLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_WTLS_RANDOM_DATA* sv) {
    CK_BYTE_PTR pClientRandom = NULL_PTR;
    CK_BYTE_PTR pServerRandom = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (sv->private.pClientRandom) {
        myNewxz(pClientRandom, sv->private.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }
    if (sv->private.pServerRandom) {
        myNewxz(pServerRandom, sv->private.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable begin */
            Safefree(pClientRandom);
            return CKR_HOST_MEMORY;
            /* uncoverable end */
        }
    }

    if (pClientRandom) {
        Copy(sv->private.pClientRandom, pClientRandom, sv->private.ulClientRandomLen, CK_BYTE);
    }
    if (pServerRandom) {
        Copy(sv->private.pServerRandom, pServerRandom, sv->private.ulServerRandomLen, CK_BYTE);
    }

    if (object->private.'.$type->{name}.'.pClientRandom) {
        Safefree(object->private.'.$type->{name}.'.pClientRandom);
    }
    if (object->private.'.$type->{name}.'.pServerRandom) {
        Safefree(object->private.'.$type->{name}.'.pServerRandom);
    }

    object->private.'.$type->{name}.'.pClientRandom = pClientRandom;
    object->private.'.$type->{name}.'.ulClientRandomLen = sv->private.ulClientRandomLen;
    object->private.'.$type->{name}.'.pServerRandom = pServerRandom;
    object->private.'.$type->{name}.'.ulServerRandomLen = sv->private.ulServerRandomLen;

    return CKR_OK;
}

';
}

sub ck_wtls_random_data_fromBytes {
    my ($what, $struct, $c_struct, $lc_struct, $type) = @_;

    unless ($what) {
    print C '    if (object->private.'.$type->{name}.'.pClientRandom) {
        Safefree(object->private.'.$type->{name}.'.pClientRandom);
    }
    if (object->private.'.$type->{name}.'.pServerRandom) {
        Safefree(object->private.'.$type->{name}.'.pServerRandom);
    }
';
    }
    else {
    print C '    if (object->private.'.$type->{name}.'.pClientRandom) {
        CK_BYTE_PTR pClientRandom = 0;
        myNewxz(pClientRandom, object->private.'.$type->{name}.'.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.'.$type->{name}.'.pClientRandom, pClientRandom, object->private.'.$type->{name}.'.ulClientRandomLen, CK_BYTE);
        object->private.'.$type->{name}.'.pClientRandom = pClientRandom;
    }
    if (object->private.'.$type->{name}.'.pServerRandom) {
        CK_BYTE_PTR pServerRandom = 0;
        myNewxz(pServerRandom, object->private.'.$type->{name}.'.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.'.$type->{name}.'.pServerRandom, pServerRandom, object->private.'.$type->{name}.'.ulServerRandomLen, CK_BYTE);
        object->private.'.$type->{name}.'.pServerRandom = pServerRandom;
    }
';
    }
}

sub ck_wtls_random_data_DESTROY {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C '        if (object->private.'.$type->{name}.'.pClientRandom) {
            Safefree(object->private.'.$type->{name}.'.pClientRandom);
        }
        if (object->private.'.$type->{name}.'.pServerRandom) {
            Safefree(object->private.'.$type->{name}.'.pServerRandom);
        }
';
}

sub ck_wtls_random_data_hh {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print H 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$_->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_WTLS_RANDOM_DATA* sv);
CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$_->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_WTLS_RANDOM_DATA* sv);
';
}

sub ck_wtls_random_data_xs {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print XS 'CK_RV
crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    Crypt::PKCS11::CK_WTLS_RANDOM_DATA* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

Crypt::PKCS11::CK_WTLS_RANDOM_DATA*
crypt_pkcs11_'.$lc_struct.'_'.$type->{name}.'(object)
    Crypt::PKCS11::'.$struct.'* object
PROTOTYPE: $
CODE:
    RETVAL = crypt_pkcs11_ck_wtls_random_data_new("Crypt::PKCS11::CK_WTLS_RANDOM_DATA");
    crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    Crypt::PKCS11::CK_WTLS_RANDOM_DATA* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

';
}

sub CK_WTLS_KEY_MAT_OUT {
    if ($_[0] == 2) {
        print H '    CK_ULONG ulIV;
';
    }
}

sub CK_WTLS_KEY_MAT_OUT_pIV {
    my ($struct, $c_struct, $lc_struct, $type) = @_;
    my $ln = $type->{name};
    $ln =~ s/^p/ul/o;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.'.$type->{name}.', object->'.$ln.' * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

';
}

sub ck_wtls_key_mat_out_ptr {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* sv) {
    CK_BYTE_PTR pIV = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((object->private.ulIVSizeInBits % 8)) {
        return CKR_GENERAL_ERROR;
    }

    if (object->private.ulIVSizeInBits) {
        myNewxz(pIV, object->private.ulIVSizeInBits / 8, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pIV) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }

    /* uncoverable branch 2 */
    if (pIV && object->'.$type->{name}.'.pIV) {
        /* uncoverable block 0 */
        Copy(object->'.$type->{name}.'.pIV, pIV, (object->private.ulIVSizeInBits / 8), CK_BYTE);
    }

    if (sv->private.pIV) {
        Safefree(sv->private.pIV);
    }

    sv->private.hMacSecret = object->'.$type->{name}.'.hMacSecret;
    sv->private.hKey = object->'.$type->{name}.'.hKey;
    sv->private.pIV = pIV;
    if (pIV) {
        sv->ulIV = (object->private.ulIVSizeInBits / 8) * sizeof(CK_BYTE);
    }
    else {
        sv->ulIV = 0;
    }

    return CKR_OK;
}

';
}

sub ck_wtls_key_mat_out_ptr_DESTROY {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C '        if (object->'.$type->{name}.'.pIV) {
            Safefree(object->'.$type->{name}.'.pIV);
        }
';
}

sub ck_wtls_key_mat_out_ptr_h {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print H '    CK_WTLS_KEY_MAT_OUT '.$type->{name}.';
';
}

sub ck_wtls_key_mat_out_ptr_hh {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print H 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$_->{name}.'('.$c_struct.'* object, Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* sv);
';
}

sub ck_wtls_key_mat_out_ptr_xs {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print XS 'CK_RV
crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT*
crypt_pkcs11_'.$lc_struct.'_'.$type->{name}.'(object)
    Crypt::PKCS11::'.$struct.'* object
PROTOTYPE: $
CODE:
    RETVAL = crypt_pkcs11_ck_wtls_key_mat_out_new("Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT");
    crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'(object, RETVAL);
OUTPUT:
    RETVAL

';
}

sub CK_CMS_SIG_PARAMS_pContentType {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpv(sv, object->private.'.$type->{name}.');
    sv_utf8_upgrade_nomg(sv);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    CK_CHAR_PTR n = 0;
    CK_CHAR_PTR p;
    STRLEN l;
    SV* _sv;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.'.$type->{name}.') {
            Safefree(object->private.'.$type->{name}.');
            object->private.'.$type->{name}.' = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(_sv = newSVsv(sv))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }
    sv_2mortal(_sv);

    sv_utf8_downgrade(_sv, 0);
    if (!(p = SvPV(_sv, l))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }

    myNewxz(n, l + 1, CK_CHAR);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_CHAR);
    if (object->private.'.$type->{name}.') {
        Safefree(object->private.'.$type->{name}.');
    }
    object->private.'.$type->{name}.' = n;

    return CKR_OK;
}

';
}

sub CK_CMS_SIG_PARAMS_pContentType_fromBytes {
    my ($what, $struct, $c_struct, $lc_struct, $type) = @_;

    unless ($what) {
    print C '    if (object->private.'.$type->{name}.') {
        Safefree(object->private.'.$type->{name}.');
    }
';
    }
    else {
    print C '    if (object->private.'.$type->{name}.') {
        CK_CHAR_PTR '.$type->{name}.' = savepv(object->private.'.$type->{name}.');
        /* uncoverable branch 0 */
        if (!'.$type->{name}.') {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        object->private.'.$type->{name}.' = '.$type->{name}.';
    }
';
    }
}

sub ck_otp_param_ptr {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, AV* sv) {
    CK_ULONG ulCount;
    Crypt__PKCS11__CK_OTP_PARAM* param;
    SV* paramSV;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(object->private.ulCount)) {
        return CKR_OK;
    }

    for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
        param = 0;
        myNewxz(param, 1, Crypt__PKCS11__CK_OTP_PARAM);
        /* uncoverable branch 0 */
        if (!param) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }

        param->private.type = object->private.'.$type->{name}.'[ulCount].type;
        /* uncoverable branch 1 */
        if (object->private.'.$type->{name}.'[ulCount].pValue) {
            myNewxz(param->private.pValue, object->private.'.$type->{name}.'[ulCount].ulValueLen, CK_BYTE);
            /* uncoverable branch 0 */
            if (!param->private.pValue) {
                /* uncoverable begin */
                Safefree(param);
                return CKR_HOST_MEMORY;
                /* uncoverable end */
            }
            Copy(object->private.'.$type->{name}.'[ulCount].pValue, param->private.pValue, object->private.'.$type->{name}.'[ulCount].ulValueLen, CK_BYTE);
            param->private.ulValueLen = object->private.'.$type->{name}.'[ulCount].ulValueLen;
        }

        paramSV = sv_setref_pv(newSV(0), "Crypt::PKCS11::CK_OTP_PARAMPtr", param);
        av_push(sv, paramSV);
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, AV* sv) {
    CK_ULONG ulCount;
    I32 key;
    SV** item;
    SV* entry;
    IV tmp;
    Crypt__PKCS11__CK_OTP_PARAM* param;
    CK_OTP_PARAM_PTR params = 0;
    CK_ULONG paramCount = 0;
    CK_RV rv = CKR_OK;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    for (key = 0; key < av_len(sv) + 1; key++) {
        item = av_fetch(sv, key, 0);

        /* uncoverable begin */
        if (!item || !*item || !SvROK(*item)
        /* uncoverable end */
            || !sv_derived_from(*item, "Crypt::PKCS11::CK_OTP_PARAMPtr"))
        {
            return CKR_ARGUMENTS_BAD;
        }

        paramCount++;
    }

    myNewxz(params, paramCount, CK_OTP_PARAM);
    /* uncoverable branch 0 */
    if (!params) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    for (key = 0; key < av_len(sv) + 1; key++) {
        item = av_fetch(sv, key, 0);

        /* uncoverable begin */
        if (!item || !*item || !SvROK(*item)
            || !sv_derived_from(*item, "Crypt::PKCS11::CK_OTP_PARAMPtr"))
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        tmp = SvIV((SV*)SvRV(*item));
        if (!(param = INT2PTR(Crypt__PKCS11__CK_OTP_PARAM*, tmp))) {
            rv = CKR_GENERAL_ERROR;
            break;
        }
        /* uncoverable end */

        params[key].type = param->private.type;
        /* uncoverable branch 1 */
        if (param->private.pValue) {
            myNewxz(params[key].pValue, param->private.ulValueLen, CK_BYTE);
            /* uncoverable branch 0 */
            if (!params[key].pValue) {
                /* uncoverable begin */
                rv = CKR_HOST_MEMORY;
                break;
                /* uncoverable end */
            }

            Copy(param->private.pValue, params[key].pValue, param->private.ulValueLen, CK_BYTE);
            params[key].ulValueLen = param->private.ulValueLen;
        }
    }

    /* uncoverable begin */
    if (rv != CKR_OK) {
        for (ulCount = 0; ulCount < paramCount; ulCount++) {
            if (params[ulCount].pValue) {
                Safefree(params[ulCount].pValue);
            }
        }
        Safefree(params);
        return rv;
    }
    /* uncoverable end */

    if (object->private.'.$type->{name}.') {
        for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
            /* uncoverable branch 1 */
            if (object->private.'.$type->{name}.'[ulCount].pValue) {
                Safefree(object->private.'.$type->{name}.'[ulCount].pValue);
            }
        }
        Safefree(object->private.'.$type->{name}.');
    }
    object->private.'.$type->{name}.' = params;
    object->private.ulCount = paramCount;

    return CKR_OK;
}

';
}

sub ck_otp_param_ptr_fromBytes {
    my ($what, $struct, $c_struct, $lc_struct, $type) = @_;

    unless ($what) {
    print C '    if (object->private.'.$type->{name}.') {
        CK_ULONG ulCount;
        for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
            /* uncoverable branch 1 */
            if (object->private.'.$type->{name}.'[ulCount].pValue) {
                Safefree(object->private.'.$type->{name}.'[ulCount].pValue);
            }
        }
        Safefree(object->private.'.$type->{name}.');
    }
';
    }
    else {
    print C '    if (object->private.'.$type->{name}.') {
        CK_OTP_PARAM_PTR params = 0;
        CK_ULONG ulCount;

        myNewxz(params, object->private.ulCount, CK_OTP_PARAM);
        /* uncoverable branch 0 */
        if (!params) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }

        for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
            params[ulCount].type = object->private.'.$type->{name}.'[ulCount].type;
            /* uncoverable branch 1 */
            if (object->private.'.$type->{name}.'[ulCount].pValue) {
                myNewxz(params[ulCount].pValue, object->private.'.$type->{name}.'[ulCount].ulValueLen, CK_BYTE);
                /* uncoverable branch 0 */
                if (!params[ulCount].pValue) {
                    /* uncoverable block 0 */
                    __croak("memory allocation error");
                }
                Copy(object->private.'.$type->{name}.'[ulCount].pValue, params[ulCount].pValue, object->private.'.$type->{name}.'[ulCount].ulValueLen, CK_BYTE);
            }
        }
        object->private.'.$type->{name}.' = params;
    }
';
    }
}

sub ck_otp_param_ptr_DESTROY {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C '        if (object->private.'.$type->{name}.') {
            CK_ULONG ulCount;
            for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
                /* uncoverable branch 1 */
                if (object->private.'.$type->{name}.'[ulCount].pValue) {
                    Safefree(object->private.'.$type->{name}.'[ulCount].pValue);
                }
            }
            Safefree(object->private.'.$type->{name}.');
        }
';
}

sub ck_otp_param_ptr_hh {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print H 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$_->{name}.'('.$c_struct.'* object, AV* sv);
CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$_->{name}.'('.$c_struct.'* object, AV* sv);
';
}

sub ck_otp_param_ptr_xs {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print XS 'CK_RV
crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    AV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

AV*
crypt_pkcs11_'.$lc_struct.'_'.$type->{name}.'(object)
    Crypt::PKCS11::'.$struct.'* object
PROTOTYPE: $
CODE:
    RETVAL = newAV();
    sv_2mortal((SV*)RETVAL);
    crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'(object, sv)
    Crypt::PKCS11::'.$struct.'* object
    AV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

';
}

sub CK_OTP_PARAMS_ulCount {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.'.$type->{name}.');
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

';
}

sub CK_OTP_SIGNATURE_INFO_ulCount {
    my ($struct, $c_struct, $lc_struct, $type) = @_;

    print C 'CK_RV crypt_pkcs11_'.$lc_struct.'_get_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.'.$type->{name}.');
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_'.$lc_struct.'_set_'.$type->{name}.'('.$c_struct.'* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

';
}
