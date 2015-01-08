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
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;
use Carp;

my %TYPE = (
    AC_ISSUER => 'ByteArray',
    ALLOWED_MECHANISMS => 'CK_MECHANISM_TYPE_PTR',
    ALWAYS_AUTHENTICATE => 'CK_BBOOL',
    ALWAYS_SENSITIVE => 'CK_BBOOL',
    APPLICATION => 'RFC2279string',
    ATTR_TYPES => 'ByteArray',
    AUTH_PIN_FLAGS => 'CK_ULONG',
    BASE => 'ByteArray',
    BITS_PER_PIXEL => 'CK_ULONG',
    CERTIFICATE_CATEGORY => 'CK_ULONG',
    CERTIFICATE_TYPE => 'CK_ULONG',
    CHAR_COLUMNS => 'CK_ULONG',
    CHAR_ROWS => 'CK_ULONG',
    CHAR_SETS => 'RFC2279string',
    CHECK_VALUE => 'ByteArray',
    CLASS => 'CK_ULONG',
    COEFFICIENT => 'ByteArray',
    COLOR => 'CK_ULONG',
    COPYABLE => 'CK_BBOOL',
    DECRYPT => 'CK_BBOOL',
    DEFAULT_CMS_ATTRIBUTES => 'ByteArray',
    DERIVE => 'CK_BBOOL',
    DERIVE_TEMPLATE => 'CK_ATTRIBUTE_PTR',
    ECDSA_PARAMS => 'ByteArray',
    EC_PARAMS => 'ByteArray',
    EC_POINT => 'ByteArray',
    ENCODING_METHODS => 'RFC2279string',
    ENCRYPT => 'CK_BBOOL',
    END_DATE => 'CK_DATE',
    EXPONENT_1 => 'ByteArray',
    EXPONENT_2 => 'ByteArray',
    EXTRACTABLE => 'CK_BBOOL',
    GOST28147_PARAMS => 'ByteArray',
    GOSTR3410_PARAMS => 'ByteArray',
    GOSTR3411_PARAMS => 'ByteArray',
    HASH_OF_ISSUER_PUBLIC_KEY => 'ByteArray',
    HASH_OF_SUBJECT_PUBLIC_KEY => 'ByteArray',
    HAS_RESET => 'CK_BBOOL',
    HW_FEATURE_TYPE => 'CK_ULONG',
    ID => 'ByteArray',
    ISSUER => 'ByteArray',
    JAVA_MIDP_SECURITY_DOMAIN => 'CK_ULONG',
    KEY_GEN_MECHANISM => 'CK_ULONG',
    KEY_TYPE => 'CK_ULONG',
    LABEL => 'RFC2279string',
    LOCAL => 'CK_BBOOL',
    MECHANISM_TYPE => 'CK_ULONG',
    MIME_TYPES => 'RFC2279string',
    MODIFIABLE => 'CK_BBOOL',
    MODULUS_BITS => 'CK_ULONG',
    MODULUS => 'ByteArray',
    NAME_HASH_ALGORITHM => 'CK_ULONG',
    NEVER_EXTRACTABLE => 'CK_BBOOL',
    OBJECT_ID => 'ByteArray',
    OTP_CHALLENGE_REQUIREMENT => 'CK_ULONG',
    OTP_COUNTER => 'ByteArray',
    OTP_COUNTER_REQUIREMENT => 'CK_ULONG',
    OTP_FORMAT => 'CK_ULONG',
    OTP_LENGTH => 'CK_ULONG',
    OTP_PIN_REQUIREMENT => 'CK_ULONG',
    OTP_SERVICE_IDENTIFIER => 'RFC2279string',
    OTP_SERVICE_LOGO => 'ByteArray',
    OTP_SERVICE_LOGO_TYPE => 'RFC2279string',
    OTP_TIME => 'RFC2279string',
    OTP_TIME_INTERVAL => 'CK_ULONG',
    OTP_TIME_REQUIREMENT => 'CK_ULONG',
    OTP_USER_FRIENDLY_MODE => 'CK_BBOOL',
    OTP_USER_IDENTIFIER => 'RFC2279string',
    OWNER => 'ByteArray',
    PIXEL_X => 'CK_ULONG',
    PIXEL_Y => 'CK_ULONG',
    PRIME_1 => 'ByteArray',
    PRIME_2 => 'ByteArray',
    PRIME_BITS => 'CK_ULONG',
    PRIME => 'ByteArray',
    PRIVATE => 'CK_BBOOL',
    PRIVATE_EXPONENT => 'ByteArray',
    PUBLIC_EXPONENT => 'ByteArray',
    REQUIRED_CMS_ATTRIBUTES => 'ByteArray',
    RESET_ON_INIT => 'CK_BBOOL',
    RESOLUTION => 'CK_ULONG',
    SECONDARY_AUTH => 'CK_BBOOL',
    SENSITIVE => 'CK_BBOOL',
    SERIAL_NUMBER => 'ByteArray',
    SIGN => 'CK_BBOOL',
    SIGN_RECOVER => 'CK_BBOOL',
    START_DATE => 'CK_DATE',
    SUBJECT => 'ByteArray',
    SUB_PRIME_BITS => 'CK_ULONG',
    SUBPRIME_BITS => 'CK_ULONG',
    SUBPRIME => 'ByteArray',
    SUPPORTED_CMS_ATTRIBUTES => 'ByteArray',
    TOKEN => 'CK_BBOOL',
    TRUSTED => 'CK_BBOOL',
    UNWRAP => 'CK_BBOOL',
    UNWRAP_TEMPLATE => 'CK_ATTRIBUTE_PTR',
    URL => 'RFC2279string',
    VALUE_BITS => 'CK_ULONG',
    VALUE => 'Value',
    VALUE_LEN => 'CK_ULONG',
    VENDOR_DEFINED => 'CK_BYTE',
    VERIFY => 'CK_BBOOL',
    VERIFY_RECOVER => 'CK_BBOOL',
    WRAP => 'CK_BBOOL',
    WRAP_TEMPLATE => 'CK_ATTRIBUTE_PTR',
    WRAP_WITH_TRUSTED => 'CK_BBOOL',
);

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

print 'our %ATTRIBUTE_MAP = (
';
open(HEADER, 'pkcs11t.h') || confess;
while (<HEADER>) {
    s/[\r\n]+$//o;

    if (/#define CKA_(\S+)/o) {
        my $attribute = $1;
        my $camelize = camelize(lc($attribute));

print '    CKA_'.$attribute.' => \'Crypt::PKCS11::Attribute::'.$camelize.'\'
';
    }
}
close(HEADER);
print ');

';

open(HEADER, 'pkcs11t.h') || confess;
while (<HEADER>) {
    s/[\r\n]+$//o;

    if (/#define CKA_(\S+)/o) {
        my $attribute = $1;
        my $camelize = camelize(lc($attribute));

        confess unless (exists $TYPE{$attribute});

        print 'package Crypt::PKCS11::Attribute::'.$camelize.';
use base qw(Crypt::PKCS11::Attribute::'.$TYPE{$attribute}.');
sub type () { CKA_'.$attribute.' }

';
    }
}
close(HEADER);
