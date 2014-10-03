# Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
# Copyright (c) 2014 .SE (The Internet Infrastructure Foundation)
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

package Crypt::PKCS11::Attributes;

use strict;
use warnings;
use Carp;

use Crypt::PKCS11 qw(:constant);

sub new {
    my $this = shift;
    my $class = ref($this) || $this;
    my %args = ( @_ );
    my $self = {
    };
    bless $self, $class;

    return $self;
}

package Crypt::PKCS11::Attribute::Class;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_CLASS }

package Crypt::PKCS11::Attribute::Token;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_TOKEN }

package Crypt::PKCS11::Attribute::Private;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_PRIVATE }

package Crypt::PKCS11::Attribute::Label;
use base qw(Crypt::PKCS11::Attribute::RFC2279string);
sub type () { CKA_LABEL }

package Crypt::PKCS11::Attribute::Application;
use base qw(Crypt::PKCS11::Attribute::RFC2279string);
sub type () { CKA_APPLICATION }

package Crypt::PKCS11::Attribute::Value;
use base qw(Crypt::PKCS11::Attribute::Value);
sub type () { CKA_VALUE }

package Crypt::PKCS11::Attribute::ObjectId;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_OBJECT_ID }

package Crypt::PKCS11::Attribute::CertificateType;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_CERTIFICATE_TYPE }

package Crypt::PKCS11::Attribute::Issuer;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_ISSUER }

package Crypt::PKCS11::Attribute::SerialNumber;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_SERIAL_NUMBER }

package Crypt::PKCS11::Attribute::AcIssuer;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_AC_ISSUER }

package Crypt::PKCS11::Attribute::Owner;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_OWNER }

package Crypt::PKCS11::Attribute::AttrTypes;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_ATTR_TYPES }

package Crypt::PKCS11::Attribute::Trusted;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_TRUSTED }

package Crypt::PKCS11::Attribute::CertificateCategory;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_CERTIFICATE_CATEGORY }

package Crypt::PKCS11::Attribute::JavaMidpSecurityDomain;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_JAVA_MIDP_SECURITY_DOMAIN }

package Crypt::PKCS11::Attribute::Url;
use base qw(Crypt::PKCS11::Attribute::RFC2279string);
sub type () { CKA_URL }

package Crypt::PKCS11::Attribute::HashOfSubjectPublicKey;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_HASH_OF_SUBJECT_PUBLIC_KEY }

package Crypt::PKCS11::Attribute::HashOfIssuerPublicKey;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_HASH_OF_ISSUER_PUBLIC_KEY }

package Crypt::PKCS11::Attribute::NameHashAlgorithm;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_NAME_HASH_ALGORITHM }

package Crypt::PKCS11::Attribute::CheckValue;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_CHECK_VALUE }

package Crypt::PKCS11::Attribute::KeyType;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_KEY_TYPE }

package Crypt::PKCS11::Attribute::Subject;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_SUBJECT }

package Crypt::PKCS11::Attribute::Id;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_ID }

package Crypt::PKCS11::Attribute::Sensitive;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_SENSITIVE }

package Crypt::PKCS11::Attribute::Encrypt;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_ENCRYPT }

package Crypt::PKCS11::Attribute::Decrypt;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_DECRYPT }

package Crypt::PKCS11::Attribute::Wrap;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_WRAP }

package Crypt::PKCS11::Attribute::Unwrap;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_UNWRAP }

package Crypt::PKCS11::Attribute::Sign;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_SIGN }

package Crypt::PKCS11::Attribute::SignRecover;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_SIGN_RECOVER }

package Crypt::PKCS11::Attribute::Verify;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_VERIFY }

package Crypt::PKCS11::Attribute::VerifyRecover;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_VERIFY_RECOVER }

package Crypt::PKCS11::Attribute::Derive;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_DERIVE }

package Crypt::PKCS11::Attribute::StartDate;
use base qw(Crypt::PKCS11::Attribute::CK_DATE);
sub type () { CKA_START_DATE }

package Crypt::PKCS11::Attribute::EndDate;
use base qw(Crypt::PKCS11::Attribute::CK_DATE);
sub type () { CKA_END_DATE }

package Crypt::PKCS11::Attribute::Modulus;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_MODULUS }

package Crypt::PKCS11::Attribute::ModulusBits;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_MODULUS_BITS }

package Crypt::PKCS11::Attribute::PublicExponent;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_PUBLIC_EXPONENT }

package Crypt::PKCS11::Attribute::PrivateExponent;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_PRIVATE_EXPONENT }

package Crypt::PKCS11::Attribute::Prime1;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_PRIME_1 }

package Crypt::PKCS11::Attribute::Prime2;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_PRIME_2 }

package Crypt::PKCS11::Attribute::Exponent1;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_EXPONENT_1 }

package Crypt::PKCS11::Attribute::Exponent2;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_EXPONENT_2 }

package Crypt::PKCS11::Attribute::Coefficient;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_COEFFICIENT }

package Crypt::PKCS11::Attribute::Prime;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_PRIME }

package Crypt::PKCS11::Attribute::Subprime;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_SUBPRIME }

package Crypt::PKCS11::Attribute::Base;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_BASE }

package Crypt::PKCS11::Attribute::PrimeBits;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_PRIME_BITS }

package Crypt::PKCS11::Attribute::SubprimeBits;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_SUBPRIME_BITS }

package Crypt::PKCS11::Attribute::SubPrimeBits;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_SUB_PRIME_BITS }

package Crypt::PKCS11::Attribute::ValueBits;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_VALUE_BITS }

package Crypt::PKCS11::Attribute::ValueLen;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_VALUE_LEN }

package Crypt::PKCS11::Attribute::Extractable;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_EXTRACTABLE }

package Crypt::PKCS11::Attribute::Local;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_LOCAL }

package Crypt::PKCS11::Attribute::NeverExtractable;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_NEVER_EXTRACTABLE }

package Crypt::PKCS11::Attribute::AlwaysSensitive;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_ALWAYS_SENSITIVE }

package Crypt::PKCS11::Attribute::KeyGenMechanism;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_KEY_GEN_MECHANISM }

package Crypt::PKCS11::Attribute::Modifiable;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_MODIFIABLE }

package Crypt::PKCS11::Attribute::Copyable;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_COPYABLE }

package Crypt::PKCS11::Attribute::EcdsaParams;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_ECDSA_PARAMS }

package Crypt::PKCS11::Attribute::EcParams;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_EC_PARAMS }

package Crypt::PKCS11::Attribute::EcPoint;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_EC_POINT }

package Crypt::PKCS11::Attribute::SecondaryAuth;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_SECONDARY_AUTH }

package Crypt::PKCS11::Attribute::AuthPinFlags;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_AUTH_PIN_FLAGS }

package Crypt::PKCS11::Attribute::AlwaysAuthenticate;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_ALWAYS_AUTHENTICATE }

package Crypt::PKCS11::Attribute::WrapWithTrusted;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_WRAP_WITH_TRUSTED }

package Crypt::PKCS11::Attribute::WrapTemplate;
use base qw(Crypt::PKCS11::Attribute::CK_ATTRIBUTE_PTR);
sub type () { CKA_WRAP_TEMPLATE }

package Crypt::PKCS11::Attribute::UnwrapTemplate;
use base qw(Crypt::PKCS11::Attribute::CK_ATTRIBUTE_PTR);
sub type () { CKA_UNWRAP_TEMPLATE }

package Crypt::PKCS11::Attribute::DeriveTemplate;
use base qw(Crypt::PKCS11::Attribute::CK_ATTRIBUTE_PTR);
sub type () { CKA_DERIVE_TEMPLATE }

package Crypt::PKCS11::Attribute::OtpFormat;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_OTP_FORMAT }

package Crypt::PKCS11::Attribute::OtpLength;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_OTP_LENGTH }

package Crypt::PKCS11::Attribute::OtpTimeInterval;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_OTP_TIME_INTERVAL }

package Crypt::PKCS11::Attribute::OtpUserFriendlyMode;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_OTP_USER_FRIENDLY_MODE }

package Crypt::PKCS11::Attribute::OtpChallengeRequirement;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_OTP_CHALLENGE_REQUIREMENT }

package Crypt::PKCS11::Attribute::OtpTimeRequirement;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_OTP_TIME_REQUIREMENT }

package Crypt::PKCS11::Attribute::OtpCounterRequirement;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_OTP_COUNTER_REQUIREMENT }

package Crypt::PKCS11::Attribute::OtpPinRequirement;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_OTP_PIN_REQUIREMENT }

package Crypt::PKCS11::Attribute::OtpCounter;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_OTP_COUNTER }

package Crypt::PKCS11::Attribute::OtpTime;
use base qw(Crypt::PKCS11::Attribute::RFC2279string);
sub type () { CKA_OTP_TIME }

package Crypt::PKCS11::Attribute::OtpUserIdentifier;
use base qw(Crypt::PKCS11::Attribute::RFC2279string);
sub type () { CKA_OTP_USER_IDENTIFIER }

package Crypt::PKCS11::Attribute::OtpServiceIdentifier;
use base qw(Crypt::PKCS11::Attribute::RFC2279string);
sub type () { CKA_OTP_SERVICE_IDENTIFIER }

package Crypt::PKCS11::Attribute::OtpServiceLogo;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_OTP_SERVICE_LOGO }

package Crypt::PKCS11::Attribute::OtpServiceLogoType;
use base qw(Crypt::PKCS11::Attribute::RFC2279string);
sub type () { CKA_OTP_SERVICE_LOGO_TYPE }

package Crypt::PKCS11::Attribute::Gostr3410Params;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_GOSTR3410_PARAMS }

package Crypt::PKCS11::Attribute::Gostr3411Params;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_GOSTR3411_PARAMS }

package Crypt::PKCS11::Attribute::Gost28147Params;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_GOST28147_PARAMS }

package Crypt::PKCS11::Attribute::HwFeatureType;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_HW_FEATURE_TYPE }

package Crypt::PKCS11::Attribute::ResetOnInit;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_RESET_ON_INIT }

package Crypt::PKCS11::Attribute::HasReset;
use base qw(Crypt::PKCS11::Attribute::CK_BBOOL);
sub type () { CKA_HAS_RESET }

package Crypt::PKCS11::Attribute::PixelX;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_PIXEL_X }

package Crypt::PKCS11::Attribute::PixelY;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_PIXEL_Y }

package Crypt::PKCS11::Attribute::Resolution;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_RESOLUTION }

package Crypt::PKCS11::Attribute::CharRows;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_CHAR_ROWS }

package Crypt::PKCS11::Attribute::CharColumns;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_CHAR_COLUMNS }

package Crypt::PKCS11::Attribute::Color;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_COLOR }

package Crypt::PKCS11::Attribute::BitsPerPixel;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_BITS_PER_PIXEL }

package Crypt::PKCS11::Attribute::CharSets;
use base qw(Crypt::PKCS11::Attribute::RFC2279string);
sub type () { CKA_CHAR_SETS }

package Crypt::PKCS11::Attribute::EncodingMethods;
use base qw(Crypt::PKCS11::Attribute::RFC2279string);
sub type () { CKA_ENCODING_METHODS }

package Crypt::PKCS11::Attribute::MimeTypes;
use base qw(Crypt::PKCS11::Attribute::RFC2279string);
sub type () { CKA_MIME_TYPES }

package Crypt::PKCS11::Attribute::MechanismType;
use base qw(Crypt::PKCS11::Attribute::CK_ULONG);
sub type () { CKA_MECHANISM_TYPE }

package Crypt::PKCS11::Attribute::RequiredCmsAttributes;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_REQUIRED_CMS_ATTRIBUTES }

package Crypt::PKCS11::Attribute::DefaultCmsAttributes;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_DEFAULT_CMS_ATTRIBUTES }

package Crypt::PKCS11::Attribute::SupportedCmsAttributes;
use base qw(Crypt::PKCS11::Attribute::ByteArray);
sub type () { CKA_SUPPORTED_CMS_ATTRIBUTES }

package Crypt::PKCS11::Attribute::AllowedMechanisms;
use base qw(Crypt::PKCS11::Attribute::CK_MECHANISM_TYPE_PTR);
sub type () { CKA_ALLOWED_MECHANISMS }

package Crypt::PKCS11::Attribute::VendorDefined;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);
sub type () { CKA_VENDOR_DEFINED }

1;

__END__
