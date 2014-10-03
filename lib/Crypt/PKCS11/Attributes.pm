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
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Token;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Private;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Label;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Application;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Value;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::ObjectId;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::CertificateType;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Issuer;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::SerialNumber;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::AcIssuer;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Owner;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::AttrTypes;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Trusted;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::CertificateCategory;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::JavaMidpSecurityDomain;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Url;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::HashOfSubjectPublicKey;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::HashOfIssuerPublicKey;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::CheckValue;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::KeyType;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Subject;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Id;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Sensitive;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Encrypt;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Decrypt;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Wrap;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Unwrap;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Sign;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::SignRecover;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Verify;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::VerifyRecover;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Derive;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::StartDate;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::EndDate;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Modulus;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::ModulusBits;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::PublicExponent;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::PrivateExponent;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Prime1;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Prime2;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Exponent1;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Exponent2;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Coefficient;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Prime;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Subprime;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Base;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::PrimeBits;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::SubprimeBits;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::SubPrimeBits;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::ValueBits;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::ValueLen;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Extractable;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Local;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::NeverExtractable;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::AlwaysSensitive;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::KeyGenMechanism;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Modifiable;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::EcdsaParams;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::EcParams;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::EcPoint;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::SecondaryAuth;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::AuthPinFlags;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::AlwaysAuthenticate;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::WrapWithTrusted;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::WrapTemplate;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::UnwrapTemplate;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::DeriveTemplate;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::OtpFormat;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::OtpLength;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::OtpTimeInterval;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::OtpUserFriendlyMode;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::OtpChallengeRequirement;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::OtpTimeRequirement;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::OtpCounterRequirement;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::OtpPinRequirement;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::OtpCounter;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::OtpTime;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::OtpUserIdentifier;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::OtpServiceIdentifier;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::OtpServiceLogo;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::OtpServiceLogoType;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Gostr3410Params;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Gostr3411Params;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Gost28147Params;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::HwFeatureType;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::ResetOnInit;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::HasReset;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::PixelX;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::PixelY;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Resolution;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::CharRows;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::CharColumns;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::Color;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::BitsPerPixel;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::CharSets;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::EncodingMethods;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::MimeTypes;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::MechanismType;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::RequiredCmsAttributes;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::DefaultCmsAttributes;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::SupportedCmsAttributes;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::AllowedMechanisms;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

package Crypt::PKCS11::Attribute::VendorDefined;
use base qw(Crypt::PKCS11::Attribute::CK_BYTE);

1;

__END__
