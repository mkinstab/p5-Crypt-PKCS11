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

package Crypt::PKCS11::Session;

use strict;
use warnings;
use Carp;
use Scalar::Util qw(blessed);

use Crypt::PKCS11 qw(:constant);
use Crypt::PKCS11::Object;

sub new {
    my $this = shift;
    my $class = ref($this) || $this;
    my $self = {
        pkcs11xs => undef,
        session => undef,
        rv => CKR_OK
    };
    bless $self, $class;

    unless (blessed($self->{pkcs11xs} = shift) and $self->{pkcs11xs}->isa('Crypt::PKCS11::XSPtr')) {
        confess 'first argument is not a Crypt::PKCS11::XSPtr';
    }
    unless (defined ($self->{session} = shift)) {
        confess 'second argument is not a session';
    }

    return $self;
}

sub DESTROY {
    if (exists $_[0]->{session}) {
        $_[0]->{pkcs11xs}->C_CloseSession($_[0]->{session});
    }
}

sub InitPIN {
    confess 'Not implemeneted!';
}

sub SetPIN {
    confess 'Not implemeneted!';
}

sub CloseSession {
    my ($self) = @_;

    unless (exists $self->{session}) {
        confess 'session is closed';
    }

    $self->{rv} = $self->{pkcs11xs}->C_CloseSession($self->{session});
    if ($self->{rv} == CKR_OK) {
        delete $self->{session};
    }
    return $self->{rv} == CKR_OK ? 1 : undef;
}

sub GetSessionInfo {
    confess 'Not implemeneted!';
}

sub GetOperationState {
    confess 'Not implemeneted!';
}

sub SetOperationState {
    confess 'Not implemeneted!';
}

sub Login {
    my ($self, $userType, $pin) = @_;

    unless (exists $self->{session}) {
        confess 'session is closed';
    }
    unless (defined $userType) {
        confess '$userType must be defined';
    }

    $self->{rv} = $self->{pkcs11xs}->C_Login($self->{session}, $userType, $pin);
    return $self->{rv} == CKR_OK ? 1 : undef;
}

sub Logout {
    my ($self) = @_;

    unless (exists $self->{session}) {
        confess 'session is closed';
    }

    $self->{rv} = $self->{pkcs11xs}->C_Logout($self->{session});
    return $self->{rv} == CKR_OK ? 1 : undef;
}

sub CreateObject {
    confess 'Not implemeneted!';
}

sub CopyObject {
    confess 'Not implemeneted!';
}

sub DestroyObject {
    confess 'Not implemeneted!';
}

sub GetObjectSize {
    confess 'Not implemeneted!';
}

sub GetAttributeValue {
    confess 'Not implemeneted!';
}

sub SetAttributeValue {
    confess 'Not implemeneted!';
}

sub FindObjectsInit {
    confess 'Not implemeneted!';
}

sub FindObjects {
    confess 'Not implemeneted!';
}

sub FindObjectsFinal {
    confess 'Not implemeneted!';
}

sub EncryptInit {
    confess 'Not implemeneted!';
}

sub Encrypt {
    confess 'Not implemeneted!';
}

sub EncryptUpdate {
    confess 'Not implemeneted!';
}

sub EncryptFinal {
    confess 'Not implemeneted!';
}

sub DecryptInit {
    confess 'Not implemeneted!';
}

sub Decrypt {
    confess 'Not implemeneted!';
}

sub DecryptUpdate {
    confess 'Not implemeneted!';
}

sub DecryptFinal {
    confess 'Not implemeneted!';
}

sub DigestInit {
    confess 'Not implemeneted!';
}

sub Digest {
    confess 'Not implemeneted!';
}

sub DigestUpdate {
    confess 'Not implemeneted!';
}

sub DigestKey {
    confess 'Not implemeneted!';
}

sub DigestFinal {
    confess 'Not implemeneted!';
}

sub SignInit {
    confess 'Not implemeneted!';
}

sub Sign {
    confess 'Not implemeneted!';
}

sub SignUpdate {
    confess 'Not implemeneted!';
}

sub SignFinal {
    confess 'Not implemeneted!';
}

sub SignRecoverInit {
    confess 'Not implemeneted!';
}

sub SignRecover {
    confess 'Not implemeneted!';
}

sub VerifyInit {
    confess 'Not implemeneted!';
}

sub Verify {
    confess 'Not implemeneted!';
}

sub VerifyUpdate {
    confess 'Not implemeneted!';
}

sub VerifyFinal {
    confess 'Not implemeneted!';
}

sub VerifyRecoverInit {
    confess 'Not implemeneted!';
}

sub VerifyRecover {
    confess 'Not implemeneted!';
}

sub DigestEncryptUpdate {
    confess 'Not implemeneted!';
}

sub DecryptDigestUpdate {
    confess 'Not implemeneted!';
}

sub SignEncryptUpdate {
    confess 'Not implemeneted!';
}

sub DecryptVerifyUpdate {
    confess 'Not implemeneted!';
}

sub GenerateKey {
    my ($self, $mechanism, $template) = @_;
    my $key;

    unless (exists $self->{session}) {
        confess 'session is closed';
    }
    unless (blessed($mechanism) and $mechanism->isa('Crypt::PKCS11::CK_MECHANISMPtr')) {
        confess '$mechanism is not a Crypt::PKCS11::CK_MECHANISMPtr';
    }
    unless (blessed($template) and $template->isa('Crypt::PKCS11::Attributes')) {
        confess '$template is not a Crypt::PKCS11::Attributes';
    }

    $self->{rv} = $self->{pkcs11xs}->C_GenerateKey($self->{session}, $mechanism->toHash, $template->toArray, $key);
    return $self->{rv} == CKR_OK ? Crypt::PKCS11::Object->new($key) : undef;
}

sub GenerateKeyPair {
    my ($self, $mechanism, $publicKeyTemplate, $privateKeyTemplate) = @_;
    my ($publicKey, $privateKey);
    my @keys;

    unless (exists $self->{session}) {
        confess 'session is closed';
    }
    unless (blessed($mechanism) and $mechanism->isa('Crypt::PKCS11::CK_MECHANISMPtr')) {
        confess '$mechanism is not a Crypt::PKCS11::CK_MECHANISMPtr';
    }
    unless (blessed($publicKeyTemplate) and $publicKeyTemplate->isa('Crypt::PKCS11::Attributes')) {
        confess '$publicKeyTemplate is not a Crypt::PKCS11::Attributes';
    }
    unless (blessed($privateKeyTemplate) and $privateKeyTemplate->isa('Crypt::PKCS11::Attributes')) {
        confess '$privateKeyTemplate is not a Crypt::PKCS11::Attributes';
    }

    $self->{rv} = $self->{pkcs11xs}->C_GenerateKeyPair($self->{session}, $mechanism->toHash, $publicKeyTemplate->toArray, $privateKeyTemplate->toArray, $publicKey, $privateKey);
    @keys = (
        Crypt::PKCS11::Object->new($publicKey),
        Crypt::PKCS11::Object->new($privateKey)
    );
    return $self->{rv} == CKR_OK ? wantarray ? @keys : \@keys : undef;
}

sub WrapKey {
    confess 'Not implemeneted!';
}

sub UnwrapKey {
    confess 'Not implemeneted!';
}

sub DeriveKey {
    confess 'Not implemeneted!';
}

sub SeedRandom {
    confess 'Not implemeneted!';
}

sub GenerateRandom {
    confess 'Not implemeneted!';
}

sub GetFunctionStatus {
    confess 'Not implemeneted!';
}

sub CancelFunction {
    confess 'Not implemeneted!';
}

sub errno {
    return $_[0]->{rv};
}

sub errstr {
    return Crypt::PKCS11::XS::rv2str($_[0]->{rv});
}

1;

__END__
