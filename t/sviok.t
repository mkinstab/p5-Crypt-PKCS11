#!perl -T

use Test::More tests => 2;

use Crypt::PKCS11;

BEGIN {
    is( Crypt::PKCS11::XS::SvIOK(1), 1, 'SvIOK(1)' );
    is( Crypt::PKCS11::XS::SvIOK('1'), 0, 'SvIOK("1")' );
}
