#!perl

use Test::More;
use Crypt::PKCS11;

if ($ENV{TEST_DEVEL_COVER}) {
    $xs = Crypt::PKCS11::XS->new;
    $xs->load('TEST_DEVEL_COVER');
    $xs->test_devel_cover;
}
ok( 1 );
done_testing;
