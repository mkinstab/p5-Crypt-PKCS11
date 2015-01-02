#!perl

use Test::More;
use Crypt::PKCS11;

$rv = 0;
if ($ENV{TEST_DEVEL_COVER}) {
    $xs = Crypt::PKCS11::XS->new;
    $xs->load('TEST_DEVEL_COVER');
    $rv = $xs->test_devel_cover;
}
is( $rv, 0, 'Failed on line '.$rv );
done_testing;
