#!perl

use Test::More;
use Crypt::PKCS11 qw(:constant);
use Scalar::Util qw(blessed);

$obj = eval {
    local $SIG{__WARN__} = sub {};
    Crypt::PKCS11::new;
};
ok( blessed $obj, 'Crypt::PKCS11::new' );
isa_ok( $obj = Crypt::PKCS11->new, 'Crypt::PKCS11', 'Crypt::PKCS11->new' );
isa_ok( $obj = $obj->new, 'Crypt::PKCS11', '$obj->new' );
$@ = undef; eval { $obj->load(undef); };
ok( $@, '$obj->load(undef)' );
is( $obj->load('FAKE'), undef, '$obj->load(FAKE)' );
is( $obj->unload, undef, '$obj->unload' );
$@ = undef; eval { $obj->Initialize(undef); };
ok( $@, '$obj->Initialize(undef)' );
is( $obj->Initialize({}), undef, '$obj->Initialize({})' );
$@ = undef; eval { $obj->Initialize({ CreateMutex => undef }); };
ok( $@, '$obj->Initialize({ CreateMutex => undef })' );
$@ = undef; eval { $obj->Initialize({ DestroyMutex => undef }); };
ok( $@, '$obj->Initialize({ DestroyMutex => undef })' );
$@ = undef; eval { $obj->Initialize({ LockMutex => undef }); };
ok( $@, '$obj->Initialize({ LockMutex => undef })' );
$@ = undef; eval { $obj->Initialize({ UnlockMutex => undef }); };
ok( $@, '$obj->Initialize({ UnlockMutex => undef })' );
$@ = undef; eval { $obj->Initialize({ CreateMutex => sub{} }); };
ok( $@, '$obj->Initialize({ CreateMutex => sub{} })' );
$@ = undef; eval { $obj->Initialize({ CreateMutex => sub{}, DestroyMutex => sub{} }); };
ok( $@, '$obj->Initialize({ CreateMutex => sub{}, DestroyMutex => sub{} })' );
$@ = undef; eval { $obj->Initialize({ CreateMutex => sub{}, DestroyMutex => sub{}, LockMutex => sub{} }); };
ok( $@, '$obj->Initialize({ CreateMutex => sub{}, DestroyMutex => sub{}, LockMutex => sub{} })' );
is( $obj->Initialize({ CreateMutex => sub{}, DestroyMutex => sub{}, LockMutex => sub{}, UnlockMutex => sub{} }), undef, '$obj->Initialize({ CreateMutex => sub{}, DestroyMutex => sub{}, LockMutex => sub{}, UnlockMutex => sub{} })' );
is( $obj->Finalize, undef, '$obj->Finalize' );
is( $obj->GetInfo, undef, '$obj->GetInfo' );

$rv = 0;
if ($ENV{TEST_DEVEL_COVER}) {
    $xs = Crypt::PKCS11::XS->new;
    $xs->load('TEST_DEVEL_COVER');
    $rv = $xs->test_devel_cover;
}
is( $rv, 0, 'Failed on line '.$rv );

*Crypt::PKCS11::XS::new = sub ($) {};
eval {
    Crypt::PKCS11->new;
};
ok( $@, '*Crypt::PKCS11::XS::new undef' );

done_testing;
