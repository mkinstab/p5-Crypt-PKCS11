#!perl

use Test::More;
use Crypt::PKCS11 qw(:constant);
use Crypt::PKCS11::Attribute;
use Crypt::PKCS11::Attributes;
use Crypt::PKCS11::Object;
use Crypt::PKCS11::Session;
use Scalar::Util qw(blessed);

# Crypt/PKCS11.pm

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
is( $obj->GetSlotList, undef, '$obj->GetSlotList' );
$@ = undef; eval { $obj->GetSlotInfo; };
ok( $@, '$obj->GetSlotInfo' );
is( $obj->GetSlotInfo(1), undef, '$obj->GetSlotInfo' );
$@ = undef; eval { $obj->GetTokenInfo; };
ok( $@, '$obj->GetTokenInfo' );
is( $obj->GetTokenInfo(1), undef, '$obj->GetTokenInfo' );
$@ = undef; eval { $obj->GetMechanismList; };
ok( $@, '$obj->GetMechanismList' );
is( $obj->GetMechanismList(1), undef, '$obj->GetMechanismList' );
$@ = undef; eval { $obj->GetMechanismInfo; };
ok( $@, '$obj->GetMechanismInfo' );
$@ = undef; eval { $obj->GetMechanismInfo(1); };
ok( $@, '$obj->GetMechanismInfo' );
is( $obj->GetMechanismInfo(1, 1), undef, '$obj->GetMechanismInfo' );
$@ = undef; eval { $obj->InitToken; };
ok( $@, '$obj->InitToken' );
$@ = undef; eval { $obj->InitToken(undef, undef); };
ok( $@, '$obj->InitToken(undef, undef)' );
$@ = undef; eval { $obj->InitToken(1, undef); };
ok( $@, '$obj->InitToken(1, undef)' );
is( $obj->InitToken(1, 1), undef, '$obj->InitToken' );
$@ = undef; eval { $obj->OpenSession(undef); };
ok( $@, '$obj->OpenSession(undef)' );
$@ = undef; eval { $obj->OpenSession(1, undef, 1); };
ok( $@, '$obj->OpenSession(1, undef, 1)' );
is( $obj->OpenSession(1, undef, sub{}), undef, '$obj->OpenSession(1, undef, sub{})' );
$@ = undef; eval { $obj->CloseAllSessions; };
ok( $@, '$obj->CloseAllSessions' );
is( $obj->CloseAllSessions(1), undef, '$obj->CloseAllSessions' );
is( $obj->WaitForSlotEvent, undef, '$obj->WaitForSlotEvent' );
ok( $obj->errno, '$obj->errno' );

$@ = undef; eval { Crypt::PKCS11::struct::toBytes; };
ok( $@, 'Crypt::PKCS11::struct::toBytes' );

my $mechanism = Crypt::PKCS11::CK_MECHANISM->new;
$mechanism->set_mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN);
$mechanism->set_pParameter('abc');
isa_ok( $mechanism->toHash, 'HASH', '$mechanism->toHash' );

$rv = 0;
if ($ENV{TEST_DEVEL_COVER}) {
    $xs = Crypt::PKCS11::XS->new;
    $xs->load('TEST_DEVEL_COVER');
    $rv = $xs->test_devel_cover;
}
is( $rv, 0, 'Failed on line '.$rv );

{
    local $SIG{__WARN__} = sub {};
    *Crypt::PKCS11::CK_MECHANISMPtr::get_pParameter = sub ($) { return CKR_GENERAL_ERROR; };
    $mechanism = Crypt::PKCS11::CK_MECHANISM->new;
    $@ = undef; eval { $mechanism->toHash; };
    ok( $@, '$mechanism->toHash' );
    *Crypt::PKCS11::CK_MECHANISMPtr::get_mechanism = sub ($) { return CKR_GENERAL_ERROR; };
    $mechanism = Crypt::PKCS11::CK_MECHANISM->new;
    $@ = undef; eval { $mechanism->toHash; };
    ok( $@, '$mechanism->toHash' );
}

# Crypt/PKCS11/Attribute.pm

$obj = eval {
    local $SIG{__WARN__} = sub {};
    Crypt::PKCS11::Attribute::new;
};
ok( blessed $obj, 'Crypt::PKCS11::Attribute::new' );
isa_ok( $obj = Crypt::PKCS11::Attribute->new, 'Crypt::PKCS11::Attribute', 'Crypt::PKCS11::Attribute->new' );
isa_ok( $obj = $obj->new, 'Crypt::PKCS11::Attribute', 'Crypt::PKCS11::Attribute $obj->new' );

# Crypt/PKCS11/Attributes.pm

$obj = eval {
    local $SIG{__WARN__} = sub {};
    Crypt::PKCS11::Attributes::new;
};
ok( blessed $obj, 'Crypt::PKCS11::Attributes::new' );
isa_ok( $obj = Crypt::PKCS11::Attributes->new, 'Crypt::PKCS11::Attributes', 'Crypt::PKCS11::Attributes->new' );
isa_ok( $obj = $obj->new, 'Crypt::PKCS11::Attributes', 'Crypt::PKCS11::Attributes $obj->new' );

# Crypt/PKCS11/Object.pm

$obj = eval {
    local $SIG{__WARN__} = sub {};
    Crypt::PKCS11::Object::new(undef, 1);
};
ok( blessed $obj, 'Crypt::PKCS11::Object::new' );
isa_ok( $obj = Crypt::PKCS11::Object->new(1), 'Crypt::PKCS11::Object', 'Crypt::PKCS11::Object->new' );
isa_ok( $obj = $obj->new(1), 'Crypt::PKCS11::Object', 'Crypt::PKCS11::Object $obj->new' );

# Crypt/PKCS11/Session.pm

$obj = eval {
    local $SIG{__WARN__} = sub {};
    Crypt::PKCS11::Session::new(undef, Crypt::PKCS11::XS->new, 1);
};
ok( blessed $obj, 'Crypt::PKCS11::Session::new' );
isa_ok( $obj = Crypt::PKCS11::Session->new(Crypt::PKCS11::XS->new, 1), 'Crypt::PKCS11::Session', 'Crypt::PKCS11::Session->new' );
isa_ok( $obj = $obj->new(Crypt::PKCS11::XS->new, 1), 'Crypt::PKCS11::Session', 'Crypt::PKCS11::Session $obj->new' );

# NOTE: This must run last!
{
    local $SIG{__WARN__} = sub {};
    *Crypt::PKCS11::XS::new = sub ($) {};
    $@ = undef; eval { Crypt::PKCS11->new; };
    ok( $@, '*Crypt::PKCS11::XS::new undef' );
}

done_testing;
