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
$@ = undef; eval { Crypt::PKCS11::Attribute->new(undef); };
ok( $@, 'Crypt::PKCS11::Attribute->new(undef)' );
isa_ok( $obj = Crypt::PKCS11::Attribute->new, 'Crypt::PKCS11::Attribute', 'Crypt::PKCS11::Attribute->new' );
isa_ok( $obj = $obj->new, 'Crypt::PKCS11::Attribute', 'Crypt::PKCS11::Attribute $obj->new' );
$@ = undef; eval { $obj->type; };
ok( $@, '$obj->type' );
$@ = undef; eval { $obj->set; };
ok( $@, '$obj->set' );
$@ = undef; eval { $obj->get; };
ok( $@, '$obj->get' );

# Crypt/PKCS11/Attributes.pm

$obj = eval {
    local $SIG{__WARN__} = sub {};
    Crypt::PKCS11::Attributes::new;
};
ok( blessed $obj, 'Crypt::PKCS11::Attributes::new' );
isa_ok( $obj = Crypt::PKCS11::Attributes->new, 'Crypt::PKCS11::Attributes', 'Crypt::PKCS11::Attributes->new' );
isa_ok( $obj = $obj->new, 'Crypt::PKCS11::Attributes', 'Crypt::PKCS11::Attributes $obj->new' );
$@ = undef; eval { $obj->push(undef); };
ok( $@, '$obj->push(undef)' );

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

ok( defined Crypt::PKCS11::CK_VERSION->new->major, 'Crypt::PKCS11::CK_VERSION->new->major' );
ok( defined Crypt::PKCS11::CK_VERSION->new->minor, 'Crypt::PKCS11::CK_VERSION->new->minor' );
ok( defined Crypt::PKCS11::CK_MECHANISM->new->mechanism, 'Crypt::PKCS11::CK_MECHANISM->new->mechanism' );
is( Crypt::PKCS11::CK_MECHANISM->new->pParameter, undef, 'Crypt::PKCS11::CK_MECHANISM->new->pParameter' );
ok( defined Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS->new->hashAlg, 'Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS->new->hashAlg' );
ok( defined Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS->new->mgf, 'Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS->new->mgf' );
ok( defined Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS->new->source, 'Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS->new->source' );
is( Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS->new->pSourceData, undef, 'Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS->new->pSourceData' );
ok( defined Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS->new->hashAlg, 'Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS->new->hashAlg' );
ok( defined Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS->new->mgf, 'Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS->new->mgf' );
ok( defined Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS->new->sLen, 'Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS->new->sLen' );
ok( defined Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS->new->kdf, 'Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS->new->kdf' );
is( Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS->new->pSharedData, undef, 'Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS->new->pSharedData' );
is( Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS->new->pPublicData, undef, 'Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS->new->pPublicData' );
ok( defined Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS->new->kdf, 'Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS->new->kdf' );
is( Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS->new->pSharedData, undef, 'Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS->new->pSharedData' );
is( Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS->new->pPublicData, undef, 'Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS->new->pPublicData' );
ok( defined Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS->new->hPrivateData, 'Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS->new->hPrivateData' );
is( Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS->new->pPublicData2, undef, 'Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS->new->pPublicData2' );
ok( defined Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS->new->kdf, 'Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS->new->kdf' );
is( Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS->new->pSharedData, undef, 'Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS->new->pSharedData' );
is( Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS->new->pPublicData, undef, 'Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS->new->pPublicData' );
ok( defined Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS->new->hPrivateData, 'Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS->new->hPrivateData' );
is( Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS->new->pPublicData2, undef, 'Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS->new->pPublicData2' );
ok( defined Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS->new->publicKey, 'Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS->new->publicKey' );
ok( defined Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS->new->kdf, 'Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS->new->kdf' );
is( Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS->new->pOtherInfo, undef, 'Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS->new->pOtherInfo' );
is( Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS->new->pPublicData, undef, 'Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS->new->pPublicData' );
ok( defined Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS->new->kdf, 'Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS->new->kdf' );
is( Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS->new->pOtherInfo, undef, 'Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS->new->pOtherInfo' );
is( Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS->new->pPublicData, undef, 'Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS->new->pPublicData' );
ok( defined Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS->new->hPrivateData, 'Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS->new->hPrivateData' );
is( Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS->new->pPublicData2, undef, 'Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS->new->pPublicData2' );
ok( defined Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS->new->kdf, 'Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS->new->kdf' );
is( Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS->new->pOtherInfo, undef, 'Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS->new->pOtherInfo' );
is( Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS->new->pPublicData, undef, 'Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS->new->pPublicData' );
ok( defined Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS->new->hPrivateData, 'Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS->new->hPrivateData' );
is( Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS->new->pPublicData2, undef, 'Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS->new->pPublicData2' );
ok( defined Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS->new->publicKey, 'Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS->new->publicKey' );
ok( defined Crypt::PKCS11::CK_KEA_DERIVE_PARAMS->new->isSender, 'Crypt::PKCS11::CK_KEA_DERIVE_PARAMS->new->isSender' );
is( Crypt::PKCS11::CK_KEA_DERIVE_PARAMS->new->pRandomA, undef, 'Crypt::PKCS11::CK_KEA_DERIVE_PARAMS->new->pRandomA' );
is( Crypt::PKCS11::CK_KEA_DERIVE_PARAMS->new->pRandomB, undef, 'Crypt::PKCS11::CK_KEA_DERIVE_PARAMS->new->pRandomB' );
is( Crypt::PKCS11::CK_KEA_DERIVE_PARAMS->new->pPublicData, undef, 'Crypt::PKCS11::CK_KEA_DERIVE_PARAMS->new->pPublicData' );
ok( defined Crypt::PKCS11::CK_RC2_CBC_PARAMS->new->ulEffectiveBits, 'Crypt::PKCS11::CK_RC2_CBC_PARAMS->new->ulEffectiveBits' );
ok( defined Crypt::PKCS11::CK_RC2_CBC_PARAMS->new->iv, 'Crypt::PKCS11::CK_RC2_CBC_PARAMS->new->iv' );
ok( defined Crypt::PKCS11::CK_RC2_MAC_GENERAL_PARAMS->new->ulEffectiveBits, 'Crypt::PKCS11::CK_RC2_MAC_GENERAL_PARAMS->new->ulEffectiveBits' );
ok( defined Crypt::PKCS11::CK_RC5_PARAMS->new->ulWordsize, 'Crypt::PKCS11::CK_RC5_PARAMS->new->ulWordsize' );
ok( defined Crypt::PKCS11::CK_RC5_PARAMS->new->ulRounds, 'Crypt::PKCS11::CK_RC5_PARAMS->new->ulRounds' );
ok( defined Crypt::PKCS11::CK_RC5_CBC_PARAMS->new->ulWordsize, 'Crypt::PKCS11::CK_RC5_CBC_PARAMS->new->ulWordsize' );
ok( defined Crypt::PKCS11::CK_RC5_CBC_PARAMS->new->ulRounds, 'Crypt::PKCS11::CK_RC5_CBC_PARAMS->new->ulRounds' );
is( Crypt::PKCS11::CK_RC5_CBC_PARAMS->new->pIv, undef, 'Crypt::PKCS11::CK_RC5_CBC_PARAMS->new->pIv' );
ok( defined Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS->new->ulWordsize, 'Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS->new->ulWordsize' );
ok( defined Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS->new->ulRounds, 'Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS->new->ulRounds' );
ok( defined Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS->new->iv, 'Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS->new->iv' );
is( Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS->new->pData, undef, 'Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS->new->pData' );
ok( defined Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS->new->iv, 'Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS->new->iv' );
is( Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS->new->pData, undef, 'Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS->new->pData' );
is( Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS->new->pPassword, undef, 'Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS->new->pPassword' );
is( Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS->new->pPublicData, undef, 'Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS->new->pPublicData' );
is( Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS->new->pRandomA, undef, 'Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS->new->pRandomA' );
is( Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS->new->pPrimeP, undef, 'Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS->new->pPrimeP' );
is( Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS->new->pBaseG, undef, 'Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS->new->pBaseG' );
is( Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS->new->pSubprimeQ, undef, 'Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS->new->pSubprimeQ' );
is( Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS->new->pOldWrappedX, undef, 'Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS->new->pOldWrappedX' );
is( Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS->new->pOldPassword, undef, 'Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS->new->pOldPassword' );
is( Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS->new->pOldPublicData, undef, 'Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS->new->pOldPublicData' );
is( Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS->new->pOldRandomA, undef, 'Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS->new->pOldRandomA' );
is( Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS->new->pNewPassword, undef, 'Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS->new->pNewPassword' );
is( Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS->new->pNewPublicData, undef, 'Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS->new->pNewPublicData' );
is( Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS->new->pNewRandomA, undef, 'Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS->new->pNewRandomA' );
ok( defined Crypt::PKCS11::CK_PBE_PARAMS->new->pInitVector, 'Crypt::PKCS11::CK_PBE_PARAMS->new->pInitVector' );
ok( defined Crypt::PKCS11::CK_PBE_PARAMS->new->pPassword, 'Crypt::PKCS11::CK_PBE_PARAMS->new->pPassword' );
is( Crypt::PKCS11::CK_PBE_PARAMS->new->pSalt, undef, 'Crypt::PKCS11::CK_PBE_PARAMS->new->pSalt' );
ok( defined Crypt::PKCS11::CK_PBE_PARAMS->new->ulIteration, 'Crypt::PKCS11::CK_PBE_PARAMS->new->ulIteration' );
ok( defined Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS->new->bBC, 'Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS->new->bBC' );
is( Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS->new->pX, undef, 'Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS->new->pX' );
is( Crypt::PKCS11::CK_SSL3_RANDOM_DATA->new->pClientRandom, undef, 'Crypt::PKCS11::CK_SSL3_RANDOM_DATA->new->pClientRandom' );
is( Crypt::PKCS11::CK_SSL3_RANDOM_DATA->new->pServerRandom, undef, 'Crypt::PKCS11::CK_SSL3_RANDOM_DATA->new->pServerRandom' );
ok( defined Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS->new->RandomInfo, 'Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS->new->RandomInfo' );
ok( defined Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS->new->pVersion, 'Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS->new->pVersion' );
ok( defined Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT->new->hClientMacSecret, 'Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT->new->hClientMacSecret' );
ok( defined Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT->new->hServerMacSecret, 'Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT->new->hServerMacSecret' );
ok( defined Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT->new->hClientKey, 'Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT->new->hClientKey' );
ok( defined Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT->new->hServerKey, 'Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT->new->hServerKey' );
is( Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT->new->pIVClient, undef, 'Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT->new->pIVClient' );
is( Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT->new->pIVServer, undef, 'Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT->new->pIVServer' );
ok( defined Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS->new->ulMacSizeInBits, 'Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS->new->ulMacSizeInBits' );
ok( defined Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS->new->ulKeySizeInBits, 'Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS->new->ulKeySizeInBits' );
ok( defined Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS->new->ulIVSizeInBits, 'Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS->new->ulIVSizeInBits' );
ok( defined Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS->new->bIsExport, 'Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS->new->bIsExport' );
ok( defined Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS->new->RandomInfo, 'Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS->new->RandomInfo' );
ok( defined Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS->new->pReturnedKeyMaterial, 'Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS->new->pReturnedKeyMaterial' );
is( Crypt::PKCS11::CK_TLS_PRF_PARAMS->new->pSeed, undef, 'Crypt::PKCS11::CK_TLS_PRF_PARAMS->new->pSeed' );
is( Crypt::PKCS11::CK_TLS_PRF_PARAMS->new->pLabel, undef, 'Crypt::PKCS11::CK_TLS_PRF_PARAMS->new->pLabel' );
is( Crypt::PKCS11::CK_TLS_PRF_PARAMS->new->pOutput, undef, 'Crypt::PKCS11::CK_TLS_PRF_PARAMS->new->pOutput' );
is( Crypt::PKCS11::CK_WTLS_RANDOM_DATA->new->pClientRandom, undef, 'Crypt::PKCS11::CK_WTLS_RANDOM_DATA->new->pClientRandom' );
is( Crypt::PKCS11::CK_WTLS_RANDOM_DATA->new->pServerRandom, undef, 'Crypt::PKCS11::CK_WTLS_RANDOM_DATA->new->pServerRandom' );
ok( defined Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS->new->DigestMechanism, 'Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS->new->DigestMechanism' );
ok( defined Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS->new->RandomInfo, 'Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS->new->RandomInfo' );
ok( defined Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS->new->pVersion, 'Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS->new->pVersion' );
ok( defined Crypt::PKCS11::CK_WTLS_PRF_PARAMS->new->DigestMechanism, 'Crypt::PKCS11::CK_WTLS_PRF_PARAMS->new->DigestMechanism' );
is( Crypt::PKCS11::CK_WTLS_PRF_PARAMS->new->pSeed, undef, 'Crypt::PKCS11::CK_WTLS_PRF_PARAMS->new->pSeed' );
is( Crypt::PKCS11::CK_WTLS_PRF_PARAMS->new->pLabel, undef, 'Crypt::PKCS11::CK_WTLS_PRF_PARAMS->new->pLabel' );
is( Crypt::PKCS11::CK_WTLS_PRF_PARAMS->new->pOutput, undef, 'Crypt::PKCS11::CK_WTLS_PRF_PARAMS->new->pOutput' );
ok( defined Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT->new->hMacSecret, 'Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT->new->hMacSecret' );
ok( defined Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT->new->hKey, 'Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT->new->hKey' );
is( Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT->new->pIV, undef, 'Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT->new->pIV' );
ok( defined Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS->new->DigestMechanism, 'Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS->new->DigestMechanism' );
ok( defined Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS->new->ulMacSizeInBits, 'Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS->new->ulMacSizeInBits' );
ok( defined Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS->new->ulKeySizeInBits, 'Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS->new->ulKeySizeInBits' );
ok( defined Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS->new->ulIVSizeInBits, 'Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS->new->ulIVSizeInBits' );
ok( defined Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS->new->ulSequenceNumber, 'Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS->new->ulSequenceNumber' );
ok( defined Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS->new->bIsExport, 'Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS->new->bIsExport' );
ok( defined Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS->new->RandomInfo, 'Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS->new->RandomInfo' );
ok( defined Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS->new->pReturnedKeyMaterial, 'Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS->new->pReturnedKeyMaterial' );
ok( defined Crypt::PKCS11::CK_CMS_SIG_PARAMS->new->certificateHandle, 'Crypt::PKCS11::CK_CMS_SIG_PARAMS->new->certificateHandle' );
ok( defined Crypt::PKCS11::CK_CMS_SIG_PARAMS->new->pSigningMechanism, 'Crypt::PKCS11::CK_CMS_SIG_PARAMS->new->pSigningMechanism' );
ok( defined Crypt::PKCS11::CK_CMS_SIG_PARAMS->new->pDigestMechanism, 'Crypt::PKCS11::CK_CMS_SIG_PARAMS->new->pDigestMechanism' );
ok( defined Crypt::PKCS11::CK_CMS_SIG_PARAMS->new->pContentType, 'Crypt::PKCS11::CK_CMS_SIG_PARAMS->new->pContentType' );
is( Crypt::PKCS11::CK_CMS_SIG_PARAMS->new->pRequestedAttributes, undef, 'Crypt::PKCS11::CK_CMS_SIG_PARAMS->new->pRequestedAttributes' );
is( Crypt::PKCS11::CK_CMS_SIG_PARAMS->new->pRequiredAttributes, undef, 'Crypt::PKCS11::CK_CMS_SIG_PARAMS->new->pRequiredAttributes' );
is( Crypt::PKCS11::CK_KEY_DERIVATION_STRING_DATA->new->pData, undef, 'Crypt::PKCS11::CK_KEY_DERIVATION_STRING_DATA->new->pData' );
ok( defined Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS->new->saltSource, 'Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS->new->saltSource' );
is( Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS->new->pSaltSourceData, undef, 'Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS->new->pSaltSourceData' );
ok( defined Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS->new->iterations, 'Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS->new->iterations' );
ok( defined Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS->new->prf, 'Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS->new->prf' );
is( Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS->new->pPrfData, undef, 'Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS->new->pPrfData' );
is( Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS->new->pPassword, undef, 'Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS->new->pPassword' );
ok( defined Crypt::PKCS11::CK_OTP_PARAM->new->type, 'Crypt::PKCS11::CK_OTP_PARAM->new->type' );
is( Crypt::PKCS11::CK_OTP_PARAM->new->pValue, undef, 'Crypt::PKCS11::CK_OTP_PARAM->new->pValue' );
ok( defined Crypt::PKCS11::CK_OTP_PARAMS->new->pParams, 'Crypt::PKCS11::CK_OTP_PARAMS->new->pParams' );
ok( defined Crypt::PKCS11::CK_OTP_PARAMS->new->ulCount, 'Crypt::PKCS11::CK_OTP_PARAMS->new->ulCount' );
ok( defined Crypt::PKCS11::CK_OTP_SIGNATURE_INFO->new->pParams, 'Crypt::PKCS11::CK_OTP_SIGNATURE_INFO->new->pParams' );
ok( defined Crypt::PKCS11::CK_OTP_SIGNATURE_INFO->new->ulCount, 'Crypt::PKCS11::CK_OTP_SIGNATURE_INFO->new->ulCount' );
ok( defined Crypt::PKCS11::CK_KIP_PARAMS->new->pMechanism, 'Crypt::PKCS11::CK_KIP_PARAMS->new->pMechanism' );
ok( defined Crypt::PKCS11::CK_KIP_PARAMS->new->hKey, 'Crypt::PKCS11::CK_KIP_PARAMS->new->hKey' );
is( Crypt::PKCS11::CK_KIP_PARAMS->new->pSeed, undef, 'Crypt::PKCS11::CK_KIP_PARAMS->new->pSeed' );
ok( defined Crypt::PKCS11::CK_AES_CTR_PARAMS->new->ulCounterBits, 'Crypt::PKCS11::CK_AES_CTR_PARAMS->new->ulCounterBits' );
ok( defined Crypt::PKCS11::CK_AES_CTR_PARAMS->new->cb, 'Crypt::PKCS11::CK_AES_CTR_PARAMS->new->cb' );
is( Crypt::PKCS11::CK_AES_GCM_PARAMS->new->pIv, undef, 'Crypt::PKCS11::CK_AES_GCM_PARAMS->new->pIv' );
ok( defined Crypt::PKCS11::CK_AES_GCM_PARAMS->new->ulIvBits, 'Crypt::PKCS11::CK_AES_GCM_PARAMS->new->ulIvBits' );
is( Crypt::PKCS11::CK_AES_GCM_PARAMS->new->pAAD, undef, 'Crypt::PKCS11::CK_AES_GCM_PARAMS->new->pAAD' );
ok( defined Crypt::PKCS11::CK_AES_GCM_PARAMS->new->ulTagBits, 'Crypt::PKCS11::CK_AES_GCM_PARAMS->new->ulTagBits' );
is( Crypt::PKCS11::CK_AES_CCM_PARAMS->new->pNonce, undef, 'Crypt::PKCS11::CK_AES_CCM_PARAMS->new->pNonce' );
is( Crypt::PKCS11::CK_AES_CCM_PARAMS->new->pAAD, undef, 'Crypt::PKCS11::CK_AES_CCM_PARAMS->new->pAAD' );
ok( defined Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS->new->ulCounterBits, 'Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS->new->ulCounterBits' );
ok( defined Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS->new->cb, 'Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS->new->cb' );
ok( defined Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS->new->iv, 'Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS->new->iv' );
is( Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS->new->pData, undef, 'Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS->new->pData' );
ok( defined Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS->new->iv, 'Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS->new->iv' );
is( Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS->new->pData, undef, 'Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS->new->pData' );

# NOTE: This must run last!
{
    local $SIG{__WARN__} = sub {};
    *Crypt::PKCS11::XS::new = sub ($) {};
    $@ = undef; eval { Crypt::PKCS11->new; };
    ok( $@, '*Crypt::PKCS11::XS::new undef' );
}

done_testing;
