#!perl

use Config;
use constant HAVE_LEAKTRACE => eval{ require Test::LeakTrace };
use Test::More;

use Crypt::PKCS11 qw(:constant);

our $LEAK_TESTING;

our $slotWithToken;
our $slotWithNoToken;
our $slotWithNotInitToken;
our $slotInvalid;

sub myisa_ok {
    my ($obj, $class, $name) = @_;

    unless ($LEAK_TESTING) {
        isa_ok( $obj, $class, $name );
    }
}

sub myis {
    my ($a, $b, $n) = @_;

    unless ($LEAK_TESTING) {
        is( $a, $b, $n );
    }
}

sub myis2 {
    my $a = shift;
    my $n = pop;

    unless ($LEAK_TESTING) {
        foreach (@_) {
            if ($a == $_) {
                is( $a, $_, $n );
                return;
            }
        }
        is( $a, $_[0], $n );
    }
}

sub myisnt {
    my ($a, $b, $n) = @_;

    unless ($LEAK_TESTING) {
        isnt( $a, $b, $n );
    }
}

sub initCheck {
    my ($obj) = @_;
    my %initArgs = (
        UnlockMutex => sub { },
        flags => CKF_OS_LOCKING_OK
    );

    myis( $obj->C_Finalize, CKR_CRYPTOKI_NOT_INITIALIZED, 'initCheck: C_Finalize uninitialized' );

    myis( $obj->C_Initialize(\%initArgs), CKR_ARGUMENTS_BAD, 'initCheck: C_Initialize bad args' );
    delete $initArgs{UnlockMutex};
    myis( $obj->C_Initialize(\%initArgs), CKR_OK, 'initCheck: C_Initialize' );
    myis( $obj->C_Initialize(\%initArgs), CKR_CRYPTOKI_ALREADY_INITIALIZED, 'initCheck: C_Initialize already initialized' );
    myis( $obj->C_Finalize, CKR_OK, 'initCheck: C_Finalize' );
    myis( $obj->C_Initialize, CKR_OK, 'initCheck: C_Initialize #2' );
    myis( $obj->C_Finalize, CKR_OK, 'initCheck: C_Finalize #2' );
}

sub infoCheck {
    my ($obj) = @_;
    my ($list, $info);
    my @mechanism = (
        [ CKM_RSA_PKCS_KEY_PAIR_GEN, 'CKM_RSA_PKCS_KEY_PAIR_GEN' ],
        [ CKM_RSA_PKCS, 'CKM_RSA_PKCS' ],
        [ CKM_MD5, 'CKM_MD5' ],
        [ CKM_RIPEMD160, 'CKM_RIPEMD160' ],
        [ CKM_SHA_1, 'CKM_SHA_1' ],
        [ CKM_SHA256, 'CKM_SHA256' ],
        [ CKM_SHA384, 'CKM_SHA384' ],
        [ CKM_SHA512, 'CKM_SHA512' ],
        [ CKM_MD5_RSA_PKCS, 'CKM_MD5_RSA_PKCS' ],
        [ CKM_RIPEMD160_RSA_PKCS, 'CKM_RIPEMD160_RSA_PKCS' ],
        [ CKM_SHA1_RSA_PKCS, 'CKM_SHA1_RSA_PKCS' ],
        [ CKM_SHA256_RSA_PKCS, 'CKM_SHA256_RSA_PKCS' ],
        [ CKM_SHA384_RSA_PKCS, 'CKM_SHA384_RSA_PKCS' ],
        [ CKM_SHA512_RSA_PKCS, 'CKM_SHA512_RSA_PKCS' ]
    );

    myis( $obj->C_GetInfo($info = {}), CKR_CRYPTOKI_NOT_INITIALIZED, 'infoCheck: C_GetInfo uninitialized' );
    myis( $obj->C_GetSlotList(CK_FALSE, $list = []), CKR_CRYPTOKI_NOT_INITIALIZED, 'infoCheck: C_GetSlotList uninitialized' );
    myis( $obj->C_GetSlotInfo($slotInvalid, $info = {}), CKR_CRYPTOKI_NOT_INITIALIZED, 'infoCheck: C_GetSlotInfo uninitialized' );
    myis( $obj->C_GetTokenInfo($slotInvalid, $info = {}), CKR_CRYPTOKI_NOT_INITIALIZED, 'infoCheck: C_GetTokenInfo uninitialized' );
    myis( $obj->C_GetMechanismList($slotInvalid, $list = []), CKR_CRYPTOKI_NOT_INITIALIZED, 'infoCheck: C_GetMechanismList uninitialized' );
    myis( $obj->C_GetMechanismInfo($slotInvalid, CKM_VENDOR_DEFINED, $info = {}), CKR_CRYPTOKI_NOT_INITIALIZED, 'infoCheck: C_GetMechanismInfo uninitialized' );

    myis( $obj->C_Initialize, CKR_OK, 'infoCheck: C_Initialize' );
    myis( $obj->C_GetInfo($info = {}), CKR_OK, 'infoCheck: C_GetInfo' );
    myis( $obj->C_GetSlotList(CK_FALSE, $list = []), CKR_OK, 'infoCheck: C_GetSlotList' );
    myis( $obj->C_GetSlotList(CK_TRUE, $list = []), CKR_OK, 'infoCheck: C_GetSlotList' );
    myis( $obj->C_GetSlotInfo($slotInvalid, $info = {}), CKR_SLOT_ID_INVALID, 'infoCheck: C_GetSlotInfo slotInvalid' );
    myis( $obj->C_GetSlotInfo($slotWithToken, $info = {}), CKR_OK, 'infoCheck: C_GetSlotInfo' );
    myis( $obj->C_GetTokenInfo($slotInvalid, $info = {}), CKR_SLOT_ID_INVALID, 'infoCheck: C_GetTokenInfo slotInvalid' );
    myis( $obj->C_GetTokenInfo($slotWithNoToken, $info = {}), CKR_TOKEN_NOT_PRESENT, 'infoCheck: C_GetTokenInfo slotWithNoToken' );
    myis( $obj->C_GetTokenInfo($slotWithToken, $info = {}), CKR_OK, 'infoCheck: C_GetTokenInfo' );
    myis( $obj->C_GetMechanismList($slotInvalid, $list = []), CKR_SLOT_ID_INVALID, 'infoCheck: C_GetMechanismList slotInvalid' );
    myis( $obj->C_GetMechanismList($slotWithToken, $list = []), CKR_OK, 'infoCheck: C_GetMechanismList' );
    myis( $obj->C_GetMechanismInfo($slotInvalid, CKM_VENDOR_DEFINED, $info = {}), CKR_SLOT_ID_INVALID, 'infoCheck: C_GetMechanismInfo slotInvalid' );
    myis( $obj->C_GetMechanismInfo($slotWithToken, CKM_VENDOR_DEFINED, $info = {}), CKR_MECHANISM_INVALID, 'infoCheck: C_GetMechanismInfo invalid mechanism' );
    foreach (@mechanism) {
        myis2( $obj->C_GetMechanismInfo($slotWithToken, $_->[0], $info = {}), CKR_OK, 'infoCheck: '.CKR_MECHANISM_INVALID, 'C_GetMechanismInfo '.$_->[1] );
    }
    myis( $obj->C_Finalize, CKR_OK, 'infoCheck: C_Finalize' );
}

sub sessionCheck {
    my ($obj) = @_;
    my @sessions = (CK_INVALID_HANDLE, CK_INVALID_HANDLE, CK_INVALID_HANDLE, CK_INVALID_HANDLE, CK_INVALID_HANDLE);
    my $info;

    myis( $obj->C_OpenSession($slotInvalid, 0, undef, $sessions[0]), CKR_CRYPTOKI_NOT_INITIALIZED, 'sessionCheck: C_OpenSession uninitialized' );
    myis2( $obj->C_CloseSession($sessions[0]), CKR_CRYPTOKI_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, 'sessionCheck: C_CloseSession uninitialized' );
    myis( $obj->C_CloseAllSessions($slotInvalid), CKR_CRYPTOKI_NOT_INITIALIZED, 'sessionCheck: C_CloseAllSessions uninitialized' );
    myis( $obj->C_GetSessionInfo($slotInvalid, $info = {}), CKR_CRYPTOKI_NOT_INITIALIZED, 'sessionCheck: C_GetSessionInfo uninitialized' );

    myis( $obj->C_Initialize, CKR_OK, 'sessionCheck: C_Initialize' );
    myis( $obj->C_OpenSession($slotInvalid, 0, undef, $sessions[0]), CKR_SLOT_ID_INVALID, 'sessionCheck: C_OpenSession slotInvalid' );
    myis( $obj->C_OpenSession($slotWithNoToken, 0, undef, $sessions[0]), CKR_TOKEN_NOT_PRESENT, 'sessionCheck: C_OpenSession slotWithNoToken' );
    myis( $obj->C_OpenSession($slotWithNotInitToken, 0, undef, $sessions[0]), CKR_TOKEN_NOT_RECOGNIZED, 'sessionCheck: C_OpenSession slotWithNotInitToken' );
    myis( $obj->C_OpenSession($slotWithToken, 0, undef, $sessions[0]), CKR_SESSION_PARALLEL_NOT_SUPPORTED, 'sessionCheck: C_OpenSession not serial' );
    myis( $obj->C_OpenSession($slotWithToken, CKF_SERIAL_SESSION, undef, $sessions[0]), CKR_OK, 'sessionCheck: C_OpenSession #0' );
    myis( $obj->C_CloseSession(CK_INVALID_HANDLE), CKR_SESSION_HANDLE_INVALID, 'sessionCheck: C_CloseSession invalid handle' );
    myis( $obj->C_CloseSession($sessions[0]), CKR_OK, 'sessionCheck: C_CloseSession #0' );
    myis( $obj->C_OpenSession($slotWithToken, CKF_SERIAL_SESSION, undef, $sessions[1]), CKR_OK, 'sessionCheck: C_OpenSession #1' );
    myis( $obj->C_OpenSession($slotWithToken, CKF_SERIAL_SESSION, undef, $sessions[2]), CKR_OK, 'sessionCheck: C_OpenSession #2' );
    myis( $obj->C_OpenSession($slotWithToken, CKF_SERIAL_SESSION, undef, $sessions[3]), CKR_OK, 'sessionCheck: C_OpenSession #3' );
    myis( $obj->C_OpenSession($slotWithToken, CKF_SERIAL_SESSION, undef, $sessions[4]), CKR_OK, 'sessionCheck: C_OpenSession #4' );
    myis( $obj->C_CloseSession($sessions[3]), CKR_OK, 'sessionCheck: C_CloseSession #3' );
    myis( $obj->C_CloseAllSessions($slotInvalid), CKR_SLOT_ID_INVALID, 'sessionCheck: C_CloseAllSessions slotInvalid' );
    myis( $obj->C_CloseAllSessions($slotWithNoToken), CKR_OK, 'sessionCheck: C_CloseAllSessions slotWithNoToken' );
    myis( $obj->C_CloseSession($sessions[2]), CKR_OK, 'sessionCheck: C_CloseSession #2' );
    myis( $obj->C_CloseAllSessions($slotWithToken), CKR_OK, 'sessionCheck: C_CloseAllSessions slotWithToken' );
    myis( $obj->C_GetSessionInfo(CK_INVALID_HANDLE, $info = {}), CKR_SESSION_HANDLE_INVALID, 'sessionCheck: C_GetSessionInfo invalid handle' );
    myis( $obj->C_OpenSession($slotWithToken, CKF_SERIAL_SESSION, undef, $sessions[0]), CKR_OK, 'sessionCheck: C_OpenSession #0 #2' );
    myis( $obj->C_OpenSession($slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, undef, $sessions[1]), CKR_OK, 'sessionCheck: C_OpenSession #1 #2' );
    myis( $obj->C_GetSessionInfo($sessions[0], $info = {}), CKR_OK, 'sessionCheck: C_GetSessionInfo #0' );
    myis( $obj->C_GetSessionInfo($sessions[1], $info = {}), CKR_OK, 'sessionCheck: C_GetSessionInfo #1' );
    myis( $obj->C_Finalize, CKR_OK, 'sessionCheck: C_Finalize' );
}

sub userCheck {
    my ($obj) = @_;
    my @sessions = (CK_INVALID_HANDLE, CK_INVALID_HANDLE);

    myis2( $obj->C_Login(CK_INVALID_HANDLE, 9999, ""), CKR_CRYPTOKI_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, 'userCheck: C_Login uninitialized' );
    myis2( $obj->C_Logout(CK_INVALID_HANDLE), CKR_CRYPTOKI_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, 'userCheck: C_Logout uninitialized' );

    myis( $obj->C_Initialize, CKR_OK, 'userCheck: C_Initialize' );
    myis( $obj->C_OpenSession($slotWithToken, CKF_SERIAL_SESSION, undef, $sessions[0]), CKR_OK, 'userCheck: C_OpenSession #0' );
    myis( $obj->C_OpenSession($slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, undef, $sessions[1]), CKR_OK, 'userCheck: C_OpenSession #1' );
    myis( $obj->C_Login(CK_INVALID_HANDLE, 9999, ""), CKR_SESSION_HANDLE_INVALID, 'userCheck: C_Login invalid handle' );
    myis2( $obj->C_Login($sessions[0], 9999, ""), CKR_ARGUMENTS_BAD, CKR_PIN_INCORRECT, 'userCheck: C_Login bad pin' );
    myis( $obj->C_Login($sessions[0], 9999, "1234"), CKR_USER_TYPE_INVALID, 'userCheck: C_Login invalid user type' );
    myis( $obj->C_Login($sessions[0], CKU_CONTEXT_SPECIFIC, "1234"), CKR_OPERATION_NOT_INITIALIZED, 'userCheck: C_Login context specific' );
    myis( $obj->C_Login($sessions[0], CKU_USER, "123"), CKR_PIN_INCORRECT, 'userCheck: C_Login bad pin #2' );
    myis( $obj->C_Login($sessions[0], CKU_USER, "1234"), CKR_OK, 'userCheck: C_Login' );
    myis( $obj->C_Login($sessions[0], CKU_CONTEXT_SPECIFIC, "1234"), CKR_OK, 'userCheck: C_Login context specific #2' );
    myis( $obj->C_Login($sessions[1], CKU_SO, "12345678"), CKR_USER_ANOTHER_ALREADY_LOGGED_IN, 'userCheck: C_Login already logged in' );
    myis( $obj->C_Logout($sessions[0]), CKR_OK, 'userCheck: C_Logout' );
    myis( $obj->C_Login($sessions[1], CKU_SO, "12345678"), CKR_SESSION_READ_ONLY_EXISTS, 'userCheck: C_Login read only exists' );
    myis( $obj->C_CloseSession($sessions[0]), CKR_OK, 'userCheck: C_CloseSession' );
    myis( $obj->C_Login($sessions[1], CKU_SO, "1234567"), CKR_PIN_INCORRECT, 'userCheck: C_Login SO bad pin' );
    myis( $obj->C_Login($sessions[1], CKU_SO, "12345678"), CKR_OK, 'userCheck: C_Login SO' );
    myis( $obj->C_Login($sessions[1], CKU_CONTEXT_SPECIFIC, "12345678"), CKR_OK, 'userCheck: C_Login SO context specific' );
    myis( $obj->C_Login($sessions[1], CKU_USER, "1234"), CKR_USER_ANOTHER_ALREADY_LOGGED_IN, 'userCheck: C_Login already logged in #2' );
    myis( $obj->C_Logout(CK_INVALID_HANDLE), CKR_SESSION_HANDLE_INVALID, 'userCheck: C_Logout invalid handle' );
    myis( $obj->C_Logout($sessions[1]), CKR_OK, 'userCheck: C_Logout #2' );
    myis( $obj->C_Finalize, CKR_OK, 'userCheck: C_Finalize' );
}

sub randomCheck {
    my ($obj) = @_;
    my $session;
    my $seed = 'abcd';
    my $random;

    myis2( $obj->C_SeedRandom(CK_INVALID_HANDLE, $seed), CKR_CRYPTOKI_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, 'randomCheck: C_SeedRandom uninitialized' );
    myis2( $obj->C_GenerateRandom(CK_INVALID_HANDLE, $random, 1), CKR_CRYPTOKI_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, 'randomCheck: C_GenerateRandom uninitialized' );

    myis( $obj->C_Initialize, CKR_OK, 'randomCheck: C_Initialize' );
    myis( $obj->C_OpenSession($slotWithToken, CKF_SERIAL_SESSION, undef, $session), CKR_OK, 'randomCheck: C_OpenSession' );
    myis( $obj->C_SeedRandom(CK_INVALID_HANDLE, $seed), CKR_SESSION_HANDLE_INVALID, 'randomCheck: C_SeedRandom invalid handle' );
    myis( $obj->C_SeedRandom($session, $seed), CKR_OK, 'randomCheck: C_SeedRandom' );
    myis( $obj->C_GenerateRandom(CK_INVALID_HANDLE, $random, 1), CKR_SESSION_HANDLE_INVALID, 'randomCheck: C_GenerateRandom invalid handle' );
    myis( $obj->C_GenerateRandom($session, $random, 40), CKR_OK, 'randomCheck: C_GenerateRandom' );
    myis( $obj->C_Finalize, CKR_OK, 'randomCheck: C_Finalize' );
}

sub generateCheck {
    my ($obj) = @_;
    my @sessions = (CK_INVALID_HANDLE, CK_INVALID_HANDLE);
    my $modulusBits = pack(CK_ULONG_SIZE < 8 ? 'L' : 'Q', 768);
    my $publicExponent = pack('C*', 0x01, 0x00, 0x01);
    my $modulus = pack('C*',
        0xcb, 0x12, 0x9d, 0xba, 0x22, 0xfa, 0x2b, 0x33, 0x7e, 0x2a, 0x24, 0x65, 0x09, 0xa9,
        0xfb, 0x41, 0x1a, 0x0e, 0x2f, 0x89, 0x3a, 0xd6, 0x97, 0x49, 0x77, 0x6d, 0x2a, 0x6e, 0x98,
        0x48, 0x6b, 0xa8, 0xc4, 0x63, 0x8e, 0x46, 0x90, 0x70, 0x2e, 0xd4, 0x10, 0xc0, 0xdd, 0xa3,
        0x56, 0xcf, 0x97, 0x2f, 0x2f, 0xfc, 0x2d, 0xff, 0x2b, 0xf2, 0x42, 0x69, 0x4a, 0x8c, 0xf1,
        0x6f, 0x76, 0x32, 0xc8, 0xe1, 0x37, 0x52, 0xc1, 0xd1, 0x33, 0x82, 0x39, 0x1a, 0xb3, 0x2a,
        0xa8, 0x80, 0x4e, 0x19, 0x91, 0xa6, 0xa6, 0x16, 0x65, 0x30, 0x72, 0x80, 0xc3, 0x5c, 0x84,
        0x9b, 0x7b, 0x2c, 0x6d, 0x2d, 0x75, 0x51, 0x9f, 0xc9, 0x6d, 0xa8, 0x4d, 0x8c, 0x41, 0x41,
        0x12, 0xc9, 0x14, 0xc7, 0x99, 0x31, 0xe4, 0xcd, 0x97, 0x38, 0x2c, 0xca, 0x32, 0x2f, 0xeb,
        0x78, 0x37, 0x17, 0x87, 0xc8, 0x09, 0x5a, 0x1a, 0xaf, 0xe4, 0xc4, 0xcc, 0x83, 0xe3, 0x79,
        0x01, 0xd6, 0xdb, 0x8b, 0xd6, 0x24, 0x90, 0x43, 0x7b, 0xc6, 0x40, 0x57, 0x58, 0xe4, 0x49,
        0x2b, 0x99, 0x61, 0x71, 0x52, 0xf4, 0x8b, 0xda, 0xb7, 0x5a, 0xbf, 0xf7, 0xc5, 0x2a, 0x8b,
        0x1f, 0x25, 0x5e, 0x5b, 0xfb, 0x9f, 0xcc, 0x8d, 0x1c, 0x92, 0x21, 0xe9, 0xba, 0xd0, 0x54,
        0xf6, 0x0d, 0xe8, 0x7e, 0xb3, 0x9d, 0x9a, 0x47, 0xba, 0x1e, 0x45, 0x4e, 0xdc, 0xe5, 0x20,
        0x95, 0xd8, 0xe5, 0xe9, 0x51, 0xff, 0x1f, 0x9e, 0x9e, 0x60, 0x3c, 0x27, 0x1c, 0xf3, 0xc7,
        0xf4, 0x89, 0xaa, 0x2a, 0x80, 0xd4, 0x03, 0x5d, 0xf3, 0x39, 0xa3, 0xa7, 0xe7, 0x3f, 0xa9,
        0xd1, 0x31, 0x50, 0xb7, 0x0f, 0x08, 0xa2, 0x71, 0xcc, 0x6a, 0xb4, 0xb5, 0x8f, 0xcb, 0xf7,
        0x1f, 0x4e, 0xc8, 0x16, 0x08, 0xc0, 0x03, 0x8a, 0xce, 0x17, 0xd1, 0xdd, 0x13, 0x0f, 0xa3,
        0xbe, 0xa3 );
    my $id = pack('C', 123);
    my $label = pack('a5', 'label');
    my $pubClass = pack(CK_ULONG_SIZE < 8 ? 'L' : 'Q', CKO_PUBLIC_KEY);
    my $keyType = pack(CK_ULONG_SIZE < 8 ? 'L' : 'Q', CKK_RSA);
    my $true = pack('C', CK_TRUE);
    my $false = pack('C', CK_FALSE);
    my $certCategory = pack(CK_ULONG_SIZE < 8 ? 'L' : 'Q', 0);
    my $publicKey;
    my $privateKey;
    my $object;
    my $mechanism = {
        mechanism => CKM_VENDOR_DEFINED
    };
    my @publicKeyTemplate = (
        { type => CKA_ENCRYPT, pValue => $true },
        { type => CKA_VERIFY, pValue => $true },
        { type => CKA_WRAP, pValue => $true },
        { type => CKA_PUBLIC_EXPONENT, pValue => $publicExponent },
        { type => CKA_TOKEN, pValue => $true }
    );
    my @privateKeyTemplate = (
        { type => CKA_PRIVATE, pValue => $true },
        { type => CKA_ID, pValue => $id },
        { type => CKA_SENSITIVE, pValue => $true },
        { type => CKA_DECRYPT, pValue => $true },
        { type => CKA_SIGN, pValue => $true },
        { type => CKA_UNWRAP, pValue => $true },
        { type => CKA_TOKEN, pValue => $true }
    );
    my @pubTemplate = (
        { type => CKA_CLASS, pValue => $pubClass },
        { type => CKA_KEY_TYPE, pValue => $keyType },
        { type => CKA_LABEL, pValue => $label },
        { type => CKA_ID, pValue => $id },
        { type => CKA_TOKEN, pValue => $true },
        { type => CKA_VERIFY, pValue => $true },
        { type => CKA_ENCRYPT, pValue => $false },
        { type => CKA_WRAP, pValue => $false },
        { type => CKA_PUBLIC_EXPONENT, pValue => $publicExponent }
    );

    myis2( $obj->C_GenerateKeyPair(CK_INVALID_HANDLE, {}, [], [], $publicKey, $privateKey), CKR_CRYPTOKI_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, 'generateCheck: C_GenerateKeyPair uninitialized' );
    myis2( $obj->C_DestroyObject(CK_INVALID_HANDLE, CK_INVALID_HANDLE), CKR_CRYPTOKI_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, 'generateCheck: C_DestroyObject uninitialized' );
    myis2( $obj->C_CreateObject(CK_INVALID_HANDLE, [], $object), CKR_CRYPTOKI_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, 'generateCheck: C_CreateObject uninitialized' );

    myis( $obj->C_Initialize, CKR_OK, 'generateCheck: C_Initialize' );
    myis( $obj->C_OpenSession($slotWithToken, CKF_SERIAL_SESSION, undef, $sessions[0]), CKR_OK, 'generateCheck: C_OpenSession #0' );
    myis( $obj->C_OpenSession($slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, undef, $sessions[1]), CKR_OK, 'generateCheck: C_OpenSession #1' );
    myis( $obj->C_GenerateKeyPair(CK_INVALID_HANDLE, {}, [], [], $publicKey, $privateKey), CKR_SESSION_HANDLE_INVALID, 'generateCheck: C_GenerateKeyPair invalid handle' );
    myis( $obj->C_GenerateKeyPair($sessions[0], $mechanism, \@publicKeyTemplate, \@privateKeyTemplate, $publicKey, $privateKey), CKR_USER_NOT_LOGGED_IN, 'generateCheck: C_GenerateKeyPair not logged in' );
    myis( $obj->C_Login($sessions[0], CKU_USER, "1234"), CKR_OK, 'generateCheck: C_Login' );
    myis( $obj->C_GenerateKeyPair($sessions[0], $mechanism, \@publicKeyTemplate, \@privateKeyTemplate, $publicKey, $privateKey), CKR_USER_NOT_LOGGED_IN, 'generateCheck: C_GenerateKeyPair not logged in #2' );
    myis( $obj->C_GenerateKeyPair($sessions[1], $mechanism, \@publicKeyTemplate, \@privateKeyTemplate, $publicKey, $privateKey), CKR_MECHANISM_INVALID, 'generateCheck: C_GenerateKeyPair invalid mechanism' );
    $mechanism->{mechanism} = CKM_RSA_PKCS_KEY_PAIR_GEN;
    myis( $obj->C_GenerateKeyPair($sessions[1], $mechanism, \@publicKeyTemplate, \@privateKeyTemplate, $publicKey, $privateKey), CKR_TEMPLATE_INCOMPLETE, 'generateCheck: C_GenerateKeyPair template incomplete' );
    push(@publicKeyTemplate, { type => CKA_MODULUS_BITS, pValue => $modulusBits });
    myis( $obj->C_GenerateKeyPair($sessions[1], $mechanism, \@publicKeyTemplate, \@privateKeyTemplate, $publicKey, $privateKey), CKR_OK, 'generateCheck: C_GenerateKeyPair' );
    myis( $obj->C_DestroyObject(CK_INVALID_HANDLE, CK_INVALID_HANDLE), CKR_SESSION_HANDLE_INVALID, 'generateCheck: C_DestroyObject invalid handle' );
    myis( $obj->C_DestroyObject($sessions[0], CK_INVALID_HANDLE), CKR_OBJECT_HANDLE_INVALID, 'generateCheck: C_DestroyObject invalid handle #2' );
    myis( $obj->C_DestroyObject($sessions[0], $privateKey), CKR_OBJECT_HANDLE_INVALID, 'generateCheck: C_DestroyObject invalid handle #3' );
    myis( $obj->C_DestroyObject($sessions[1], $privateKey), CKR_OK, 'generateCheck: C_DestroyObject' );
    myis( $obj->C_DestroyObject($sessions[1], $publicKey), CKR_OK, 'generateCheck: C_DestroyObject #2' );
    myis( $obj->C_Logout($sessions[0]), CKR_OK, 'generateCheck: C_Logout' );
    myis( $obj->C_CreateObject(CK_INVALID_HANDLE, [], $object), CKR_SESSION_HANDLE_INVALID, 'generateCheck: C_CreateObject invalid handle' );
    myis( $obj->C_CreateObject($sessions[0], \@pubTemplate, $object), CKR_SESSION_READ_ONLY, 'generateCheck: C_CreateObject read only' );
    myis( $obj->C_CreateObject($sessions[1], \@pubTemplate, $object), CKR_USER_NOT_LOGGED_IN, 'generateCheck: C_CreateObject not logged in' );
    myis( $obj->C_Login($sessions[0], CKU_USER, "1234"), CKR_OK, 'generateCheck: C_Login #2' );
    myis( $obj->C_CreateObject($sessions[1], \@pubTemplate, $object), CKR_TEMPLATE_INCOMPLETE, 'generateCheck: C_CreateObject template incomplete' );
    push(@pubTemplate, { type => CKA_MODULUS, pValue => $modulus },
        { type => CKA_CERTIFICATE_CATEGORY, pValue => $certCategory });
    myis( $obj->C_CreateObject($sessions[1], \@pubTemplate, $object), CKR_ATTRIBUTE_TYPE_INVALID, 'generateCheck: C_CreateObject attribute invalid' );
    pop(@pubTemplate);
    myis( $obj->C_CreateObject($sessions[1], \@pubTemplate, $object), CKR_OK, 'generateCheck: C_CreateObject' );
    myis( $obj->C_DestroyObject($sessions[1], $object), CKR_OK, 'generateCheck: C_DestroyObject #3' );
    myis( $obj->C_Finalize, CKR_OK, 'generateCheck: C_Finalize' );
}

sub objectCheck {
    my ($obj) = @_;
    my @sessions = (CK_INVALID_HANDLE, CK_INVALID_HANDLE);
    my $modulusBits = pack(CK_ULONG_SIZE < 8 ? 'L' : 'Q', 768);
    my $publicExponent = pack('C*', 0x01, 0x00, 0x01);
    my $id = pack('C', 123);
    my $true = pack('C', CK_TRUE);
    my $publicKey;
    my $privateKey;
    my $object;
    my $mechanism = {
        mechanism => CKM_RSA_PKCS_KEY_PAIR_GEN
    };
    my @publicKeyTemplate = (
        { type => CKA_ENCRYPT, pValue => $true },
        { type => CKA_VERIFY, pValue => $true },
        { type => CKA_WRAP, pValue => $true },
        { type => CKA_PUBLIC_EXPONENT, pValue => $publicExponent },
        { type => CKA_TOKEN, pValue => $true },
        { type => CKA_MODULUS_BITS, pValue => $modulusBits }
    );
    my @privateKeyTemplate = (
        { type => CKA_PRIVATE, pValue => $true },
        { type => CKA_ID, pValue => $id },
        { type => CKA_SENSITIVE, pValue => $true },
        { type => CKA_DECRYPT, pValue => $true },
        { type => CKA_SIGN, pValue => $true },
        { type => CKA_UNWRAP, pValue => $true },
        { type => CKA_TOKEN, pValue => $true }
    );
    my $list;
    my $oClass = pack(CK_ULONG_SIZE < 8 ? 'L' : 'Q', CKO_PUBLIC_KEY);
    my @searchTemplate = (
        { type => CKA_CLASS, pValue => $oClass }
    );

    myis2( $obj->C_FindObjectsInit(CK_INVALID_HANDLE, $list = []), CKR_CRYPTOKI_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, 'objectCheck: C_FindObjectsInit uninitialized' );
    myis2( $obj->C_FindObjects(CK_INVALID_HANDLE, $list = [], 1), CKR_CRYPTOKI_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, 'objectCheck: C_FindObjects uninitialized' );
    myis2( $obj->C_FindObjectsFinal(CK_INVALID_HANDLE), CKR_CRYPTOKI_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, 'objectCheck: C_FindObjectsFinal uninitialized' );
    myis2( $obj->C_GetAttributeValue(CK_INVALID_HANDLE, CK_INVALID_HANDLE, $list = []), CKR_CRYPTOKI_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, 'objectCheck: C_GetAttributeValue uninitialized' );
    myis2( $obj->C_SetAttributeValue(CK_INVALID_HANDLE, CK_INVALID_HANDLE, $list = []), CKR_CRYPTOKI_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, 'objectCheck: C_SetAttributeValue uninitialized' );

    myis( $obj->C_Initialize, CKR_OK, 'generateCheck: C_Initialize' );
    myis( $obj->C_OpenSession($slotWithToken, CKF_SERIAL_SESSION, undef, $sessions[0]), CKR_OK, 'objectCheck: C_OpenSession #0' );
    myis( $obj->C_OpenSession($slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, undef, $sessions[1]), CKR_OK, 'objectCheck: C_OpenSession #1' );
    myis( $obj->C_Login($sessions[1], CKU_USER, "1234"), CKR_OK, 'objectCheck: C_Login' );
    myis( $obj->C_GenerateKeyPair($sessions[1], $mechanism, \@publicKeyTemplate, \@privateKeyTemplate, $publicKey, $privateKey), CKR_OK, 'objectCheck: C_GenerateKeyPair' );
    myis( $obj->C_Logout($sessions[1]), CKR_OK, 'objectCheck: C_Logout' );
    myis( $obj->C_FindObjectsInit(CK_INVALID_HANDLE, \@searchTemplate), CKR_SESSION_HANDLE_INVALID, 'objectCheck: C_FindObjectsInit invalid handle' );
    myis( $obj->C_FindObjectsInit($sessions[0], \@searchTemplate), CKR_OK, 'objectCheck: C_FindObjectsInit' );
    myis( $obj->C_FindObjectsInit($sessions[0], \@searchTemplate), CKR_OPERATION_ACTIVE, 'objectCheck: C_FindObjectsInit active' );
    myis( $obj->C_FindObjects(CK_INVALID_HANDLE, $list = [], 1), CKR_SESSION_HANDLE_INVALID, 'objectCheck: C_FindObjects invalid handle' );
    myis( $obj->C_FindObjects($sessions[1], $list = [], 1), CKR_OPERATION_NOT_INITIALIZED, 'objectCheck: C_FindObjects op not init' );
    myis( $obj->C_FindObjects($sessions[0], $list = [], 1), CKR_OK, 'objectCheck: C_FindObjects' );
    myis( $obj->C_FindObjectsFinal(CK_INVALID_HANDLE), CKR_SESSION_HANDLE_INVALID, 'objectCheck: C_FindObjectsFinal invalid handle' );
    myis( $obj->C_FindObjectsFinal($sessions[1]), CKR_OPERATION_NOT_INITIALIZED, 'objectCheck: C_FindObjectsFinal op not init' );
    myis( $obj->C_FindObjectsFinal($sessions[0]), CKR_OK, 'objectCheck: C_FindObjectsFinal' );
    # TODO: C_GetAttributeValue
    myis( $obj->C_Login($sessions[1], CKU_USER, "1234"), CKR_OK, 'objectCheck: C_Login' );
    # TODO: C_SetAttributeValue
    myis( $obj->C_DestroyObject($sessions[1], $privateKey), CKR_OK, 'objectCheck: C_DestroyObject' );
    myis( $obj->C_DestroyObject($sessions[1], $publicKey), CKR_OK, 'objectCheck: C_DestroyObject #2' );
    myis( $obj->C_Finalize, CKR_OK, 'objectCheck: C_Finalize' );
}

sub mytests {
    my $obj = Crypt::PKCS11->new;
    myisa_ok( $obj, 'Crypt::PKCS11' );

    # TODO: Check various PKCS#11 modules

    my ($so) = grep -r "$_/softhsm/libsofthsm.so",
        '/usr/local/lib64', '/usr/lib64',
        '/usr/local/lib', '/usr/lib',
        split / /, $Config{loclibpth},
        split / /, $Config{libpth};
    $so .= '/softhsm/libsofthsm.so';
    
    if ($so) {
#        my $h = {};
#        my $a = [];
#        my $a2 = [];
#        my $s;

        $ENV{SOFTHSM_CONF} = 'softhsm.conf';
        chdir('t');
#        system('softhsm --slot 0 --init-token --label ѪѫѬ --so-pin 12345678 --pin 1234');
        system('softhsm --slot 1 --init-token --label slot1 --so-pin 12345678 --pin 1234');

        myis( $obj->load($so), Crypt::PKCS11::CKR_OK );

        $slotWithToken = 1;
        $slotWithNoToken = 0;
        $slotWithNotInitToken = 2;
        $slotInvalid = 9999;

        my $i = 5;
        while ($i--) {
            initCheck($obj);
            infoCheck($obj);
            sessionCheck($obj);
            userCheck($obj);
            randomCheck($obj);
            generateCheck($obj);
            objectCheck($obj);
            last;
        }

        # TODO: setCreate/Destroy/Lock/Unlock-Mutex
#        myis( $obj->C_Initialize, Crypt::PKCS11::CKR_OK );
        # TODO: C_Initialize with pInitArgs
#        myis( $obj->C_GetInfo($h = {}), Crypt::PKCS11::CKR_OK );
#        myis( $obj->C_GetSlotList(1, $a = []), Crypt::PKCS11::CKR_OK );
#        myis( $obj->C_GetSlotList(0, $a = []), Crypt::PKCS11::CKR_OK );
#        foreach (@$a) {
#            myis( $obj->C_GetSlotInfo($_, $h = {}), Crypt::PKCS11::CKR_OK );
#            myis( $obj->C_GetTokenInfo($_, $h = {}), Crypt::PKCS11::CKR_OK );
#            myis( $obj->C_GetMechanismList($_, $a2 = []), Crypt::PKCS11::CKR_OK );
#            foreach my $m (@$a2) {
#                myis( $obj->C_GetMechanismInfo($_, $m, $h = {}), Crypt::PKCS11::CKR_OK );
#            }
#            myis( $obj->C_InitToken($_, "12345678", "ѪѫѬѪѫѬ"), Crypt::PKCS11::CKR_OK );
#            myis( $obj->C_GetTokenInfo($_, $h = {}), Crypt::PKCS11::CKR_OK );
#            $h->{label} =~ s/\s+$//o;
#            myis( $h->{label}, "ѪѫѬѪѫѬ" );
            # TODO: C_InitPIN
            # TODO: C_SetPIN
            # TODO: C_OpenSession with callback
#            myis( $obj->C_OpenSession($_, Crypt::PKCS11::CKF_SERIAL_SESSION|Crypt::PKCS11::CKF_RW_SESSION, undef, $s), Crypt::PKCS11::CKR_OK );
#            myisnt( $s, Crypt::PKCS11::CK_INVALID_HANDLE );
#            myisnt( $s, undef );
#            myis( $obj->C_CloseSession($s), Crypt::PKCS11::CKR_OK );
#            myis( $obj->C_OpenSession($_, Crypt::PKCS11::CKF_SERIAL_SESSION|Crypt::PKCS11::CKF_RW_SESSION, undef, $s), Crypt::PKCS11::CKR_OK );
#            myisnt( $s, Crypt::PKCS11::CK_INVALID_HANDLE );
#            myisnt( $s, undef );
#            myis( $obj->C_CloseAllSessions($_), Crypt::PKCS11::CKR_OK );
            # TODO: C_GetSessionInfo
            # TODO: C_GetOperationState
            # TODO: C_SetOperationState
            # TODO: C_Login
            # TODO: C_Logout
            # TODO: C_CreateObject
            # TODO: C_CopyObject
            # TODO: C_DestroyObject
            # TODO: C_GetObjectSize
            # TODO: C_GetAttributeValue
            # TODO: C_SetAttributeValue
            # TODO: C_FindObjectsInit
            # TODO: C_FindObjects
            # TODO: C_FindObjectsFinal
            # TODO: C_EncryptInit
            # TODO: C_Encrypt
            # TODO: C_EncryptUpdate
            # TODO: C_EncryptFinal
            # TODO: C_DecryptInit
            # TODO: C_Decrypt
            # TODO: C_DecryptUpdate
            # TODO: C_DecryptFinal
            # TODO: C_DigestInit
            # TODO: C_Digest
            # TODO: C_DigestUpdate
            # TODO: C_DigestFinal
            # TODO: C_SignInit
            # TODO: C_Sign
            # TODO: C_SignUpdate
            # TODO: C_SignFinal
            # TODO: C_SignRecoverInit
            # TODO: C_SignRecover
            # TODO: C_VerifyInit
            # TODO: C_Verify
            # TODO: C_VerifyUpdate
            # TODO: C_VerifyFinal
            # TODO: C_VerifyRecoverInit
            # TODO: C_VerifyRecover
            # TODO: C_DigestEncryptUpdate
            # TODO: C_DecryptDigestUpdate
            # TODO: C_SignEncryptUpdate
            # TODO: C_DecryptVerifyUpdate
            # TODO: C_GenerateKey
            # TODO: C_GenerateKeyPair
            # TODO: C_WrapKey
            # TODO: C_UnwrapKey
            # TODO: C_DeriveKey
            # TODO: C_SeedRandom
            # TODO: C_GenerateRandom
            # TODO: C_GetFunctionStatus
            # TODO: C_CancelFunction
            # TODO: C_WaitForSlotEvent
#        }
#        myis( $obj->C_Finalize, Crypt::PKCS11::CKR_OK );
        myis( $obj->unload, Crypt::PKCS11::CKR_OK );
        # TODO: clearCreate/Destroy/Lock/Unlock-Mutex
    }
}

BEGIN {
    mytests;

    if (HAVE_LEAKTRACE) {
        use Test::LeakTrace;
        $LEAK_TESTING = 1;
        leaks_cmp_ok { mytests; } '<', 1;
    }
    
    done_testing;
}
