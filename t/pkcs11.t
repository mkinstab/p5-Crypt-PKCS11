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
