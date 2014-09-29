#!perl

use Config;
use constant HAVE_LEAKTRACE => eval{ require Test::LeakTrace };
use Test::More;

use Crypt::PKCS11 qw(:constant);

our $LEAK_TESTING;

our $slotWithToken = 1;
our $slotWithNoToken = 0;
our $slotWithNotInitToken = 2;
our $slotInvalid = 9999;

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

    myis( $obj->C_Finalize, CKR_CRYPTOKI_NOT_INITIALIZED, 'C_Finalize uninitialized' );
    myis( $obj->C_Initialize(\%initArgs), CKR_ARGUMENTS_BAD, 'C_Initialize bad args' );
    delete $initArgs{UnlockMutex};
    myis( $obj->C_Initialize(\%initArgs), CKR_OK, 'C_Initialize' );
    myis( $obj->C_Initialize(\%initArgs), CKR_CRYPTOKI_ALREADY_INITIALIZED, 'C_Initialize already initialized' );
    myis( $obj->C_Finalize, CKR_OK, 'C_Finalize' );
    myis( $obj->C_Initialize, CKR_OK, 'C_Initialize #2' );
    myis( $obj->C_Finalize, CKR_OK, 'C_Finalize #2' );
}

sub infoCheck {
    my ($obj) = @_;
    my ($list, $info);
    my %mechanism = (
        CKM_RSA_PKCS_KEY_PAIR_GEN => 'CKM_RSA_PKCS_KEY_PAIR_GEN',
        CKM_RSA_PKCS => 'CKM_RSA_PKCS',
        CKM_MD5 => 'CKM_MD5',
        CKM_RIPEMD160 => 'CKM_RIPEMD160',
        CKM_SHA_1 => 'CKM_SHA_1',
        CKM_SHA256 => 'CKM_SHA256',
        CKM_SHA384 => 'CKM_SHA384',
        CKM_SHA512 => 'CKM_SHA512',
        CKM_MD5_RSA_PKCS => 'CKM_MD5_RSA_PKCS',
        CKM_RIPEMD160_RSA_PKCS => 'CKM_RIPEMD160_RSA_PKCS',
        CKM_SHA1_RSA_PKCS => 'CKM_SHA1_RSA_PKCS',
        CKM_SHA256_RSA_PKCS => 'CKM_SHA256_RSA_PKCS',
        CKM_SHA384_RSA_PKCS => 'CKM_SHA384_RSA_PKCS',
        CKM_SHA512_RSA_PKCS => 'CKM_SHA512_RSA_PKCS' );

    myis( $obj->C_GetInfo(($info = {})), CKR_CRYPTOKI_NOT_INITIALIZED, 'C_GetInfo uninitialized' );
    myis( $obj->C_GetSlotList(CK_FALSE, ($list = [])), CKR_CRYPTOKI_NOT_INITIALIZED, 'C_GetSlotList uninitialized' );
    myis( $obj->C_GetSlotInfo($slotInvalid, ($info = {})), CKR_CRYPTOKI_NOT_INITIALIZED, 'C_GetSlotInfo uninitialized' );
    myis( $obj->C_GetTokenInfo($slotInvalid, ($info = {})), CKR_CRYPTOKI_NOT_INITIALIZED, 'C_GetTokenInfo uninitialized' );
    myis( $obj->C_GetMechanismList($slotInvalid, CK_FALSE, ($list = [])), CKR_CRYPTOKI_NOT_INITIALIZED, 'C_GetMechanismList uninitialized' );
    myis( $obj->C_GetMechanismInfo($slotInvalid, CKM_VENDOR_DEFINED, ($info = {})), CKR_CRYPTOKI_NOT_INITIALIZED, 'C_GetMechanismInfo uninitialized' );

    myis( $obj->C_Initialize, CKR_OK, 'C_Initialize' );
    myis( $obj->C_GetInfo(($info = {})), CKR_OK, 'C_GetInfo' );
    myis( $obj->C_GetSlotList(($list = [])), CKR_OK, 'C_GetSlotList' );
    myis( $obj->C_GetSlotInfo($slotInvalid, ($info = {})), CKR_CRYPTOKI_NOT_INITIALIZED, 'C_GetSlotInfo slotInvalid' );
    myis( $obj->C_GetSlotInfo($slotWithToken, ($info = {})), CKR_OK, 'C_GetSlotInfo' );
    myis( $obj->C_GetTokenInfo($slotInvalid, ($info = {})), CKR_SLOT_ID_INVALID, 'C_GetTokenInfo slotInvalid' );
    myis( $obj->C_GetTokenInfo($slotWithNoToken, ($info = {})), CKR_TOKEN_NOT_PRESENT, 'C_GetTokenInfo slotWithNoToken' );
    myis( $obj->C_GetTokenInfo($slotWithToken, ($info = {})), CKR_OK, 'C_GetTokenInfo' );
    myis( $obj->C_GetMechanismList($slotInvalid, ($list = [])), CKR_SLOT_ID_INVALID, 'C_GetMechanismList slotInvalid' );
    myis( $obj->C_GetMechanismList($slotWithToken, ($list = [])), CKR_OK, 'C_GetMechanismList' );
    myis( $obj->C_GetMechanismInfo($slotInvalid, CKM_VENDOR_DEFINED, ($info = {})), CKR_SLOT_ID_INVALID, 'C_GetMechanismInfo slotInvalid' );
    myis( $obj->C_GetMechanismInfo($slotWithToken, CKM_VENDOR_DEFINED, ($info = {})), CKR_MECHANISM_INVALID, 'C_GetMechanismInfo invalid mechanism' );
    while ( my ($mechanism, $text) = each(%mechanism) ) {
        my $rv = $obj->C_GetMechanismInfo($slotWithToken, $mechanism, ($info = {}));
        next if ($rv == CKR_MECHANISM_INVALID);
        myis( $rv, CKR_OK, $text );
    }
    myis( $obj->C_Finalize, CKR_OK, 'C_Finalize' );
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
        system('softhsm --slot 0 --init-token --label ѪѫѬ --so-pin 12345678 --pin 1234');
        system('softhsm --slot 1 --init-token --label slot1 --so-pin 12345678 --pin 1234');

        myis( $obj->load($so), Crypt::PKCS11::CKR_OK );

        my $i = 5;
        while ($i--) {
            initCheck($obj);
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
