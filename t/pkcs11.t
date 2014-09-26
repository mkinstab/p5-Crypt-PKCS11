#!perl

use Config;
use constant HAVE_LEAKTRACE => eval{ require Test::LeakTrace };
use Test::More;

use Crypt::PKCS11;

our $LEAK_TESTING;

sub myisa_ok {
    my ($obj, $class) = @_;

    unless ($LEAK_TESTING) {
        isa_ok( $obj, $class );
    }
}

sub myis {
    my ($a, $b) = @_;

    unless ($LEAK_TESTING) {
        is( $a, $b );
    }
}

sub myisnt {
    my ($a, $b) = @_;

    unless ($LEAK_TESTING) {
        isnt( $a, $b );
    }
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
        my $h = {};
        my $a = [];
        my $a2 = [];
        my $s;

        $ENV{SOFTHSM_CONF} = 'softhsm.conf';
        chdir('t');
        system('softhsm --slot 0 --init-token --label ѪѫѬ --so-pin 12345678 --pin 1234');
        system('softhsm --slot 1 --init-token --label slot1 --so-pin 12345678 --pin 1234');

        myis( $obj->load($so), Crypt::PKCS11::CKR_OK );
        # TODO: setCreate/Destroy/Lock/Unlock-Mutex
        myis( $obj->C_Initialize, Crypt::PKCS11::CKR_OK );
        # TODO: C_Initialize with pInitArgs
        myis( $obj->C_GetInfo($h = {}), Crypt::PKCS11::CKR_OK );
        myis( $obj->C_GetSlotList(1, $a = []), Crypt::PKCS11::CKR_OK );
        myis( $obj->C_GetSlotList(0, $a = []), Crypt::PKCS11::CKR_OK );
        foreach (@$a) {
            myis( $obj->C_GetSlotInfo($_, $h = {}), Crypt::PKCS11::CKR_OK );
            myis( $obj->C_GetTokenInfo($_, $h = {}), Crypt::PKCS11::CKR_OK );
            myis( $obj->C_GetMechanismList($_, $a2 = []), Crypt::PKCS11::CKR_OK );
            foreach my $m (@$a2) {
                myis( $obj->C_GetMechanismInfo($_, $m, $h = {}), Crypt::PKCS11::CKR_OK );
            }
            myis( $obj->C_InitToken($_, "12345678", "ѪѫѬѪѫѬ"), Crypt::PKCS11::CKR_OK );
            myis( $obj->C_GetTokenInfo($_, $h = {}), Crypt::PKCS11::CKR_OK );
            $h->{label} =~ s/\s+$//o;
            myis( $h->{label}, "ѪѫѬѪѫѬ" );
            # TODO: C_InitPIN
            # TODO: C_SetPIN
            # TODO: C_OpenSession with callback
            myis( $obj->C_OpenSession($_, Crypt::PKCS11::CKF_SERIAL_SESSION|Crypt::PKCS11::CKF_RW_SESSION, undef, $s), Crypt::PKCS11::CKR_OK );
            myisnt( $s, Crypt::PKCS11::CK_INVALID_HANDLE );
            myisnt( $s, undef );
            myis( $obj->C_CloseSession($s), Crypt::PKCS11::CKR_OK );
            myis( $obj->C_OpenSession($_, Crypt::PKCS11::CKF_SERIAL_SESSION|Crypt::PKCS11::CKF_RW_SESSION, undef, $s), Crypt::PKCS11::CKR_OK );
            myisnt( $s, Crypt::PKCS11::CK_INVALID_HANDLE );
            myisnt( $s, undef );
            myis( $obj->C_CloseAllSessions($_), Crypt::PKCS11::CKR_OK );
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
        }
        myis( $obj->C_Finalize, Crypt::PKCS11::CKR_OK );
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
