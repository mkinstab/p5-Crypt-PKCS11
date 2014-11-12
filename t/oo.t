#!perl

use Test::More;
use Config;

use Crypt::PKCS11 qw(:constant :constant_names);
use Crypt::PKCS11::Attributes;

my @pkcs11_libraries = (
    '/softhsm/libsofthsm.so',
    '/softhsm/libsofthsm2.so'
);
my %library_paths = (
    '/usr/local/lib64' => 1,
    '/usr/lib64' => 1,
    '/usr/local/lib' => 1,
    '/usr/lib' => 1
);
my @libraries;

foreach my $path (
    split / /, $Config{loclibpth},
    split / /, $Config{libpth} )
{
    $library_paths{$path} = 1;
}

foreach my $path (keys %library_paths) {
    foreach my $so (@pkcs11_libraries) {
        push(@libraries, $path.$so) if (-r $path.$so);
    }
}

chdir('t');

foreach my $so (@libraries) {
    my $obj;
    my $s;

    my $slotWithToken = 1;
    %MECHANISM_SIGNVERIFY = ();
    foreach (( CKM_RSA_PKCS, CKM_RSA_X_509, CKM_MD5_RSA_PKCS,
        CKM_RIPEMD160_RSA_PKCS, CKM_SHA1_RSA_PKCS ,CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS, CKM_SHA1_RSA_PKCS_PSS,
        CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS,
        CKM_SHA512_RSA_PKCS_PSS ))
    {
        isa_ok( ($MECHANISM_SIGNVERIFY{$_} = Crypt::PKCS11::CK_MECHANISM->new), 'Crypt::PKCS11::CK_MECHANISMPtr' );
        is( $MECHANISM_SIGNVERIFY{$_}->set_mechanism($_), CKR_OK, 'CK_MECHANISM->new->set_mechanism('.$CKM_NAME{$_}.')' );
    }

    isa_ok( ($param = Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS->new), 'Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMSPtr' );
    is( $param->set_hashAlg(CKM_SHA_1), CKR_OK, 'CK_RSA_PKCS_PSS_PARAMS->set_hashAlg(CKM_SHA_1)' );
    is( $param->set_mgf(CKG_MGF1_SHA1), CKR_OK, 'CK_RSA_PKCS_PSS_PARAMS->set_mgf(CKG_MGF1_SHA1)' );
    is( $param->set_sLen(20), CKR_OK, 'CK_RSA_PKCS_PSS_PARAMS->set_sLen(20)' );
    is( $MECHANISM_SIGNVERIFY{CKM_SHA1_RSA_PKCS_PSS()}->set_pParameter($param->toBytes), CKR_OK, 'CK_MECHANISM(CKM_SHA1_RSA_PKCS_PSS)->new->set_pParameter()' );

    isa_ok( ($param = Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS->new), 'Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMSPtr' );
    is( $param->set_hashAlg(CKM_SHA256), CKR_OK, 'CK_RSA_PKCS_PSS_PARAMS->set_hashAlg(CKM_SHA256)' );
    is( $param->set_mgf(CKG_MGF1_SHA256), CKR_OK, 'CK_RSA_PKCS_PSS_PARAMS->set_mgf(CKG_MGF1_SHA256)' );
    is( $param->set_sLen(0), CKR_OK, 'CK_RSA_PKCS_PSS_PARAMS->set_sLen(0)' );
    is( $MECHANISM_SIGNVERIFY{CKM_SHA256_RSA_PKCS_PSS()}->set_pParameter($param->toBytes), CKR_OK, 'CK_MECHANISM(CKM_SHA256_RSA_PKCS_PSS)->new->set_pParameter()' );

    isa_ok( ($param = Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS->new), 'Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMSPtr' );
    is( $param->set_hashAlg(CKM_SHA384), CKR_OK, 'CK_RSA_PKCS_PSS_PARAMS->set_hashAlg(CKM_SHA384)' );
    is( $param->set_mgf(CKG_MGF1_SHA384), CKR_OK, 'CK_RSA_PKCS_PSS_PARAMS->set_mgf(CKG_MGF1_SHA384)' );
    is( $param->set_sLen(0), CKR_OK, 'CK_RSA_PKCS_PSS_PARAMS->set_sLen(0)' );
    is( $MECHANISM_SIGNVERIFY{CKM_SHA384_RSA_PKCS_PSS()}->set_pParameter($param->toBytes), CKR_OK, 'CK_MECHANISM(CKM_SHA384_RSA_PKCS_PSS)->new->set_pParameter()' );

    isa_ok( ($param = Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS->new), 'Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMSPtr' );
    is( $param->set_hashAlg(CKM_SHA512), CKR_OK, 'CK_RSA_PKCS_PSS_PARAMS->set_hashAlg(CKM_SHA512)' );
    is( $param->set_mgf(CKG_MGF1_SHA512), CKR_OK, 'CK_RSA_PKCS_PSS_PARAMS->set_mgf(CKG_MGF1_SHA512)' );
    is( $param->set_sLen(0), CKR_OK, 'CK_RSA_PKCS_PSS_PARAMS->set_sLen(0)' );
    is( $MECHANISM_SIGNVERIFY{CKM_SHA512_RSA_PKCS_PSS()}->set_pParameter($param->toBytes), CKR_OK, 'CK_MECHANISM(CKM_SHA512_RSA_PKCS_PSS)->new->set_pParameter()' );

    if ($so =~ /libsofthsm\.so$/o) {
        $ENV{SOFTHSM_CONF} = 'softhsm.conf';
        system('softhsm --slot 1 --init-token --label slot1 --so-pin 12345678 --pin 1234') == 0 || die;
    }
    elsif ($so =~ /libsofthsm2\.so$/o) {
        $ENV{SOFTHSM2_CONF} = 'softhsm2.conf';
        system('mkdir -p tokens') == 0 || die;
        system('softhsm2-util --slot 0 --init-token --label slot1 --so-pin 12345678 --pin 1234') == 0 || die;
        $slotWithToken = 0;
        delete $MECHANISM_INFO{CKM_RIPEMD160};
        delete $MECHANISM_INFO{CKM_RIPEMD160_RSA_PKCS};
        delete $MECHANISM_SIGNVERIFY{CKM_RIPEMD160_RSA_PKCS};
    }
    
    isa_ok( $obj = Crypt::PKCS11->new, 'Crypt::PKCS11', $so.' new' );
    ok( $obj->load($so), $so.' load' );
    ok( $obj->Initialize, $so.' Initialize' );
    isa_ok( $obj->GetInfo, 'HASH', $so.' GetInfo' );
    isa_ok( $s = $obj->OpenSession($slotWithToken, CKF_SERIAL_SESSION), 'Crypt::PKCS11::Session', $so.' OpenSession' );
    ok( $obj->Finalize, $so.' Finalize' );
    ok( $obj->unload, $so.' unload' );
}

done_testing;
