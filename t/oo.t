#!perl

use Test::More;
use Config;

use Crypt::PKCS11 qw(:constant :constant_names);
use Crypt::PKCS11::Attributes;

sub signVerifyCheck {
    my ($obj) = @_;
    my $mechanism = Crypt::PKCS11::CK_MECHANISM->new;
    my $publicKeyTemplate = Crypt::PKCS11::Attributes->new->push(
        Crypt::PKCS11::Attribute::Encrypt->new->set(1),
        Crypt::PKCS11::Attribute::Verify->new->set(1),
        Crypt::PKCS11::Attribute::Wrap->new->set(1),
        Crypt::PKCS11::Attribute::PublicExponent->new->set(0x01, 0x00, 0x01),
        Crypt::PKCS11::Attribute::Token->new->set(1),
        Crypt::PKCS11::Attribute::ModulusBits->new->set(768)
    );
    my $privateKeyTemplate = Crypt::PKCS11::Attributes->new->push(
        Crypt::PKCS11::Attribute::Private->new->set(1),
        Crypt::PKCS11::Attribute::Id->new->set(123),
        Crypt::PKCS11::Attribute::Sensitive->new->set(1),
        Crypt::PKCS11::Attribute::Decrypt->new->set(1),
        Crypt::PKCS11::Attribute::Sign->new->set(1),
        Crypt::PKCS11::Attribute::Unwrap->new->set(1),
        Crypt::PKCS11::Attribute::Token->new->set(1)
    );
    my $data = 'Text';
    my $signature;
    my $session;

    ok( $obj->Initialize, 'signVerifyCheck: Initialize' );
    isa_ok( $session = $obj->OpenSession($slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION), 'Crypt::PKCS11::Session', 'signVerifyCheck: OpenSession #1' );
    ok( $session->Login(CKU_USER, "1234"), 'signVerifyCheck: Login' );
    is( $mechanism->set_mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN), CKR_OK, 'signVerifyCheck: set_mechanism' );
    my ($publicKey, $privateKey) = $session->GenerateKeyPair($mechanism, $publicKeyTemplate, $privateKeyTemplate);
    is( $session->errno, CKR_OK, 'signVerifyCheck: GenerateKeyPair '.$session->errstr );
    isa_ok( $publicKey, 'Crypt::PKCS11::Object', 'signVerifyCheck: publicKey' );
    isa_ok( $privateKey, 'Crypt::PKCS11::Object', 'signVerifyCheck: privateKey' );
#    foreach (values %MECHANISM_SIGNVERIFY) {
#        myis( $obj->C_SignInit($sessions[0], $_, $privateKey), CKR_OK, 'signVerifyCheck: C_SignInit mech '.($MECHANISM_INFO{$_->{mechanism}} ? $MECHANISM_INFO{$_->{mechanism}}->[1] : $_->{mechanism}) );
#        $signature = undef;
#        myis( $obj->C_Sign($sessions[0], $data, $signature), CKR_OK, 'signVerifyCheck: C_Sign mech '.($MECHANISM_INFO{$_->{mechanism}} ? $MECHANISM_INFO{$_->{mechanism}}->[1] : $_->{mechanism}) );
#        myis( $obj->C_VerifyInit($sessions[0], $_, $publicKey), CKR_OK, 'signVerifyCheck: C_VerifyInit mech '.($MECHANISM_INFO{$_->{mechanism}} ? $MECHANISM_INFO{$_->{mechanism}}->[1] : $_->{mechanism}) );
#        myis( $obj->C_Verify($sessions[0], $data, $signature), CKR_OK, 'signVerifyCheck: C_Verify mech '.($MECHANISM_INFO{$_->{mechanism}} ? $MECHANISM_INFO{$_->{mechanism}}->[1] : $_->{mechanism}) );
#    }
#    myis( $obj->C_DestroyObject($sessions[0], $privateKey), CKR_OK, 'signVerifyCheck: C_DestroyObject' );
#    myis( $obj->C_DestroyObject($sessions[0], $publicKey), CKR_OK, 'signVerifyCheck: C_DestroyObject #2' );
    ok( $obj->Finalize, 'signVerifyCheck: Finalize' );
}

sub mytests {
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

    foreach my $so (@libraries) {
        my $obj;
        my $s;

        $slotWithToken = 1;
        %MECHANISM_INFO = (
            CKM_RSA_PKCS_KEY_PAIR_GEN => [ CKM_RSA_PKCS_KEY_PAIR_GEN, 'CKM_RSA_PKCS_KEY_PAIR_GEN' ],
            CKM_RSA_PKCS => [ CKM_RSA_PKCS, 'CKM_RSA_PKCS' ],
            CKM_MD5 => [ CKM_MD5, 'CKM_MD5' ],
            CKM_RIPEMD160 => [ CKM_RIPEMD160, 'CKM_RIPEMD160' ],
            CKM_SHA_1 => [ CKM_SHA_1, 'CKM_SHA_1' ],
            CKM_SHA256 => [ CKM_SHA256, 'CKM_SHA256' ],
            CKM_SHA384 => [ CKM_SHA384, 'CKM_SHA384' ],
            CKM_SHA512 => [ CKM_SHA512, 'CKM_SHA512' ],
            CKM_MD5_RSA_PKCS => [ CKM_MD5_RSA_PKCS, 'CKM_MD5_RSA_PKCS' ],
            CKM_RIPEMD160_RSA_PKCS => [ CKM_RIPEMD160_RSA_PKCS, 'CKM_RIPEMD160_RSA_PKCS' ],
            CKM_SHA1_RSA_PKCS => [ CKM_SHA1_RSA_PKCS, 'CKM_SHA1_RSA_PKCS' ],
            CKM_SHA256_RSA_PKCS => [ CKM_SHA256_RSA_PKCS, 'CKM_SHA256_RSA_PKCS' ],
            CKM_SHA384_RSA_PKCS => [ CKM_SHA384_RSA_PKCS, 'CKM_SHA384_RSA_PKCS' ],
            CKM_SHA512_RSA_PKCS => [ CKM_SHA512_RSA_PKCS, 'CKM_SHA512_RSA_PKCS' ]
        );
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
        signVerifyCheck($obj);
        ok( $obj->unload, $so.' unload' );
    }
}

chdir('t');
mytests;
done_testing;
