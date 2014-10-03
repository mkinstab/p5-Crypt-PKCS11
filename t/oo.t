#!perl

use Test::More;
use Config;

use Crypt::PKCS11 qw(:constant);

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

    if ($so =~ /libsofthsm\.so$/o) {
        $ENV{SOFTHSM_CONF} = 'softhsm.conf';
        system('softhsm --slot 1 --init-token --label slot1 --so-pin 12345678 --pin 1234') == 0 || die;
    }
    elsif ($so =~ /libsofthsm2\.so$/o) {
        $ENV{SOFTHSM2_CONF} = 'softhsm2.conf';
        system('mkdir -p tokens') == 0 || die;
        system('softhsm2-util --slot 0 --init-token --label slot1 --so-pin 12345678 --pin 1234') == 0 || die;
        $slotWithToken = 0;
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
