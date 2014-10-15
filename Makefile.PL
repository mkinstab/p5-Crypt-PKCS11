use 5.008000;
use Config;
use ExtUtils::MakeMaker;

# have_inc() EV's Makefile.PL by Marc Lehmann <schmorp@schmorp.de>
sub have_inc($) {
   scalar grep -r "$_/$_[0]", $Config{usrinc}, split / /, $Config{incpth}
}

my @LIBS;
my @DEFINES;

if (have_inc('dlfcn.h')) {
    push(@LIBS, '-ldl');
    push(@DEFINES, '-DHAVE_DLFCN_H=1');
}

WriteMakefile(
    NAME              => 'Crypt::PKCS11',
    VERSION_FROM      => 'lib/Crypt/PKCS11.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (#ABSTRACT_FROM  => 'lib/Crypt/PKCS11.pm', # retrieve abstract from module
       AUTHOR         => 'Jerry Lundström <lundstrom.jerry@gmail.com>') : ()),
    LIBS              => \@LIBS, # e.g., '-lm'
    DEFINE            => join(' ', @DEFINES), # e.g., '-DHAVE_SOMETHING'
    INC               => '-I.', # e.g., '-I. -I/usr/include/other'
    OBJECT            => '$(O_FILES)', # link all the C files too
    TYPEMAPS          => [ 'typemap', 'typemap.struct' ],
);
