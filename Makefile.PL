use 5.008005;
use ExtUtils::MakeMaker 7.12; # for XSMULTI option

use Config;

sub search_lib {
    my ($lib) = @_;
    unless ($lib =~ /^-l/) {
        warn "search_lib: illegal arguments, \`$lib\'.\n";
        return undef;
    }
    my $libbase = 'lib' . substr($lib, 2) . $Config{lib_ext};
    my $libbase_so = 'lib' . substr($lib, 2) . "." . $Config{so};
    my $libbase_cyg = 'lib' . substr($lib, 2) . ".dll" . $Config{lib_ext};

    my @paths = split(' ', $Config{libpth});
    push @paths, $ENV{PERL_LIBPATH} if exists $ENV{PERL_LIBPATH};

    for my $path (@paths) {
        if (-f $path . '/' . $libbase) {
            print "$path/$libbase\n";
            print "Found '$path/$libbase'.\n";
            return $lib;
        } elsif (-f $path . '/' . $libbase_so) {
            print "$path/$libbase_so\n";
            print "Found `$path/$libbase_so'.\n";
            return $lib;
        } elsif (-f $path . '/' . $libbase_cyg) {
            print "$path/$libbase_cyg\n";
            print "Found `$path/$libbase_cyg'.\n";
            return $lib;
        }
    }
    return undef;
}

if (!defined search_lib('-lcrypto')) {
        warn "* libcrypto is not installed or not in the default lib path. Aborting.\n";
        exit;
}

my $inc_path;
my $lib_path;
if (-d "/usr/include/openssl") {
        $inc_path = '-I/usr/include/openssl';
        $lib_path = '/usr/lib';
} elsif (-d "/usr/local/include/ssl") {
        $inc_path = '-I/usr/local/include/ssl';
        $lib_path = '/usr/local/lib/ssl';
} elsif (-d "/usr/local/ssl/include") {
        $inc_path = '-I/usr/local/ssl/include';
        $lib_path = '/usr/local/ssl/lib';
}

my $lib_links = '-lcrypto';

my $ccflags = '';
if ($Config::Config{ccname} =~ /gcc/i) {
  $ccflags =  $ENV{AUTHOR_TESTING} ? '-Wall -Werror': '-Wall';
} else {
  $ccflags =  '';
}

my $optimize_flags = '';
if (($Config::Config{myuname} =~ /sunos|solaris/i) && ($Config::Config{PATCHLEVEL} =~ /5.20/)) {
    $optimize_flags = "-O3 -DOPENSSL_API_COMPAT=0x10100000L";
} else {
    $optimize_flags = "-O3 $ccflags -DOPENSSL_API_COMPAT=0x10100000L";
}

my @authors = ( 'Timothy Legge <timlegge@cpan.org>', 'Wesley Schwengle <waterkip@cpan.org>' );

WriteMakefile(
  NAME           => 'Crypt::OpenSSL::Verify',
  VERSION_FROM   => 'lib/Crypt/OpenSSL/Verify.pm',
  PREREQ_PM      => {
      'perl' => '5.010',
      'ExtUtils::MakeMaker' => '7.12',
      'Crypt::OpenSSL::X509' => '1.807'
  },
  ABSTRACT_FROM  => 'lib/Crypt/OpenSSL/Verify.pm',
  AUTHOR         => \@authors,
  CONFIGURE_REQUIRES => {
      ExtUtils::MakeMaker=>q[6.59],
  },
  BUILD_REQUIRES => {
      ExtUtils::MakeMaker=>q[6.59],
      File::Slurp=>q[0],
      Test::More=>q[0.88]
  },
  MIN_PERL_VERSION => '5.010',
  INC            => "$inc_path",
  LIBS           => "$lib_links",
  TEST_REQUIRES  => {
      'Test::More' => '0.88',
      'File::Slurp' => '0' ,
      'Test::NoTabs' => '0',
      'Test::Pod' => '1.14',
      'Test::Pod::Coverage' => '1.04',
      'Test::Exception' => '0',
  },
  test          => {
        TESTS => 't/*.t t/author/*.t',
  },
  OPTIMIZE       => "$optimize_flags",
  LICENSE        => 'perl_5',
  XSMULTI        => 1,
  META_MERGE        => {
        "meta-spec" => { version => 1.4 },
        resources => {
            bugtracker => 'https://github.com/perl-net-saml2/perl-Crypt-OpenSSL-Verify/issues',
            repository => 'https://github.com/perl-net-saml2/perl-Crypt-OpenSSL-Verify',
            license     => "http://dev.perl.org/licenses",
        },
  },
);
