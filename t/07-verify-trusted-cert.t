use strict;
use warnings;
use Crypt::OpenSSL::Verify;
use Crypt::OpenSSL::X509;
use IO::Socket::SSL;
use Net::SSLeay;
use Data::Dumper;
use File::Slurp qw{ write_file };
use Test::More;

my $openssl_version = `openssl version`;

    $openssl_version =~ /OpenSSL ([\d\.]+)/;
    $openssl_version = $1;

my %chain = ();
my $inter_cnt = 1;

my $server_name = 'www.google.com';

sub verify_callback {
    my $cert = $_[4];
    my $subject = Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($cert));
    my $issuer  = Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_issuer_name($cert));

    $subject =~ /CN=(.*$)/;
    $subject = $1;
    $issuer =~ /CN=(.*$)/;
    $issuer = $1;
    if ( $subject eq $server_name ) {
        $chain{'server'} = { name => $subject, x509 => Net::SSLeay::PEM_get_string_X509($cert), }; 
    } elsif ( $subject ne $issuer ) {
        my $int = 'intermediate' . $inter_cnt;
        $chain{'intermediates'} = $inter_cnt;
        $chain{$int} = { 'name' => $subject, 'x509' => Net::SSLeay::PEM_get_string_X509($cert), }; 
        $inter_cnt++;
    } elsif ( $subject eq $issuer ) {
        $chain{'root'} = { 'name' => $subject, 'x509' => Net::SSLeay::PEM_get_string_X509($cert), };
    }
    return 1;
}

sub get_cert_chain {
    my $peer = shift;
    IO::Socket::SSL->new(
        PeerHost => $peer . ":443",
        SSL_verify_callback => \&verify_callback
    ) or die $SSL_ERROR||$!;
}

get_cert_chain($server_name);

my $cert = $chain{'server'}{'x509'};

my $intermediate = '';
for ( my $i = 1; $i <= $chain{intermediates}; $i++ ) {
    $intermediate = $intermediate . $chain{"intermediate$i"}{'x509'} ."\n";
}

write_file('intermediate.pem', $intermediate);
write_file('cert.pem', $cert);

#say 'OpenSSL verification:';
my $ret;
eval {
    $ret = `openssl verify -CAfile intermediate.pem cert.pem`;
};
ok($ret =~ 'OK', "OpenSSL verification - OK");

#say 'Crypt::OpenSSL::Verify verification:';
my $verifier = Crypt::OpenSSL::Verify->new('intermediate.pem',{strict_certs=>0});
my $cert_object = Crypt::OpenSSL::X509->new_from_string($cert);
my $verify = $verifier->verify($cert_object);
ok($verify, "Crypt::OpenSSL::Verify verification - OK");

$verifier = Crypt::OpenSSL::Verify->new('intermediate.pem',{strict_certs=>1});
$cert_object = Crypt::OpenSSL::X509->new_from_string($cert);
$verify = $verifier->verify($cert_object);
ok($verify, "Crypt::OpenSSL::Verify strict verification - OK");

SKIP: {
    skip "Incorrect version of openSSL", 2 unless ($openssl_version ge '1.1.1');
    #say 'OpenSSL verification - noCApath:';
    eval {
        $ret = `openssl verify -no-CApath -CAfile intermediate.pem cert.pem  2>&1`;
    };
    ok ($ret =~ /error 2 at 1 depth lookup: .* issuer certificate/s, "OpenSSL verification no-CApath - OK");

    $verifier = Crypt::OpenSSL::Verify->new('intermediate.pem', {noCApath =>1, strict_certs=>1});
    $cert_object = Crypt::OpenSSL::X509->new_from_string($cert);
    eval {
        $ret = $verifier->verify($cert_object);
    };
    ok($ret =~ /error 2 at 1 depth lookup: .* issuer certificate/s, "Crypt::OpenSSL::Verify - noCApath failed to find root - OK");
}

#say 'OpenSSL verification intermediate:';
eval {
    $ret = `openssl verify intermediate.pem`;
};
ok ($ret =~ /intermediate.pem: OK/s, "OpenSSL verification intermediate - OK");

$verifier = Crypt::OpenSSL::Verify->new('', { strict_certs=>1});
$cert_object = Crypt::OpenSSL::X509->new_from_string($intermediate);
eval {
    $ret = $verifier->verify($cert_object);
};
ok($ret, "Crypt::OpenSSL::Verify intermediate - OK");

SKIP: {
    skip "Incorrect version of openSSL", 2 unless ($openssl_version ge '1.1.1');
    #say 'OpenSSL verification intermediate - noCAfile & noCApath:';
    eval {
        $ret = `openssl verify -no-CApath -no-CAfile intermediate.pem  2>&1`;
    };
    ok ($ret =~ /error 20 at 0 depth lookup: unable to get local issuer certificate/s, "OpenSSL verification intermediate no-CAfile & no-CApath - OK");

    $verifier = Crypt::OpenSSL::Verify->new('', {noCAfile =>1,  noCApath =>1, strict_certs=>1});
    $cert_object = Crypt::OpenSSL::X509->new_from_string($intermediate);
    eval {
        $ret = $verifier->verify($cert_object);
    };
    ok($ret =~ /error 20 at 0 depth lookup: unable to get local issuer certificate/s, "Crypt::OpenSSL::Verify intermediate - noCAfile & noCApath failed to find root - OK");
}


done_testing;
