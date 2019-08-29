#!/usr/bin/perl
use strict;
#
# if needed install additional perl modules using cpanm Digest::HMAC Digest::SHA1
use Digest::HMAC qw(hmac hmac_hex);
use Digest::SHA1;
use Sys::Hostname;

my $hostname=hostname();

if (scalar @ARGV !=1)  {
  my $message = "This script generates a JSON configuration file that should be passed to the HNA\n";
  $message.= "The first parameter should be a FQDN of the delegated zone e.g. sub.homenetdns.com\n";
  print $message;
  exit 0;
}

# trivial for now
my $destination="/var/www/html/config/"; # include trailing /
my $key="My secret key. shhhh!";

my $zone=$ARGV[0];

# read in the certificate
my $certfn=$zone.".pem";

open (my $certfh,"<",$certfn) or die "Can't open certificate file < $certfn $!";
my $one_line_cert="";
my $ignore=1;
while (my $l=<$certfh>) {
  chomp($l);
  $ignore=0 if ($l =~ /-----BEGIN CERTIFICATE-----/);
  next if ($ignore == 1);
  $one_line_cert.=$l.'\n'; # non-interpolated crlf
  $ignore=1 if ($l =~ /-----END CERTIFICATE-----/);
}

close $certfh;

# read in the key
my $keyfn=$zone.".key";

open (my $keyfh,"<",$keyfn) or die "Can't open keyfile < $keyfn $!";
my $one_line_key="";
$ignore=1;
while (my $l=<$keyfh>) {
  chomp($l);
  $ignore=0 if ($l =~ /-----BEGIN RSA PRIVATE KEY-----/);
  next if ($ignore == 1);
  $one_line_key.=$l.'\n'; # non-interpolated crlf
  $ignore=1 if ($l =~ /-----END RSA PRIVATE KEY----/);
}

close $keyfh;


print "Generating JSON config file for zone:$zone\n";

my $hmac=Digest::HMAC->new($key,"Digest::SHA1");
$hmac->add($zone);

my $fn="config_".$hmac->hexdigest.".json";
my $fp = $destination.$fn;

print "Storing result in $fp\n";

open (my $fh, ">", $fp) or die "Can't open > $fp: $!";

print $fh "{";
print $fh "\"dm_notify\":\"2001:470:1f15:62e:21c::2\",";
print $fh "\"dm_acl\":\"2001:470:1f15:62e:21c::/64\",";
print $fh "\"dm_ctrl\":\"dm.homenetdns.com\",";
print $fh "\"dm_port\":\"4433\",";
print $fh "\"zone\":\"$zone\",";
print $fh "\"hna_certificate\":\"$one_line_cert\",";
print $fh "\"hna_key\":\"$one_line_key\"";


print $fh "}\n";
close $fh;
print "Please share the url $hostname/config/$fn with the HNA\n";
print "Generating knot-dm delegation glue for zone:$zone\n";
$zone.="." if $zone !~/.*\.$/;
my $new_zone=`/usr/local/etc/knot-dm/make_new_ns.bash $zone`;

exit 0;
