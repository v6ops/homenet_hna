make_ca.bash is a script to initialise a CA. Sample config is supplied for all openssl parameters except the common name
The common name should be set to the FQDN of the DM.
Argument 1 should be a secret used to encrypt the private key.

make_zone_cert.bash is a script to create a certificate signed with the root CA certificate.
This certificate should have a common name of the FQDN of the zone to be delegated e.g. sub.homenetdns.com
Argument 1 is the zone name.
The output is a PEM file that can be given to the HNA to validate itself to the DM.

make_hna_conf.pl is a perl script that generates a JSON config string that can be sent to the HNA during enrolment.
You probably want to improve security here e.g. ask for username password before serving the file, creating the file on the fly, or deleting it once served and enrolment is complete

fwd.subzone.homenetdns.com.db is a template zone file served to the HNA from the DM. Used by the HNA to set default values and the upstream NS records when generating the HOmenet zone
