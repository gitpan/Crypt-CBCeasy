#!/usr/bin/perl -w

use Crypt::CBCeasy;

$|=1;
require "chat2new.pl";

$host="204.71.200.67";
$req= "GET / HTTP/1.0\r\n\r\n";

http_get($host,80,$req);


sub http_get {
    my ($host,$port,$request) = @_;
    my ($rezult, $handle);
    ($handle = chat::open_port($host, $port))
        || die "chat::open($host,$port): $!\n";

    chat::print($handle,$request);

    *S = *chat::S = *chat::S; # avoid warnings
#    $rezult = join"",<S>;

    my $key     = "my personal key";
    IDEA::encipher($key, *S, "outfile");
    IDEA::decipher($key, "outfile", "outfile.html");

    chat::close($handle);
#    $rezult;
}