# easy en/decrypting with DES/IDEA/Blowfish
# Mike Blazer <blazer@mail.nevalink.ru>  Mar 5, 2000

package Crypt::CBCeasy;

use 5.003;
use strict;
no strict 'refs';
use vars qw($VERSION);

use Crypt::CBC;
use Carp;

$VERSION = '0.21';


#--------------
sub useCBC {
#--------------
# $from - handler (r), filename or just plain or encrypted text
# $to   - handler (r), or filename. If '' or undef sub returns $to-string
  my ($key, $algorithm, $from, $to, $op) = @_;
  my ($fhi, $fho, $fromFile, $buffer, $fromStr, $toStr, $cipher);
  local ($_, *I, *O);

  croak "CBCeasy: source not defined\n"      unless defined $from;
  croak "CBCeasy: key not defined\n"         unless defined $key;
  croak "CBCeasy: you must provide \$op eq `en' or `de'\n" unless $op && $op =~ /^(en|de)$/i;

  if ((UNIVERSAL::isa($from, 'GLOB') ||     # \*HANDLE
       UNIVERSAL::isa(\$from,'GLOB')        # *HANDLE
       ) &&  defined fileno $from
     ) {

     $fhi = $from; $fromFile = 1;

  } elsif (-e $from && -r _) {      # filename
     $fhi = *I; $fromFile = 1;
     open ($fhi, $from) || croak "CBCeasy: file `$from' not found/readable\n";

  } elsif (-e $from && !-r _) {     # filename
     croak "CBCeasy: file `$from' not readable\n";

  } else { # stream itself in $from
  }

  $cipher = new Crypt::CBC($key, $algorithm);
  $cipher->start(lc $op);

  if ($fromFile) {

     binmode $fhi;
     # fails with too long chains
     while (read($fhi,$buffer,4096)) {
	$toStr .= $cipher->crypt($buffer);
     }
     $toStr .= $cipher->finish;

     close $fhi if $fhi eq *I;

  } else {
     # fails with too long chains
     while ($from) {
       $fromStr = substr($from, 0, 4096);
       substr($from, 0, 4096) = '';
       $toStr .= $cipher->crypt($fromStr);
     }
     $toStr .= $cipher->finish;
  }

  return $toStr unless $to;

  if ((UNIVERSAL::isa($to, 'GLOB') ||     # \*HANDLE
       UNIVERSAL::isa(\$to,'GLOB')        # *HANDLE
      ) &&  defined fileno $to
     ) {

     $fho = $to;

  } else {      # filename
     $fho = *O;
     open ($fho, ">$to") || croak "CBCeasy: can't write file `$to'\n";

  }

  binmode $fho;
  print $fho $toStr;

  close $fho if $fho eq *O;

}

package DES;

sub encipher ($$;$) {
  Crypt::CBCeasy::useCBC($_[0], __PACKAGE__, $_[1], ($_[2]||undef) , 'en');
}

sub decipher ($$;$) {
  Crypt::CBCeasy::useCBC($_[0], __PACKAGE__, $_[1], ($_[2]||undef) , 'de');
}

*IDEA::encipher = *Blowfish::encipher = \&DES::encipher;
*IDEA::decipher = *Blowfish::decipher = \&DES::decipher;

1;
__END__

=head1 NAME

Crypt::CBCeasy - Easy things make really easy with Crypt::CBC

=head1 SYNOPSIS

 use Crypt::CBCeasy;

 IDEA::encipher($my_key, "plain-file", "crypted-file");

 $plain_text = DES::decipher($my_key, \*CRYPTO_FILE);

 $crypted = Blowfish::encipher($my_key, \*PLAIN_SOCKET);

=head1 ABSTRACT

This module is just a helper for Crypt::CBC to make simple and
usual jobs just one-liners.

The current version of the module is available at:

  http://base.dux.ru/guest/fno/perl/

=head1 DESCRIPTION

This module creates C<encipher()> and C<decipher()> functions
in B<DES::>, B<IDEA::> and
B<Blowfish::> namespaces (the last one works only if your Crypt::CBC
is 1.22 or later). So, the total is 6 functions neither of which is
imported.

All functions take 3 parameters:

  1 - en/decryption key
  2 - source
  3 - destination

Sources could be: existing file path, scalar (just a string that would be
encrypted), opened filehandle, any object that inherits from filehandle,
for example IO::File or FileHandle object, and socket.

Destinations could be any of the above except scalar, because we can not
distinguish between scalar and output file name here.

Well, it's easier to look at the examples:

(C<$fh> vars here are IO::Handle, IO::File or FileHandle objects,
variables of type "GLOB", "GLOB" refs or sockets)

B<IDEA::encipher(> $my_key, "in-file", "out-file" B<);>

B<IDEA::encipher(> $my_key, *IN, "out-file" B<);>

B<IDEA::encipher(> $my_key, \*IN, "out-file" B<);>

B<IDEA::encipher(> $my_key, $fh_in, "out-file" B<);>

B<IDEA::encipher(> $my_key, "in-file", *OUT B<);>

B<IDEA::encipher(> $my_key, "in-file", \*OUT B<);>

B<IDEA::encipher(> $my_key, "in-file", $fh_out B<);>

B<IDEA::encipher(> $my_key, *IN, *OUT B<);>

B<IDEA::encipher(> $my_key, \*IN, \*OUT B<);>

B<IDEA::encipher(> $my_key, $fh_in, $fh_out B<);>

B<IDEA::encipher(> $my_key, $plain_text, "out-file" B<);>

B<IDEA::encipher(> $my_key, $plain_text, *OUT B<);>

B<IDEA::encipher(> $my_key, $plain_text, \*OUT B<);>

B<IDEA::encipher(> $my_key, $plain_text, $fh_out B<);>

any of the above will work and do what was expected.

In addition there is a 2-argument version that returns it's result
as scalar:

$crypted_text = B<IDEA::encipher(> $my_key, $plain_text B<);>

$crypted_text = B<IDEA::encipher(> $my_key, "in-file" B<);>

$crypted_text = B<IDEA::encipher(> $my_key, *IN B<);>

$crypted_text = B<IDEA::encipher(> $my_key, \*IN B<);>

$crypted_text = B<IDEA::encipher(> $my_key, $fh B<);>

All the same is implemented for C<decipher()> and for B<DES> and
B<Blowfish>.

All functions croak on errors (such as "input file not found"), so
if you want to trap errors use them inside the C<eval{}> block
and check C<$@>.

Sure IDEA:: functions will work only if you have Crypt::IDEA installed,
DES:: - if you have Crypt::DES, Blowfish:: - if you have Crypt::Blowfish
and Crypt::CBC is version 1.22 or above.

Note that all filehandles are used in C<binmode> whether you claimed them
C<binmode> or not. On Win32 for example this will result in CRLF's in
$plain_text after

 $plain_text = DES::decipher($my_key, "crypted_file");

if "crypted_file" was created by

 DES::encipher($my_key, "text_file", "crypted_file");

If the filehandle was used before - it's your job to rewind it
to the beginning and/or close.

=head1 INSTALLATION

As this is just a plain module no special installation is needed. Put it
into the /Crypt subdirectory somewhere in your @INC. Though the standard

 Makefile.PL
 make
 make test
 make install

procedure is provided. In addition

 make html

will produce the HTML-docs.

This module requires

Crypt::CBC at least 1.20 by Lincoln Stein, lstein@cshl.org

one or more of

Crypt::IDEA, Crypt::DES, Crypt::Blowfish available from CPAN

=head1 CAVEATS

This module has been created and tested in a Win95 environment.  Although
I expect it to function correctly on any other system, that fact
has not been confirmed.

=head1 CHANGES

 0.21   Mon Mar  6 07:28:41 2000  -  first public release

=head1 TODO

Any suggestions are much appreciated.

=head1 BUGS

Please report.

=head1 VERSION

This man page documents "Crypt::CBCeasy" version 0.21.

March 6, 2000.

=head1 AUTHOR

Mike Blazer, blazer@mail.nevalink.ru

http://base.dux.ru/guest/fno/perl/

=head1 SEE ALSO

Crypt::CBC

=head1 COPYRIGHT

Copyright (C) 2000 Mike Blazer.

This package is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut

