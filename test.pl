# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN {
 # OK, we want to check THIS version, not some older one
 unshift @INC, qw(blib/lib blib/arch);

 require Crypt::CBC;
 
 @ciphers = ();
 for ('DES', 'IDEA', ($Crypt::CBC::VERSION >= 1.22 ? 'Blowfish' : ())) {
   eval "require Crypt::$_";
   $@ or push @ciphers, $_;
   undef $@;
 }

 $all_tests = 27;

 $| = 1; print "1..".(2 + $all_tests * scalar @ciphers)."\n";
}
END {print "not ok 1\n" unless $loaded;}

use Crypt::CBCeasy;
use MD5;
use File::Path;
use FileHandle;

$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

$key     = "my personal key";
$in_file = "CBCeasy.pm";
$out_file = "";

$test_num = 2;

$FILE_STR = read_file($in_file);
print(( $FILE_STR ? "" : "not " )."ok ".($test_num++)."\n");
$FILE_STR or exit;

$FILE_HASH = MD5->hash($FILE_STR);

mkpath(["tests"], 0) or die "Can't create dir \"tests\"\n"  unless -d "tests";

for $cipher(@ciphers) {
   for $i(1..$all_tests) {
      eval qq~print(( Test${i}() ? "" : "not " )."ok ".(\$test_num++)."\n")~;
   }
}


sub Test1 {
  my $out = "tests/$cipher.o1";
  eval "${cipher}::encipher(\$key, \$in_file, \$out)";
  $@ and undef($@), return;
  -f $out && -s _ or return;
  1;
}

sub Test2 {
  my $in  = "tests/$cipher.o1";
  my $out = "tests/$cipher.o2";
  -f $in or return;
  eval "${cipher}::decipher(\$key, \$in, \$out)";
  $@ and undef($@), return;
  -f $out && -s _ or return;

  $FILE_HASH eq hash_file($out);
}

sub Test3 {
  my $in  = "tests/$cipher.o1";
  my $out = "tests/$cipher.o3";
  local *OUT;

  -f $in or return;

  open (OUT, ">$out") or return;
  eval "${cipher}::decipher(\$key, \$in, \*OUT)";
  close OUT;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  $FILE_HASH eq hash_file($out);
}

sub Test4 {
  my $in  = "tests/$cipher.o1";
  my $out = "tests/$cipher.o4";
  local *OUT;

  -f $in or return;

  open (OUT, ">$out") or return;
  eval "${cipher}::decipher(\$key, \$in, \\*OUT)";
  close OUT;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  $FILE_HASH eq hash_file($out);
}

sub Test5 {
  my $in  = "tests/$cipher.o1";
  my $out = "tests/$cipher.o5";
  local *IN;

  -f $in or return;

  open (IN, $in) or return;
  eval "${cipher}::decipher(\$key, \*IN, \$out)";
  close IN;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  $FILE_HASH eq hash_file($out);
}

sub Test6 {
  my $in  = "tests/$cipher.o1";
  my $out = "tests/$cipher.o6";
  local *IN;

  -f $in or return;

  open (IN, $in) or return;
  eval "${cipher}::decipher(\$key, \\*IN, \$out)";
  close IN;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  $FILE_HASH eq hash_file($out);
}

sub Test7 {
  my $in  = "tests/$cipher.o1";
  my $out = "tests/$cipher.o7";
  local (*IN, *OUT);

  -f $in or return;

  open (IN, $in) or return;
  open (OUT, ">$out") or return;
  eval "${cipher}::decipher(\$key, \*IN, \*OUT)";
  close IN; close OUT;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  $FILE_HASH eq hash_file($out);
}

sub Test8 {
  my $in  = "tests/$cipher.o1";
  my $out = "tests/$cipher.o8";
  local (*IN, *OUT);

  -f $in or return;

  open (IN, $in) or return;
  open (OUT, ">$out") or return;
  eval "${cipher}::decipher(\$key, \\*IN, \\*OUT)";
  close IN; close OUT;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  $FILE_HASH eq hash_file($out);
}

sub Test9 {
  my $in  = "tests/$cipher.o1";

  -f $in or return;

  my $str = eval "${cipher}::decipher(\$key, \$in)";

  $@ and undef($@), return;
  $str =~ s/\r\n/\n/g;
  $FILE_HASH eq MD5->hash($str);
}

sub Test10 {
  my $in  = "tests/$cipher.o1";
  local *IN;

  -f $in or return;

  open (IN, $in) or return;
  my $str = eval "${cipher}::decipher(\$key, \\*IN)";
  close IN;

  $@ and undef($@), return;
  $str =~ s/\r\n/\n/g;
  $FILE_HASH eq MD5->hash($str);
}

sub Test11 {
  check_plainfile("tests/$cipher.o1");
}

sub Test12 {
  my $out = "tests/$cipher.o12";
  local *OUT;

  open(OUT, ">$out") or return;
  eval "${cipher}::encipher(\$key, \$in_file, \\*OUT)";
  close OUT;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  check_plainfile($out);
}

sub Test13 {
  my $out = "tests/$cipher.o13";
  local *OUT;

  open(OUT, ">$out") or return;
  eval "${cipher}::encipher(\$key, \$in_file, \*OUT)";
  close OUT;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  check_plainfile($out);
}

sub Test14 {
  my $out = "tests/$cipher.o14";
  local (*IN, *OUT);

  open(IN, $in_file) or return;
  my $in_str = join "", <IN>;
  close IN;
  open(OUT, ">$out") or return;
  eval "${cipher}::encipher(\$key, \$in_str, \*OUT)";
  close OUT;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  check_plainfile($out);
}

sub Test15 {
  my $out = "tests/$cipher.o15";
  local (*IN, *OUT);

  open(IN, $in_file) or return;
  open(OUT, ">$out") or return;
  eval "${cipher}::encipher(\$key, \*IN, \*OUT)";
  close OUT; close IN;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  check_plainfile($out);
}

sub Test16 {
  my $out = "tests/$cipher.o16";
  local (*IN, *OUT);

  open(IN, $in_file) or return;
  open(OUT, ">$out") or return;
  eval "${cipher}::encipher(\$key, \\*IN, \\*OUT)";
  close OUT; close IN;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  check_plainfile($out);
}

sub Test17 {
  my $out = "tests/$cipher.o17";
  local *IN;

  open(IN, $in_file) or return;
  my $str = eval "${cipher}::encipher(\$key, \*IN)";
  close IN;

  $@ and undef($@), return;

  write_file($out, $str) or return;
  -f $out && -s _ or return;

  check_plainfile($out);
}

sub Test18 {
  my $out = "tests/$cipher.o18";
  local *IN;

  open(IN, $in_file) or return;
  my $str = eval "${cipher}::encipher(\$key, \\*IN)";
  close IN;

  $@ and undef($@), return;

  write_file($out, $str) or return;
  -f $out && -s _ or return;

  check_plainfile($out);
}

sub Test19 {
  my $out = "tests/$cipher.o19";

  my $str = eval "${cipher}::encipher(\$key, \$in_file)";

  $@ and undef($@), return;

  write_file($out, $str) or return;
  -f $out && -s _ or return;

  check_plainfile($out);
}

#==== OO ======
sub Test20 {
  my $in  = "tests/$cipher.o1";
  my $out = "tests/$cipher.o20";

  -f $in or return;
  my $fh  = FileHandle->new(">$out") or return;

  eval "${cipher}::decipher(\$key, \$in, \$fh)";
  $fh->close;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  $FILE_HASH eq hash_file($out);
}

sub Test21 {
  my $in  = "tests/$cipher.o1";
  my $out = "tests/$cipher.o21";

  -f $in or return;
  my $fh  = FileHandle->new($in) or return;

  eval "${cipher}::decipher(\$key, \$fh, \$out)";
  $fh->close;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  $FILE_HASH eq hash_file($out);
}

sub Test22 {
  my $in  = "tests/$cipher.o1";
  my $out = "tests/$cipher.o22";

  -f $in or return;
  my $fhi = FileHandle->new($in) or return;
  my $fho = FileHandle->new(">$out") or return;

  eval "${cipher}::decipher(\$key, \$fhi, \$fho)";
  $fhi->close; $fho->close;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  $FILE_HASH eq hash_file($out);
}

sub Test23 {
  my $in  = "tests/$cipher.o1";

  -f $in or return;

  my $fh = FileHandle->new($in) or return;
  my $str = eval "${cipher}::decipher(\$key, \$fh)";
  $fh->close;

  $@ and undef($@), return;
  $str =~ s/\r\n/\n/g;
  $FILE_HASH eq MD5->hash($str);
}

sub Test24 {
  my $out = "tests/$cipher.o24";

  my $fh = FileHandle->new(">$out") or return;
  eval "${cipher}::encipher(\$key, \$in_file, \$fh)";
  $fh->close;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  check_plainfile($out);
}

sub Test25 {
  my $out = "tests/$cipher.o25";
  local (*IN);

  open(IN, $in_file) or return;
  my $in_str = join "", <IN>;
  close IN;
  my $fh = FileHandle->new(">$out") or return;
  eval "${cipher}::encipher(\$key, \$in_str, \$fh)";
  $fh->close;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  check_plainfile($out);
}

sub Test26 {
  my $out = "tests/$cipher.o26";

  my $fhi = FileHandle->new($in_file) or return;
  my $fho = FileHandle->new(">$out") or return;
  eval "${cipher}::encipher(\$key, \$fhi, \$fho)";
  $fhi->close; $fho->close;

  $@ and undef($@), return;
  -f $out && -s _ or return;

  check_plainfile($out);
}

sub Test27 {
  my $out = "tests/$cipher.o27";

  my $fh = FileHandle->new($in_file) or return;
  my $str = eval "${cipher}::encipher(\$key, \$fh)";
  $fh->close;

  $@ and undef($@), return;

  write_file($out, $str) or return;
  -f $out && -s _ or return;

  check_plainfile($out);
}

sub read_file {
  my $in = shift;
  local *IN;

  open(IN, $in) || return;
  my $in_string = join "", <IN>;
  close IN;
  $in_string;
}

sub hash_file {
  my $str  = read_file(shift) or return "";
  MD5->hash($str);
}

sub check_plainfile {
  my $in  = shift;
  local *IN;

  -f $in or return;

  open (IN, $in) or return;
  my $str = eval "${cipher}::decipher(\$key, \*IN)";
  close IN;

  $@ and undef($@), return;
  $str =~ s/\r\n/\n/g;
  $FILE_HASH eq MD5->hash($str);
}

sub write_file {
  my ($out, $str) = @_;
  local *OUT;
  open(OUT, ">$out") or return;
  binmode OUT;
  print OUT $str;
  close OUT;
  1;
}

