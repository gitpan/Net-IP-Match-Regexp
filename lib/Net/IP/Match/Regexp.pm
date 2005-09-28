package Net::IP::Match::Regexp;

require 5.006;
use strict;
use warnings;

use base 'Exporter';
our @EXPORT = qw();
our @EXPORT_OK = qw( create_iprange_regexp match_ip );
our $VERSION = '0.93';

=head1 NAME

Net::IP::Match::Regexp - Efficiently match IPv4 addresses against IPv4 ranges via regexp

=head1 LICENSE

Copyright 2005 Clotho Advanced Media, Inc., <cpan@clotho.com>

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=head1 SYNOPSIS

    use Net::IP::Match::Regexp qw( create_iprange_regexp match_ip );
    
    my $regexp = create_iprange_regexp(
       qw( 10.0.0.0/8 87.134.66.128 87.134.87.0/24 145.97.0.0/16 )
    );
    if (match_ip("209.249.163.62", $regexp)) {
       ...
    }

=head1 DESCRIPTION

This module allows you to check an IP address against one or more IP
ranges.  It employs Perl's highly optimized regular expression engine
to do the hard work, so it is very fast.  It is optimized for speed by
doing the match against a pre-computed regexp, which implicitly checks
the broadest IP ranges first.  An advantage is that the regexp can be
comuted and stored in advance (in source code, in a database table,
etc) and reused, saving much time if the IP ranges don't change too
often.  The match can optionally report a value (e.g. a network name)
instead of just a boolean, which makes module useful for mapping IP
ranges to names or codes or anything else.

=head1 LIMITATIONS

This module does not yet support IPv6 addresses, although that feature
should not be hard to implement as long as the regexps start with a 4
vs. 6 flag.  Patches welcome.  :-)

This module only accepts IP ranges in C<a.b.c.d/x> (aka CIDR)
notation.  To work around that limitation, we recommend
Net::CIDR::Lite to conveniently convert collections of IP address
ranges into CIDR format.

This module makes no effort to validate the IP addresses or ranges
passed as arguments.  If you pass address ranges like
C<1000.0.0.0/300>, you will probably get weird regexps out.

=head1 FUNCTIONS

=over

=cut

=item create_iprange_regexp IPRANGE | MAP, ...

This function digests IP ranges into a regular expression that can
subsequently be used to efficiently test single IP addresses.  It
returns a regular expression string that can be passed to match_ip().

The simple way to use this is to pass a list of IP ranges as
C<aaa.bbb.ccc.ddd/n>.  When used this way, the return value of the
match_ip() function will be simply C<1> or C<undef>.

The more complex way is to pass a hash reference of IP range => return
value pairs.  When used this way, the return value of the match_ip()
function will be the specified return value or C<undef> for no match.

For example:

    my $re1 = create_iprange_regexp("209.249.163.0/25", "127.0.0.1/32");
    print match_ip("209.249.163.62", $re1); # prints "1"
    
    my $re2 = create_iprange_regexp({"209.249.163.0/25" => "clotho.com",
                                     "127.0.0.1/32" => "localhost"});
    print match_ip("209.249.163.62", $re2); # prints "clotho.com"

Be aware that the value string will be wrapped in single quotes in the
regexp.  Therefore, you must double-escape any single quotes in that
value.  For example:

    create_iprange_regexp({"208.201.239.36/31" => "O\\'Reilly publishing"});

Note that the scalar and hash styles can be mixed (a rarely used
feature).  These two examples are equivalent:

    create_iprange_regexp("127.0.0.1/32",
                          {"209.249.163.0/25" => "clotho.com"},
                          "10.0.0.0/8",
                          {"192.168.0.0/16" => "LAN"});

    create_iprange_regexp({"127.0.0.1/32" => 1,
                           "209.249.163.0/25" => "clotho.com",
                           "10.0.0.0/8" => 1,
                           "192.168.0.0/16" => "LAN"});

If any of the IP ranges are overlapping, the broadest one is used.  If
they are equivalent, then the first one passed is used.  If you have
some data that might be ambiguous, you pass an arrayref instead of a
hashref, but it's better to clean up your data instead!  For example:

    my $re = create_iprange_regexp(["1.1.1.0/31" => "zero", "1.1.1.1/31" => "one"]);
    print match_ip("1.1.1.1", $re));   # prints "zero", since both match

WARNING: This function does no checking for validity of IP ranges.  It
happily accepts C<1000.0.0.0/-38> and makes a garbage regexp.
Hopefully a future version will validate the ranges, perhaps via
Net::CIDR or Net::IP.

=cut

sub create_iprange_regexp
{
   # If an argument is a hash or array ref, flatten it
   # If an argument is a scalar, make it a key and give it a value of 1
   my @map = map {ref $_ ? (ref $_ eq "ARRAY" ? @$_ : %$_) : ($_ => 1)} @_;
   
   # The tree is a temporary construct.  It has three possible
   # properties: 0, 1, and code.  The code is the return value for a
   # match.
   my %tree;

   for (my $i=0; $i<@map; $i+=2)
   {
      my $range = $map[$i];
      my $match = $map[$i+1];

      my ($ip,$mask) = split /\//, $range;
      
      my $tree = \%tree;
      my @bits = split //, unpack("B32", pack("C4", split(/\./, $ip)));
      for my $val (@bits[0..$mask-1])
      {
         # If this case is hit, it means that our IP range is a subset
         # of some other range.
         last if ($tree->{code});

         $tree->{$val} ||= {};
         $tree = $tree->{$val};
      }
      # If the code is already set, it's a non-fatal error (redundant data)
      $tree->{code} ||= $match;

      # prune redundant branches
      # this is only important if the range data is redundant
      delete $tree->{0};
      delete $tree->{1};
   }

   # Recurse into the tree making it into a regexp
   my $re = "^4"._tree2re(\%tree);

   # Performance optimization:
   use re 'eval';
   $re = qr/$re/;

   return $re;
}

=item match_ip IP_ADDR, REGEXP

Given a single IP address as a string of the form C<aaa.bbb.ccc.ddd>
and a regular expression string (typically the output of
create_iprange_regexp()), this function returns a pre-specified value
(typically C<1>) if the IP is in one of the ranges, or C<undef> if no
ranges match.

See create_ipranges_regexp() for more details about the return value
of this function.

WARNING: This function does no checking for validity of the IP address.

=cut

sub match_ip
{
   my ($ip,$re) = @_;

   return undef unless ($ip && $re);

   local $^R;
   use re 'eval';
   ("4".unpack("B32", pack("C4", split(/\./, $ip)))) =~ $re;
   return $^R;
}

# Helper function.  This recurses to build the regular expression
# string from a tree of IP ranges constructed by
# create_iprange_regexp().

sub _tree2re
{
   my $tree = shift;
   
   if (defined $tree->{code})
   {
      return "(?{'$$tree{code}'})";
   }
   elsif ($tree->{0} && $tree->{1})
   {
      return "(?>0"._tree2re($tree->{0})."|1"._tree2re($tree->{1}).")";
   }
   elsif ($tree->{0})
   {
      return "0"._tree2re($tree->{0});
   }
   elsif ($tree->{1})
   {
      return "1"._tree2re($tree->{1});
   }
   else
   {
      die "Internal error";
   }
}

1;

__END__

=back

=head1 SEE ALSO

There are several other CPAN modules that perform a similar function.
This one is comparable to or faster than the other ones that we've
found and tried.  Here is a synopsis of those others:

=head2 L<Net::IP::Match>

Optimized for speed by taking a "source filter" approach.  That is, it
modifies your source code at run time, kind of like a C preprocessor.
A huge limitation is that the IP ranges must be hard-coded into your
program.

=head2 L<Net::IP::Match::XS>

(Also released as Net::IP::CMatch)

Optimized for speed by doing the match in C instead of in Perl.  This
module loses efficiency, however, because the IP ranges must be
re-parsed every invocation.

=head2 L<Net::IP::Resolver>

Uses Net::IP::Match::XS to implement a range-to-name map.

=head1 PERFORMANCE

We ran a series of test on a Mac G5 with Perl 5.8.6 to compare this
module to Net::IP::Match::XS.  The tests are intended to be a
realistic net filter case: 100,000 random IPs tested against a number
of semi-random IP ranges.  Times are in seconds.

    Networks: 1, IPs: 100000
    Test name              | Setup time | Run time | Total time 
    -----------------------+------------+----------+------------
    Net::IP::Match::XS     |    0.000   |  0.415   |    0.415   
    Net::IP::Match::Regexp |    0.001   |  1.141   |    1.141   
    
    Networks: 10, IPs: 100000
    Test name              | Setup time | Run time | Total time 
    -----------------------+------------+----------+------------
    Net::IP::Match::XS     |    0.000   |  0.613   |    0.613   
    Net::IP::Match::Regexp |    0.003   |  1.312   |    1.316   
    
    Networks: 100, IPs: 100000
    Test name              | Setup time | Run time | Total time 
    -----------------------+------------+----------+------------
    Net::IP::Match::XS     |    0.000   |  2.621   |    2.622   
    Net::IP::Match::Regexp |    0.024   |  1.381   |    1.405   
    
    Networks: 1000, IPs: 100000
    Test name              | Setup time | Run time | Total time 
    -----------------------+------------+----------+------------
    Net::IP::Match::XS     |    0.003   | 20.910   |   20.912   
    Net::IP::Match::Regexp |    0.203   |  1.514   |    1.717   

This test indicates that ::Regexp is faster than ::XS when you have
more than about 50 IP ranges to test.  The relative run time does not
vary significantly with the number of singe IP to match, but with a
small number of IPs to match, the setup time begins to dominate, so
::Regexp loses in that scenario.

To reproduce the above benchmarks, run the following command in the
distribution directory:

   perl benchmark/speedtest.pl -s -n 1,10,100,1000 -i 100000

=head1 IMPLEMENTATION

The speed of this module comes from the short-circuit nature of
regular expressions.  The setup function turns all of the IP ranges
into binary strings, and mixes them into a regexp with C<|> choices
between ones and zeros.  This regexp can then be passed to the match
function.  When an unambiguous match is found, the regexp sets a
variable (via the regexp $^R feature) and terminates.  That variable
becomes the return value for the match, typically a true value.

Here's an example of the regexp for a single range, that of the
Clotho.com subnet:

    print create_iprange_regexp("209.249.163.0/25")'
    # ^41101000111111001101000110(?{'1'})

If we add another range, say a NAT LAN, we get:

    print create_iprange_regexp("209.249.163.0/25", "192.168.0.0/16")'
    # ^4110(?>0000010101000(?{'1'})|1000111111001101000110(?{'1'}))

Note that for a 192.168.x.x address, the regexp checks at most the
first 16 bits (1100000010101000) whereas for a 209.249.163.x address,
it goes out to 25 bits (1101000111111001101000110).  The cool part is
that for an IP address that starts in the lower half (say 127.0.0.1)
only needs to check the first bit (0) to see that the regexp won't
match.

If mapped return values are specified for the ranges, they get embedded
into the regexp like so:

    print create_iprange_regexp({"209.249.163.0/25" => "clotho.com",
                                 "192.168.0.0/16" => "localhost"})'
    # ^4110(?>0000010101000(?{'localhost'})|1000111111001101000110(?{'clotho.com'}))

This could be implemented in C to be even faster.  In C, it would
probably be better to use a binary tree instead of a regexp.  However,
a goal of this module is to create a serializable representation of
the range data, and the regexp is perfect for that.  So, we'll
probably never do a C version.

=head1 COMPATIBILITY

Because this module relies on the C<(?{ code })> feature of regexps,
it won't work on old Perl versions.  I've successfully tested this
module on Perl 5.6.0, 5.8.1 and 5.8.6.  In theory, the code regexp
feature should work in 5.005, but I've used "our" and the like, so it
won't work there.  I don't have a 5.005 to test anyway...

=head1 TESTS

This module has 100% code coverage in its regression tests, as
reported by C<perl Build testcover>.

=head1 AUTHOR

Clotho Advanced Media, Inc. I<cpan@clotho.com>

Primary developer: Chris Dolan
