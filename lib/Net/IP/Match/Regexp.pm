package Net::IP::Match::Regexp;

require 5.005_62;
use strict;
use warnings;

use base 'Exporter';
our @EXPORT = qw();
our @EXPORT_OK = qw( create_iprange_regexp match_ip );
our $VERSION = '0.90';

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

WARNING: I have not yet tested Perl versions older than 5.8.1.  This
WILL fail on some versions, because I use the C<(?{})> regexp feature,
but I haven't researched the limit yet.

This module allows you to check an IP address against one or more IP
ranges.  There are several other CPAN modules that perform a similar
function.  My intuition says that the Regexp approach is the best, but
I have not yet performed a speed comparison.

=head2 Net::IP::Match

Optimized for speed by taking a "source filter" approach.  That is, it
modifies your source code at run time, kind of like a C preprocessor.
A huge limitation is that the IP ranges must be hard-coded into your
program.

=head2 Net::IP::Match::XS

(Also released as Net::IP::CMatch)

Optimized for speed by doing the match in C instead of in Perl.  This
loses efficiency because the IP ranges must be re-parsed every
invokation.

=head2 Net::IP::Match::Resolver

Uses Net::IP::Match::XS to implement a range-to-name map.

=head2 Net::IP::Match::Regexp (this module)

Optimized for speed by doing the match against a pre-computed regexp,
which implicitly checks the broadest IP ranges first.  An advantage is
that the regexp can be comuted and stored in advance (in source code,
in a database table, etc) and reused.  The match can optionally report
a value instead of just a boolean, which makes module useful for
mapping IP ranges to names or codes or anything else.

=head1 PERFORMANCE

I ran a test on my Mac G5 to compare this module to
Net::IP::Match::XS.  The test was intended to be a realistic net
filter case: 100,000 random IPs tested against 300 semi-random IP
ranges.  Times are in seconds.

    Module                 | Setup time | Run time
    -----------------------+------------+-------
    Net::IP::Match::Regexp |    0.057   | 1.663
    Net::IP::Match::XS     |    0.0     | 4.238


=head1 FUNCTIONS

=over

=cut


=item create_iprange_regexp ...

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

Note that these two styles can be mixed (a rarely used feature).
These two examples are equivalent:

    create_iprange_regexp("127.0.0.1/32",
                          {"209.249.163.0/25" => "clotho.com"},
                          "10.0.0.0/8",
                          {"192.168.0.0/16" => "LAN"});

    create_iprange_regexp({"127.0.0.1/32" => 1,
                           "209.249.163.0/25" => "clotho.com",
                           "10.0.0.0/8" => 1,
                           "192.168.0.0/16" => "LAN"});

Special note: the value string will be wrapped in single-quotes in the
regexp.  Therefore, you must double-escape any single quotes in that value.
For example:

    create_iprange_regexp({"208.201.239.36/31" => "O\\'Reilly publishing"});

Warning: This function does no checking for validity of IP ranges.  It
happily accepts C<1000.0.0.0/-38>.  Hopefully a future version will
validate the ranges, perhaps via Net::CIDR or Net::IP.

=cut

sub create_iprange_regexp
{
   my %map = map {ref $_ ? %$_ : ($_ => 1)} @_;
   
   my %tree;
   for my $range (keys %map)
   {
      my ($ip,$mask) = split /\//, $range;
      
      my $tree = \%tree;
      my @bits = split //, unpack("B32", pack("C4", split(/\./, $ip)));
      for my $val (@bits[0..$mask-1])
      {
         last if ($tree->{code});
         $tree->{$val} ||= {};
         $tree = $tree->{$val};
      }
      $tree->{code} ||= $map{$range};
      # prune redundant branches
      # this is only important if the range data is poor
      delete $tree->{0};
      delete $tree->{1};
   }

   my $re = "^".tree2re(\%tree);
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

Warning: This function does no checking for validity of the IP address.

=cut

sub match_ip
{
   my ($ip,$re) = @_;

   local $^R;
   use re 'eval';
   unpack("B32", pack("C4", split(/\./, $ip))) =~ /$re/;
   return $^R;
}

# Helper function.  This recurses to build the regular expression
# string from a tree of IP ranges constructed by
# create_iprange_regexp().

sub tree2re
{
   my $tree = shift;
   
   if ($tree->{code})
   {
      return "(?{'$$tree{code}'})";
   }
   elsif ($tree->{0} && $tree->{1})
   {
      return "(?:0".tree2re($tree->{0})."|1".tree2re($tree->{1}).")";
   }
   elsif ($tree->{0})
   {
      return "0".tree2re($tree->{0});
   }
   elsif ($tree->{1})
   {
      return "1".tree2re($tree->{1});
   }
   else
   {
      die "Error\n";
   }
}

1;

__END__

=head1 SEE ALSO

Net::IP::Match

Net::IP::Match::XS

Net::IP::CMatch

Net::IP::Resolver

=head1 AUTHOR

Clotho Advanced Media, Inc. I<cpan@clotho.com>

Primary developer: Chris Dolan
