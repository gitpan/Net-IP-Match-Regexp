#!/usr/bin/perl -w

BEGIN
{
   use Test::More tests => 15+(33*18);
   use_ok(Net::IP::Match::Regexp);
}

use strict;
use warnings;
use Net::IP::Match::Regexp qw( create_iprange_regexp match_ip );


my $re;



#### These two tests are translated from Net-IP-Match-XS.t ####
$re = create_iprange_regexp(qw(10.0.0.0/8 99.99.99.0/1));
ok(!match_ip("207.175.219.202", $re), "match_ip");
$re = create_iprange_regexp(qw(10.0.0.0/8 192.168.0.0/16 207.175.219.200/29));
ok(match_ip("207.175.219.202", $re), "match_ip");
###############################################################



#### A random assortment of tests ####
$re = create_iprange_regexp("127.0.0.1/32");
ok(match_ip("127.0.0.1", $re), "match_ip");
ok(!match_ip("127.0.0.2", $re), "match_ip");

$re = create_iprange_regexp("192.168.0.0/16");
ok(match_ip("192.168.0.1", $re), "match_ip");
ok(match_ip("192.168.255.255", $re), "match_ip");
ok(!match_ip("127.0.0.1", $re), "match_ip");

$re = create_iprange_regexp("209.249.163.0/25");
ok(match_ip("209.249.163.20", $re), "match_ip");
ok(!match_ip("209.249.163.128", $re), "match_ip");
ok(!match_ip("209.249.164.0", $re), "match_ip");

$re = create_iprange_regexp({
   "127.0.0.1/32" => "localhost",
   "192.168.0.0/16" => "localnet",
   "209.249.163.0/25" => "clotho.com",
});
is(match_ip("127.0.0.1", $re), "localhost", "match_ip");
is(match_ip("192.168.0.0", $re), "localnet", "match_ip");
is(match_ip("209.249.163.20", $re), "clotho.com", "match_ip");
is(match_ip("10.0.0.1", $re), undef, "match_ip");
######################################



#### A more methodical group of tests ####
for my $mask (0..32)
{
   # Notes for my masking math...
   # 127.0.0.0       = 0F.00.00.00
   # 128.0.0.0       = 80.00.00.00
   # 207.0.0.0       = CF.00.00.00
   # 224.0.0.0       = E0.00.00.00
   # 255.255.255.254 = FF.FF.FF.FE
   # 255.255.255.255 = FF.FF.FF.FF

   $re = create_iprange_regexp("0.0.0.0/$mask");
   is(match_ip("0.0.0.0",         $re), $mask > 32 ? undef : 1, "match_ip 0,0/$mask");
   is(match_ip("0.0.0.1",         $re), $mask > 31 ? undef : 1, "match_ip 1,0/$mask");
   is(match_ip("1.2.3.4",         $re), $mask >  7 ? undef : 1, "match_ip 1234,0/$mask");
   is(match_ip("127.0.0.1",       $re), $mask >  1 ? undef : 1, "match_ip 127,0/$mask");
   is(match_ip("128.0.0.0",       $re), $mask >  0 ? undef : 1, "match_ip 128,0/$mask");
   is(match_ip("207.0.0.0",       $re), $mask >  0 ? undef : 1, "match_ip 207,0/$mask");
   is(match_ip("224.0.0.0",       $re), $mask >  0 ? undef : 1, "match_ip 224,0/$mask");
   is(match_ip("255.255.255.254", $re), $mask >  0 ? undef : 1, "match_ip 254,0/$mask");
   is(match_ip("255.255.255.255", $re), $mask >  0 ? undef : 1, "match_ip 255,0/$mask");

   $re = create_iprange_regexp("255.255.255.255/$mask");
   is(match_ip("0.0.0.0",         $re), $mask >  0 ? undef : 1, "match_ip 0,255/$mask");
   is(match_ip("0.0.0.1",         $re), $mask >  0 ? undef : 1, "match_ip 1,255/$mask");
   is(match_ip("1.2.3.4",         $re), $mask >  0 ? undef : 1, "match_ip 1234,255/$mask");
   is(match_ip("127.0.0.1",       $re), $mask >  0 ? undef : 1, "match_ip 127,255/$mask");
   is(match_ip("128.0.0.0",       $re), $mask >  1 ? undef : 1, "match_ip 128,255/$mask");
   is(match_ip("207.0.0.0",       $re), $mask >  2 ? undef : 1, "match_ip 207,255/$mask");
   is(match_ip("224.0.0.0",       $re), $mask >  3 ? undef : 1, "match_ip 224,255/$mask");
   is(match_ip("255.255.255.254", $re), $mask > 31 ? undef : 1, "match_ip 254,255/$mask");
   is(match_ip("255.255.255.255", $re), $mask > 32 ? undef : 1, "match_ip 255,255/$mask");
}
##########################################
