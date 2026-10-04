#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Test::More;

use File::Basename;
use lib dirname(__FILE__) . '/../../../lib/perl';
use OVH::Bastion;

# The HTTP proxy used to send `Date: ` . gmtime() . " GMT".
# scalar gmtime() is ctime, which is not an IMF-fixdate (RFC 9110).
# Example of the old value for the epoch: "Thu Jan  1 00:00:00 1970 GMT".

my $epoch = 0;
my $got   = OVH::Bastion::http_imf_fixdate(epoch => $epoch);
is($got, "Thu, 01 Jan 1970 00:00:00 GMT", "epoch 0 is IMF-fixdate, not ctime");

unlike($got, qr/\w{3} \w{3} +\d/, "not the ctime layout produced by scalar gmtime()");

# A later timestamp must still match the fixed English IMF-fixdate shape.
my $stamp = 1759570080;
my $day   = OVH::Bastion::http_imf_fixdate(epoch => $stamp);
like($day, qr/^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$/, "matches IMF-fixdate");

# Locale must not leak into the weekday/month (LC_TIME=fr_FR.UTF-8 would break strftime %a/%b).
ok($day =~ / GMT$/, "explicit GMT, not a local timezone name");

done_testing();
