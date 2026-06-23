#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Test::More;

use File::Basename;
use lib dirname(__FILE__) . '/../../../lib/perl';
use OVH::Bastion;
use OVH::Result;

# syslogFormatted() renders audit log fields as a single `key="value" ...` line that is sent to
# syslog and (verbatim) to the flat-file logs. User-controlled field values (e.g. the `params`
# field, which carries the raw osh command line) must be neutralized to avoid control-characters
# injection that would make the log difficult to read. Fields values are already checked by the
# callers, but it doesn't hurt to force the sanitization at the low level too.

OVH::Bastion::enable_mocking();
OVH::Bastion::set_mock_data({});
OVH::Bastion::load_configuration(
    mock_data => {
        bastionName  => "mock",
        enableSyslog => 0,        # keep the test from actually emitting to syslog
    }
);

# Render a single field value through syslogFormatted() and return just that field's
# rendered text (the function prepends fixed fields like uniqid/pid; ours is appended last).
sub rendered {
    my ($value) = @_;
    my $r = OVH::Bastion::syslogFormatted(type => 'test', fields => [['f', $value]]);
    return (undef, $r) if !$r;
    my ($field) = $r->value =~ / f="(.*)"$/;
    return ($field, $r);
}

# passthrough: ordinary text is unchanged
{
    my ($out) = rendered("plain value 123");
    is($out, "plain value 123", "ordinary text passes through untouched");
}

# every control character is escaped to a visible \xNN, never left raw
my %cases = (
    "newline"      => ["a\nb",      'a\x0ab'],
    "carriage ret" => ["a\rb",      'a\x0db'],
    "tab"          => ["a\tb",      'a\x09b'],
    "NUL"          => ["a\x00b",    'a\x00b'],
    "ESC sequence" => ["a\x1b[2Kb", 'a\x1b[2Kb'],
    "DEL"          => ["a\x7fb",    'a\x7fb'],
);
foreach my $name (sort keys %cases) {
    my ($in, $want) = @{$cases{$name}};
    my ($out) = rendered($in);
    is($out, $want, "$name is escaped to a visible \\xNN sequence");
}

# delimiter / escape chars are escaped so a field value cannot break out
{
    my ($out) = rendered('he said "hi"');
    is($out, 'he said \\"hi\\"', "double-quotes are escaped (no field-spoofing)");
}

# input is a single backslash between a and b; it must be doubled
{
    my ($out) = rendered('a\\b');
    is($out, 'a\\\\b', "backslashes are doubled");
}

# field-spoofing attempt: try to inject a fake allowed="1" field
{
    my ($out) = rendered('x" allowed="1');
    is($out, 'x\\" allowed=\\"1', "injected key=\"value\" is neutralized");
}

# the strongest invariant: NO raw control byte survives anywhere in the full line
{
    my (undef, $r) = rendered("info\x1b[2K\rFAKE CLEAN\tend\x00\nsecond line");
    ok($r, "syslogFormatted returned OK on a control-char-laden value");
    unlike($r->value, qr/[\x00-\x1f\x7f]/, "no raw C0/DEL control byte survives in the rendered line");
    unlike($r->value, qr/\n/,              "rendered line is single-line (no raw newline)");
}

# legitimate UTF-8 content must be preserved untouched
{
    my $utf8 = "café — naïve 日本語 🎉";
    my ($out) = rendered($utf8);
    is($out, $utf8, "legitimate UTF-8 (byte-string) content is preserved");
}

done_testing();
