#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use strict;
use warnings;

use FindBin;

my %h;
my @out;
my $section;
my %sections;
my %sectiondesc;
my @orderedsections;

my $document = $ARGV[0] || 'unknown';

sub dumpdoc {
    if (!%h) {
        ;    # nothing to do
    }
    elsif (defined $h{param} && defined $h{default} && defined $h{desc} && defined $h{type}) {
        die "attempting to dump data but section=$section" if !$section;
        push @{$sections{$section}}, $h{param};
        push @out, ".. _$h{param}:\n", "\n"
          if $ENV{'GLOBAL_REFS'};
        push @out, "$h{param}\n", "*" x length($h{param}) . "\n", "\n", ":Type: ``$h{type}``\n", "\n", ":Default: ``$h{default}``\n", "\n";
        push @out, ":Example: ``$h{example}``\n", "\n"
          if $h{example};
        push @out, "$h{desc}\n", "\n";
    }
    else {
        die "something is missing: " . ($h{param} ? "" : "param ") . ($h{default} ? "" : "default ") . ($h{desc} ? "" : "desc ") . ($h{type} ? "" : "type") . "\n";
    }
    %h = ();
    return;
}

my $state = '';
while (<STDIN>) {
    $ENV{'DEBUG'} && print;
    next if /^\s*$/;
    if (m{^# ([a-zA-Z0-9_]+) \((.+)\)}) {
        $h{param} = $1;
        $h{type}  = $2;
        $ENV{'DEBUG'} && print "--- state=name\n";
        $state = 'name';
    }
    elsif (m{^#\s+DESC:\s+(.+)$}) {
        $h{desc} = $1;
        $ENV{'DEBUG'} && print "--- state=desc\n";
        $state = 'desc';
    }
    elsif (m{^#\s+EXAMPLE:\s+(.+)$}) {
        $h{example} = $1;
        $ENV{'DEBUG'} && print "--- state=example\n";
        $state = 'example';
    }
    elsif (m{^#\s+DEFAULT:\s+(.+)$}) {
        $h{default} = $1;
        $ENV{'DEBUG'} && print "--- state=default\n";
        $state = 'default';
    }
    elsif (m{^#\s{0,11}(.*)$} && exists $h{desc} && $state eq 'desc') {
        $h{desc} .= "\n$1";
    }
    elsif ((m{^"([^"]+)"} && $h{param} eq $1) || (m{^([A-Za-z0-9_]+)=} && $h{param} eq $1)) {
        $ENV{'DEBUG'} && print "--- state=param\n";
        $state = 'param';
    }
    elsif (m{^#$} && $state eq 'param') {
        $ENV{'DEBUG'} && print "--- state=(empty)\n";
        $state = '';
        dumpdoc();
    }
    elsif ($state eq 'param') {
    }
    elsif (m{^# > (.+)$}) {
        if (%h or $state) { die "new section '$1' but we have pending data"; }
        $section = $1;
        $state   = 'section';
        push @orderedsections, $section;
        push @out, $section, "\n", "-" x (length($section)), "\n\n";
    }
    elsif (m{^# >> (.+)$} and $state eq 'section' and $section) {
        $sectiondesc{$section} = $1;
    }
    elsif (!/^##|^[{}]|^#\s*$/) {
        die("$_^^^ lost here, state='$state'");
    }
}
dumpdoc();

if (open(my $fh, "<", "$FindBin::Bin/../sphinx-reference-headers/$document.header")) {
    local $/;
    my $contents = <$fh>;
    close($fh);
    print $contents;
}
else {
    print STDERR "No header found in '$FindBin::Bin/../sphinx-reference-headers/$document.header'\n";
}

foreach my $section (@orderedsections) {
    die "no description for section $section" if !$sectiondesc{$section};
    print "\n", "$section options\n", "-" x length("$section options"), "\n\n", $sectiondesc{$section}, "\n\n";
    print "- `$_`_\n" for @{$sections{$section}};
}
print <<'EOF', join('', @out);

Option Reference
================

EOF
