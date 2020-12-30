#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use strict;
use warnings;

my %h;
my @out;
my $section;
my %sections;
my %sectiondesc;
my @orderedsections;

sub dumpdoc {
    if (!%h) {
        ;    # nothing to do
    }
    elsif (defined $h{param} && defined $h{default} && defined $h{desc} && defined $h{type}) {
        die "attempting to dump data but section=$section" if !$section;
        push @{$sections{$section}}, $h{param};
        push @out, ".. _$h{param}:\n\n", "$h{param}\n", "*" x length($h{param}), "\n\n", ":Type: ``$h{type}``\n\n", ":Default: ``$h{default}``\n\n";
        push @out, ":Example: ``$h{example}``\n\n" if $h{example};
        push @out, "$h{desc}\n\n";
    }
    else {
        die "something is missing: " . ($h{param} ? "" : "param ") . ($h{default} ? "" : "default ") . ($h{desc} ? "" : "desc ") . ($h{type} ? "" : "type") . "\n";
    }
    %h = ();
    return;
}

my $state = '';
while (<STDIN>) {
    print STDERR $_;
    next if /^\s*$/;
    if (m{^# ([a-zA-Z0-9_]+) \((.+)\)}) {
        $h{param} = $1;
        $h{type}  = $2;
        $state    = 'name';
    }
    elsif (m{^#\s+DESC:\s+(.+)$}) {
        $h{desc} = $1;
        $state = 'desc';
    }
    elsif (m{^#\s+EXAMPLE:\s+(.+)$}) {
        $h{example} = $1;
        $state = 'example';
    }
    elsif (m{^#\s+DEFAULT:\s+(.+)$}) {
        $h{default} = $1;
        $state = 'default';
    }
    elsif (m{^#\s{0,11}(.*)$} && exists $h{desc} && $state eq 'desc') {
        $h{desc} .= "\n$1";
    }
    elsif (m{^"([^"]+)"} && $h{param} eq $1) {
        $state = '';
        dumpdoc();
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
        die("\\--- lost here, state='$state'");
    }
}
dumpdoc();

print <<'EOF';
======================
bastion.conf reference
======================

.. note::

   The Bastion has a lot of configuration options so that you can tailor it to your needs.
   However, if you're just starting and would like to get started quickly, just configure
   the ``Main Options``. All the other options have sane defaults that can still be customized
   at a later time.

Option List
===========

EOF

foreach my $section (@orderedsections) {
    die "no description for section $section" if !$sectiondesc{$section};
    print "\n", $section, "\n", "-" x length($section), "\n\n", $sectiondesc{$section}, "\n\n";
    print "- :ref:`$_`\n" for @{$sections{$section}};
}
print <<'EOF', join('', @out);

Option Reference
================

EOF
