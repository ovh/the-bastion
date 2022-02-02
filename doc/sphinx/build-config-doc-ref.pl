#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use strict;
use warnings;

use FindBin;

my %h;
my @header;
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
        push @out, (".. _$h{param}:\n", "\n") if $ENV{'GLOBAL_REFS'};
        push @out, "$h{param}\n", "*" x length($h{param}) . "\n", "\n", ":Type: ``$h{type}``\n", "\n", ":Default: ``$h{default}``\n", "\n";
        push @out, (":Example: ``$h{example}``\n", "\n") if $h{example};
        push @out, "$h{desc}\n", "\n";
    }
    else {
        die "something is missing: " . ($h{param} ? "" : "param ") . ($h{default} ? "" : "default ") . ($h{desc} ? "" : "desc ") . ($h{type} ? "" : "type") . "\n";
    }
    %h = ();
    return;
}

my $state = 'start';
while (<STDIN>) {
    printf STDERR "%9s line=%s", $state, $_ if $ENV{'DEBUG'};
    next if /^\s*$/;
    if ($state eq 'start') {
        if (m{^###}) {
            $state = '' if @header;
        }
        elsif (m{^#@(.*)$}) {
            push @header, $1;
        }
    }
    elsif (m{^# ([a-zA-Z0-9_]+) \((.+)\)}) {
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
    elsif ((m{^"([^"]+)"} && $h{param} eq $1) || (m{^([A-Za-z0-9_]+)=} && $h{param} eq $1)) {
        $state = 'param';
    }
    elsif (m{^#$} && $state eq 'param') {
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
    my $contents = do { local $/; <$fh>; };
    close($fh);
    print $contents;
}
elsif (@header) {
    print "=" x length($document) . "\n";
    print "$document\n";
    print "=" x length($document) . "\n\n";
    print join("\n", @header);
    print "\n\nOption List\n===========\n";
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
