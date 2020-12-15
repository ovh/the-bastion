package OVH::Bastion;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:

use common::sense;

my $_mocking_enabled = 0;
my $_mock_data;

sub enable_mocking {
    $_mocking_enabled = 1;
    return;
}

sub is_mocking {
    return $_mocking_enabled;
}

sub set_mock_data {
    die "tried to set_mock_data without enabling mocking first" unless is_mocking();
    $_mock_data = shift;
    return;
}

sub mock_get_account_entry {
    my %params  = @_;
    my $account = $params{'account'};

    die "tried to mock without enabling mocking first" unless is_mocking();

    my $h = $_mock_data->{'accounts'}{$account};
    return () if !$h;
    return ($account, "x", $h->{'uid'}, $h->{'gid'}, $h->{'gecos'}, "/home/$account", $OVH::Bastion::BASEPATH . "/bin/shell/osh.pl");
}

sub mock_get_account_accesses {
    my %params  = @_;
    my $account = $params{'account'};

    die "tried to mock without enabling mocking first" unless is_mocking();

    return split /:/, $_mock_data->{'accounts'}{$account}{'accesses'};
}

sub mock_get_account_personal_accesses {
    my %params  = @_;
    my $account = $params{'account'};

    die "tried to mock without enabling mocking first" unless is_mocking();

    return $_mock_data->{'accounts'}{$account}{'personal_accesses'};
}

sub mock_get_account_legacy_accesses {
    my %params  = @_;
    my $account = $params{'account'};

    die "tried to mock without enabling mocking first" unless is_mocking();

    return $_mock_data->{'accounts'}{$account}{'legacy_accesses'};
}

sub mock_get_group_accesses {
    my %params = @_;
    my $group  = $params{'group'};

    die "tried to mock without enabling mocking first" unless is_mocking();

    return $_mock_data->{'groups'}{$group}{'accesses'};
}

sub mock_get_account_guest_accesses {
    my %params  = @_;
    my $group   = $params{'group'};
    my $account = $params{'account'};

    die "tried to mock without enabling mocking first" unless is_mocking();

    return $_mock_data->{'account'}{$account}{'guest_accesses'}{$group};
}

1;
