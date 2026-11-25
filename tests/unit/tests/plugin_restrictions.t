#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Test::More;

use File::Basename;
use lib dirname(__FILE__) . '/../../../lib/perl';
use OVH::Bastion;
use OVH::Bastion::Plugin;
use OVH::Result;

OVH::Bastion::enable_mocking();

my $fnret;

# a valid configuration, along with rules that must all be discarded at load time
OVH::Bastion::load_configuration(
    mock_data => {
        pluginRestrictions => [
            {
                accounts  => [qw{ johndoe janedoe }],
                plugins   => [qw{ groupCreate groupModify groupDelete }],
                resources => {group => '^test$'},
            },
            {
                accounts  => [qw{ johndoe }],
                plugins   => [qw{ groupCreate }],
                resources => {group => '^t', account => '^john'},
            },
            {
                accounts  => [qw{ johndoe }],
                plugins   => [qw{ groupList }],
                resources => {group => '^test$'},
            },
            {
                accounts  => [qw{ johndoe }],
                plugins   => [qw{ accountCreate accountModify accountDelete }],
                resources => {account => '^ext-'},
            },
            "not a hash",
            {accounts => [],                  plugins => [qw{ groupCreate }], resources => {group => '^test$'}},
            {accounts => [qw{ johndoe }],     plugins => "not an array",      resources => {group => '^test$'}},
            {accounts => [qw{ john doe }],    plugins => [qw{ groupCreate }], resources => {}},
            {accounts => [qw{ bad;account }], plugins => [qw{ groupCreate }], resources => {group       => '^test$'}},
            {accounts => [qw{ johndoe }],     plugins => [qw{ groupCreate }], resources => {nonexistent => '^test$'}},
            {accounts => [qw{ johndoe }],     plugins => [qw{ groupCreate }], resources => {group => '(unbalanced'}},
            {accounts => [qw{ johndoe }],     plugins => [qw{ groupCreate }], resources => {group => ''}},
        ],
    }
);

$fnret = OVH::Bastion::config('pluginRestrictions');
is(scalar @{$fnret->value}, 4, "only the valid rules are kept");

sub check {
    my ($account, $plugin, $resources) = @_;
    return OVH::Bastion::check_plugin_restrictions(
        account   => $account,
        plugin    => $plugin,
        resources => $resources
    );
}

# an account that appears in no rule is never restricted
ok(check("someoneelse", "groupCreate", {group => "prod"}), "unlisted account is not restricted");

# a plugin that appears in no rule is never restricted
ok(check("johndoe", "groupAddMember", {group => "prod", account => "janedoe"}), "unlisted plugin is not restricted");

# the nominal case: the resource matches, or it doesn't
ok(check("janedoe", "groupCreate", {group => "test"}), "matching resource is allowed");
$fnret = check("janedoe", "groupCreate", {group => "prod"});
is($fnret->err, 'KO_RESTRICTED_RESOURCE', "non-matching resource is denied");
like($fnret->msg, qr{\^test\$}, "the denial message states the expected regex");

# the same rule applies to all the plugins it lists
$fnret = check("janedoe", "groupDelete", {group => "prod"});
is($fnret->err, 'KO_RESTRICTED_RESOURCE', "every plugin of the rule is restricted");

# all the rules matching the account and plugin are enforced, not just the first one
$fnret = check("johndoe", "groupCreate", {group => "test", account => "janedoe"});
is($fnret->err, 'KO_RESTRICTED_RESOURCE', "a second matching rule is enforced too");
ok(check("johndoe", "groupCreate", {group => "test", account => "johndoe"}), "both matching rules are satisfied");

# janedoe is only in the first rule, the second one doesn't apply to her
ok(check("janedoe", "groupCreate", {group => "test", account => "janedoe"}), "a rule only applies to its accounts");

# the account resource behaves like the group one, on the commands that act on accounts
ok(check("johndoe", "accountCreate", {account => "ext-janedoe"}), "a matching account resource is allowed");
foreach my $plugin (qw{ accountCreate accountModify accountDelete }) {
    is(check("johndoe", $plugin, {account => "janedoe"})->err,
        'KO_RESTRICTED_RESOURCE', "$plugin is restricted on the account resource");
}
ok(check("janedoe", "accountDelete", {account => "johndoe"}), "the account rule only applies to its accounts");

# a rule constrains the values a resource takes, it doesn't make it mandatory
ok(check("janedoe", "groupCreate", {group => undef}), "an unspecified resource is not restricted");

# a rule naming a resource the plugin doesn't have can't be enforced, so it denies
$fnret = check("johndoe", "groupList", {});
is($fnret->err, 'KO_RESTRICTED_RESOURCE', "an unenforceable rule denies the plugin");
like($fnret->msg, qr{can't be enforced.+sysadmin}, "the denial message says the rule can't be enforced");

# missing parameters
is(check("johndoe", "",            {})->err, 'ERR_MISSING_PARAMETER', "empty plugin is rejected");
is(check("",        "groupCreate", {})->err, 'ERR_MISSING_PARAMETER', "empty account is rejected");
is(check("johndoe", "groupCreate")->err, 'ERR_MISSING_PARAMETER', "missing resources is rejected");

# a non-array option value is ignored entirely
OVH::Bastion::load_configuration(mock_data => {pluginRestrictions => "nope"});
is_deeply(OVH::Bastion::config('pluginRestrictions')->value, [], "a non-array option defaults to []");
ok(check("johndoe", "groupCreate", {group => "prod"}), "no rule left means no restriction");

# the resources are picked from the plugin options, as declared by the plugins themselves
sub resources {
    my ($options, %params) = @_;
    return OVH::Bastion::Plugin::resources_from_options(options => $options, %params);
}

# groupAddMember, whose options are declared with an already existing lexical
my ($account, $group) = ("janedoe", "keytest");
is_deeply(
    resources({"account=s", \$account, "group=s", \$group}),
    {account => "janedoe", group => "test", user => undef, host => undef},
    "options are mapped to resources, and the group 'key' prefix is stripped"
);

# accountCreate, whose options are declared inline, with an alias and non-string types
my %accountCreateOptions = (
    'uid=i'               => \my $uid,
    'account=s'           => \my $newAccount,
    'pubKey|public-key=s' => \my $pubKey,
    'no-key'              => \my $noKey,
    'ttl=s'               => \my $ttl,
);
$newAccount = "johndoe";
is_deeply(
    resources(\%accountCreateOptions),
    {account => "johndoe", user => undef, host => undef},
    "only the known resource types are picked, aliases and non-resources are ignored"
);

# accountAddPersonalAccess, whose remote user and host come from the tuple, not from the options
$newAccount = "johndoe";
is_deeply(
    resources(\%accountCreateOptions, user => "root", host => "srv1.example.org"),
    {account => "johndoe", user => "root", host => "srv1.example.org"},
    "the remote user and host are taken from the tuple"
);

# accountModify, whose other options are refs to hash elements rather than to plain lexicals
my %modify;
my $modifiedAccount = "ext-janedoe";
is_deeply(
    resources(
        {
            "account=s"               => \$modifiedAccount,
            "mfa-password-required=s" => \$modify{'mfa-password-required'},
            "max-inactive-days=i"     => \$modify{'max-inactive-days'},
        }
    ),
    {account => "ext-janedoe", user => undef, host => undef},
    "options pointing to hash elements are handled like the other ones"
);

# accountDelete, whose second option has an alias longer than the option itself
my $deletedAccount = "ext-janedoe";
is_deeply(
    resources(
        {
            'account=s'                                                           => \$deletedAccount,
            'i-am-a-robot-and-i-dont-know-how-to-answer-your-question|no-confirm' => \my $noConfirm,
        }
    ),
    {account => "ext-janedoe", user => undef, host => undef},
    "an aliased non-resource option is ignored"
);

# groupListServers, whose --group wasn't specified
my $unspecified = '';
is_deeply(
    resources({"group=s", \$unspecified}),
    {group => undef, user => undef, host => undef},
    "an unspecified option is undef, not the empty string"
);

# a code ref option (used by the plugins to toggle several variables at once) is not a resource
is_deeply(
    resources({"group" => sub { return 1 }}),
    {user => undef, host => undef},
    "a non-scalar option ref is ignored"
);

done_testing();
