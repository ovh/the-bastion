#! /usr/bin/env perl
# vim: set filetype=perl ts=4 sw=4 sts=4 et:

use strict;
use warnings;

use Carp;
use CGI;
use common::sense;
use Config;
use Cwd;
use Data::Dumper;
use DBD::SQLite;
use Digest::MD5;
use Digest::SHA;
use Exporter;
use Fcntl;
use File::Basename;
use File::Copy;
use File::Find;
use File::Path;
use File::Temp;
use Getopt::Long;
use HTTP::Headers;
use HTTP::Message;
use HTTP::Request;
use IO::Compress::Gzip;
use IO::Handle;
use IO::Pipe;
use IO::Select;
use IO::Socket::SSL;
use IPC::Open2;
use IPC::Open3;
use JSON;
use List::Util;
use LWP::UserAgent;
use MIME::Base64;
use Net::IP;
use Net::Netmask;
use Net::Server::PreFork;
use Net::Server::PreForkSimple;
use POSIX;
use Scalar::Util;
use Socket;
use Storable;
use Symbol;
use Sys::Hostname;
use Sys::Syslog;
use Term::ANSIColor;
use Term::ReadKey;
use Term::ReadLine;
use Time::HiRes;
use Time::Piece;
use URI;

print "OK: all required Perl modules are present\n";
