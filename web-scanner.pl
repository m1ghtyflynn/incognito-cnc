#!/usr/bin/perl
use strict;

# $Id$
use Getopt::Long;
use Time::Local;
Getopt::Long::Configure('no_ignore_case');

# global var/definitions
use vars qw/$TEMPLATES %CLI %VARIABLES %TESTS/;
use vars qw/%FILE %CONFIGFILE %COUNTERS %db_extensions/;
use vars qw/@RESULTS @PLUGINS @DBFILE @REPORTS %CONTENTSEARCH/;

# setup
$COUNTERS{'scan_start'}  = time();
$VARIABLES{'DIV'}        = "-" x 75;

# signal trap so we can close down reports properly
$SIG{'INT'} = \&safe_quit;

config_init();
setup_dirs();
require "$CONFIGFILE{'PLUGINDIR'}/core.plugin";
nprint("T:" . localtime($COUNTERS{'scan_start'}) . ": Starting", "d");
$VARIABLES{'GMTOFFSET'} = gmt_offset();

use LW2;                   ### Change this line to use a different installed version
use JSON::PP;

my ($a, $b) = split(/\./, $LW2::VERSION);
die("- You must use LW2 2.4 or later\n") if ($a != 2 || $b < 4);

general_config();
load_databases();
load_databases('u');
nprint("- $VARIABLES{'name'} v$VARIABLES{'version'}");
nprint($VARIABLES{'DIV'});

# No targets - quit while we're ahead
if ($CLI{'host'} eq "") {
    nprint("+ ERROR: No host specified");
    usage();
}

$COUNTERS{'total_targets'} = $COUNTERS{'hosts_completed'} = 0;
load_plugins();

# Parse the supplied list of targets
my @MARKS = set_targets($CLI{'host'}, $CLI{'ports'}, $CLI{'ssl'}, $CLI{'root'});

if (defined($CLI{'key'}) || defined($CLI{'cert'})) {
    $CLI{'key'}  = $CLI{'cert'} unless (defined($CLI{'key'}));
    $CLI{'cert'} = $CLI{'key'}  unless (defined($CLI{'cert'}));
}

# Now check each target is real and remove duplicates/fill in extra information
foreach my $mark (@MARKS) {
    $mark->{'test'} = 1;

    # Try to resolve the host
    ($mark->{'hostname'}, $mark->{'ip'}, $mark->{'display_name'}) = resolve($mark->{'ident'});

    # Skip if we can't resolve the host - we'll error later
    if (!defined $mark->{'ip'}) {
        $mark->{'test'} = 0;
        next;
    }

    # Check that the port is open
    my $open =
      port_check($mark->{'hostname'}, $mark->{'ip'}, $mark->{'port'}, $CLI{'key'}, $CLI{'cert'});
    if (defined $CLI{'vhost'}) { $mark->{'vhost'} = $CLI{'vhost'} }
    if ($open == 0) {
        $mark->{'test'} = 0;
        next;
    }
    else {
        $COUNTERS{'total_targets'}++;
    }
    $mark->{'ssl'} = $open - 1;

    if ($mark->{'ssl'}) {
        $mark->{'key'}  = $CLI{'key'};
        $mark->{'cert'} = $CLI{'cert'};
    }
}

# Open reporting
report_head($CLI{'format'}, $CLI{'file'});

# Load db_tests
set_scan_items();

# Start hook to allow plugins to load databases etc
run_hooks("", "start");

# Now we've done the precursor, do the scan
foreach my $mark (@MARKS) {
    next unless ($mark->{'test'});
    $mark->{'start_time'} = time();
    $VARIABLES{'TEMPL_HCTR'}++;

    if (defined $CLI{'vhost'}) {
        $mark->{'vhost'} = $CLI{'vhost'};
    }

    # Saving responses
    if ($CLI{'saveresults'} ne '') {
        $mark->{'save_dir'} = save_createdir($CLI{'saveresults'}, $mark);
        $mark->{'save_prefix'} = save_getprefix($mark);
    }

    # Cookies
    if (defined $CONFIGFILE{'STATIC-COOKIE'}) {
        $mark->{'cookiejar'} = LW2::cookie_new_jar();

        # parse conf line into name/value pairs
        foreach my $p (split(/;/, $CONFIGFILE{'STATIC-COOKIE'})) {
            $p =~ s/(?:^\s+|\s+$)//;
            $p =~ s/"(?:[ ]+)?=(?:[ ]+)?"/","/g;
            my @cv = parse_csv($p);

            # Set into the jar
            LW2::cookie_set(\%{ $mark->{'cookiejar'} }, $cv[0], $cv[1]);
        }
    }

    $mark->{'total_vulns'}  = 0;
    $mark->{'total_errors'} = 0;

    my %FoF = ();

    nfetch($mark, "/", "GET", "", "", { noprefetch => 1, nopostfetch => 1 }, "getinfo");

    report_host_start($mark);
    if ($CLI{'findonly'}) {
        my $protocol = "http";
        if ($mark->{'ssl'}) { $protocol .= "s"; }
        if ($mark->{'banner'} eq "") {
            $mark->{'banner'} = "(no identification possible)";
        }

        add_vulnerability($mark,
                   "Server: $protocol://$mark->{'display_name'}:$mark->{'port'}\t$mark->{'banner'}",
                   0);
    }
    else {
        dump_target_info($mark);
        unless ((defined $CLI{'nofof'}) || ($CLI{'plugins'} eq '@@NONE')) { map_codes($mark) }
        run_hooks($mark, "recon");
        run_hooks($mark, "scan");
    }
    $mark->{'end_time'} = time();
    $mark->{'elapsed'}  = $mark->{'end_time'} - $mark->{'start_time'};
    if (!$CLI{'findonly'}) {
        if (!$mark->{'terminate'}) {
            nprint(
                "+ $COUNTERS{'total_checks'} items checked: $mark->{'total_errors'} error(s) and $mark->{'total_vulns'} item(s) reported on remote host"
                );
        }
        else {
            nprint(
                "+ Scan terminated:  $mark->{'total_errors'} error(s) and $mark->{'total_vulns'} item(s) reported on remote host"
                );
        }
        nprint(  "+ End Time:           "
               . date_disp($mark->{'end_time'})
               . " (GMT$VARIABLES{'GMTOFFSET'}) ($mark->{'elapsed'} seconds)");
    }
    nprint($VARIABLES{'DIV'});

    $COUNTERS{'hosts_completed'}++;
    report_host_end($mark);
}
$COUNTERS{'scan_end'}     = time();
$COUNTERS{'scan_elapsed'} = ($COUNTERS{'scan_end'} - $COUNTERS{'scan_start'});
report_summary();
report_close();

if (!$CLI{'findonly'}) {
    nprint("+ $COUNTERS{'hosts_completed'} host(s) tested");
    nprint("+ $COUNTERS{'totalrequests'} requests made in $COUNTERS{'scan_elapsed'} seconds", "v");

    send_updates(@MARKS);
}

nprint("T:" . localtime() . ": Ending", "d");

exit;

#################################################################################
# Load config files in order
sub config_init {

    # read just the --config option
    {
        my %optcfg;
        Getopt::Long::Configure('pass_through', 'noauto_abbrev');
        GetOptions(\%optcfg, "config=s");
        Getopt::Long::Configure('nopass_through', 'auto_abbrev');
        if (defined $optcfg{'config'}) { $VARIABLES{'configfile'} = $optcfg{'config'}; }
    }

    # Read the config files in order
    my ($error, $home);
    my $config_exists = 0;
    $error = load_config("$VARIABLES{'configfile'}");
    $config_exists = 1 if ($error eq "");

    # Guess home directory -- to support Windows
    foreach my $var (split(/ /, "HOME USERPROFILE")) {
        $home = $ENV{$var} if ($ENV{$var});
    }
    $error = load_config("$home/file.conf");
    $config_exists = 1 if ($error eq "");

    # Guess current directory
    my $FILEDIR = $0;
    chomp($FILEDIR);
    $FILEDIR =~ s#[\\/]web-scanner.pl$##;
    $error = load_config("$FILEDIR/file.conf");
    $config_exists = 1 if ($error eq "");

    $error = load_config("file.conf");
    $config_exists = 1 if ($error eq "");

    if ($config_exists == 0) {
        die "- Could not find a valid config file\n";
    }

    return;
}

#################################################################################
# load config file
# error=load_config(FILENAME)
sub load_config {
    my $configfile = $_[0];

    open(CONF, "<$configfile") || return "+ ERROR: Unable to open config file '$configfile'";
    my @CONFILE = <CONF>;
    close(CONF);

    foreach my $line (@CONFILE) {
        $line =~ s/\#.*$//;
        chomp($line);
        $line =~ s/\s+$//;
        $line =~ s/^\s+//;
        next if ($line eq "");
        my @temp = split(/=/, $line, 2);
        if ($temp[0] ne "") { $CONFIGFILE{ $temp[0] } = $temp[1]; }
    }

    # add CONFIG{'CLIOPTS'} to ARGV if defined...
    if (defined $CONFIGFILE{'CLIOPTS'}) {
        my @t = split(/ /, $CONFIGFILE{'CLIOPTS'});
        foreach my $c (@t) { push(@ARGV, $c); }
    }

    # Check for necessary config items
    check_config_defined("CHECKMETHODS", "HEAD");
    check_config_defined('@@MUTATE',     'dictionary;subdomain');
    check_config_defined('@@DEFAULT',    '@@ALL,-@@MUTATE');

    return "";
}
#################################################################################
# find plugins directory
sub setup_dirs {
    my $CURRENTDIR = $0;
    chomp($CURRENTDIR);
    $CURRENTDIR =~ s#[\\/]file.pl$##;
    $CURRENTDIR = "." if $CURRENTDIR =~ /^file.pl$/;

    # First assume we get it from CONFIGFILE
    unless (defined $CONFIGFILE{'EXECDIR'}) {
        if (-d "$ENV{'PWD'}/plugins") {
            $CONFIGFILE{'EXECDIR'} = $ENV{'PWD'};
        }
        elsif (-d "$CURRENTDIR/plugins") {
            $CONFIGFILE{'EXECDIR'} = $CURRENTDIR;
        }
        elsif (-d "./plugins") {
            $CONFIGFILE{'EXECDIR'} = $CURRENTDIR;
        }
        else {
            print STDERR "Could not work out the EXECDIR, try setting it in file.conf\n";
            exit;
        }
    }
    unless (defined $CONFIGFILE{'PLUGINDIR'}) {
        $CONFIGFILE{'PLUGINDIR'} = "$CONFIGFILE{'EXECDIR'}/plugins";
    }
    unless (defined $CONFIGFILE{'TEMPLATEDIR'}) {
        $CONFIGFILE{'TEMPLATEDIR'} = "$CONFIGFILE{'EXECDIR'}/templates";
    }
    unless (defined $CONFIGFILE{'DOCUMENTDIR'}) {
        $CONFIGFILE{'DOCUMENTDIR'} = "$CONFIGFILE{'EXECDIR'}/docs";
    }
    unless (defined $CONFIGFILE{'DBDIR'}) {
        $CONFIGFILE{'DBDIR'} = "$CONFIGFILE{'EXECDIR'}/databases";
    }
    return;
}

######################################################################
## check_config_defined(item, default)
## Checks whether config has been set, warns and sets to a default
sub check_config_defined {
    my $item    = $_[0];
    my $default = $_[1];

    if (!defined $CONFIGFILE{$item}) {
        print STDERR
          "- Warning: $item is not defined in configuration, setting to \"$default\"\n";
        $CONFIGFILE{$item} = $default;
    }

    return;
}
