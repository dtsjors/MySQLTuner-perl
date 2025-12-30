#!/usr/bin/env perl
use warnings;
use strict;
use LWP::Simple;
use Archive::Zip qw(:ERROR_CODES :CONSTANTS);
use File::Find;
use File::Path qw(make_path);
use File::Basename;
use File::Util;
use JSON;
use Data::Dumper;
use List::MoreUtils qw(uniq);
use Time::HiRes qw(time);

use constant MAX_VERSION_PART => 9999;
sub apply_before_logic {
    my ($version) = @_;
    my @nb = split(/\./, $version);
    if (defined($nb[2]) && $nb[2] ne '' && $nb[2] =~ /^\d+$/) {
        if ($nb[2] == 0) {
            $nb[2] = MAX_VERSION_PART;
            if ($nb[1] ne '' && $nb[1] =~ /^\d+$/) {
                if ($nb[1] == 0) {
                    $nb[1] = MAX_VERSION_PART;
                    if ($nb[0] ne '' && $nb[0] =~ /^\d+$/ && $nb[0] > 0) {
                        $nb[0]--;
                    }
                } else {
                    $nb[1]--;
                }
            }
        } else {
            $nb[2]--;
        }
        return join('.', $nb[0], $nb[1], $nb[2]);
    }
    return $version;
}

my $verbose=1;

my $zip_url = 'https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip';
my $zip_file = 'zip/main.zip';
my $extract_dir = 'zip/cvelistV5-main';
my $cves_dir = "$extract_dir/cves";
my $output_csv = 'output/vulnerabilities.csv';

$| = 1;

my $start_time = time();
print "[Step 1/4] Checking for CVE zip...\n";

# Download zip if not present
unless (-f $zip_file) {
    print "[Step 2/4] Downloading CVE zip from $zip_url...\n";
    my $rc = getstore($zip_url, $zip_file);
    die "Failed to download zip: $rc" unless $rc == 200;
    print "[Step 2/4] Download complete.\n";
} else {
    print "[Step 2/4] CVE zip already present.\n";
}

# Extract zip if not already extracted
unless (-d $extract_dir) {
    print "[Step 3/4] Extracting $zip_file...\n";
    my $zip = Archive::Zip->new();
    unless ($zip->read($zip_file) == AZ_OK) {
        die "Failed to read zip file";
    }
    $zip->extractTree('', 'zip/');
    print "[Step 3/4] Extraction complete.\n";
} else {
    print "[Step 3/4] CVE zip already extracted.\n";
}

# Prepare output

unlink $output_csv if -f $output_csv;
open(my $outfh, '>:encoding(UTF-8)', $output_csv) or die "Cannot open $output_csv: $!";


# Recursively process all JSON files, but filter early with grep
print "[Step 4/4] Collecting CVE JSON files (early filter with grep)...\n";
my @json_files = `grep -rilE 'mysql|mariadb|percona' $cves_dir`;
chomp @json_files;
my $total = scalar @json_files;
print "Found $total relevant CVE JSON files to process.\n";

my $processed = 0;
my $reported = 0;
my $last_percent = -1;

foreach my $json_file (@json_files) {
    $processed++;
    my $percent = int(($processed / $total) * 100);
    if ($percent != $last_percent && $percent % 5 == 0 && $percent != 100) {
        print "Processing: $percent% ($processed/$total)\r";
        $last_percent = $percent;
    }
    open my $fh, '<', $json_file or do {
        warn "Could not open $json_file: $!";
        next;
    };
    local $/; # slurp
    my $json_text = <$fh>;
    close $fh;
    my $data;
    eval { $data = decode_json($json_text); };
    if ($@ || !$data) {
        warn "Malformed JSON in $json_file: $@";
        next;
    }

    # Compose fields for output
    my $cveid = $data->{cveMetadata}->{cveId} // '';
    my $desc = '';
    if (ref $data->{containers}->{cna}->{descriptions} eq 'ARRAY') {
        foreach my $desc_obj (@{ $data->{containers}->{cna}->{descriptions} }) {
            if ($desc_obj->{lang} && $desc_obj->{lang} =~ /^en/i) {
                $desc = $desc_obj->{value};
                last;
            }
        }
    }
    my $title = $data->{containers}->{cna}->{title} // '';
    # Fallback: if no title, try to get from adp array
    if (!$title && ref $data->{containers}->{adp} eq 'ARRAY') {
        foreach my $adp_obj (@{ $data->{containers}->{adp} }) {
            if ($adp_obj->{title}) {
                $title = $adp_obj->{title};
                last;
            }
        }
    }
    my $status = $data->{cveMetadata}->{state} // $data->{containers}->{cna}->{x_legacyV4Record}->{CVE_data_meta}->{STATE} // '';
    my $assigned = $data->{cveMetadata}->{dateReserved} // '';
    my $proposal = '';
    my $extra = '';
    # References
    my $refs = '';
    if (ref $data->{containers}->{cna}->{references} eq 'ARRAY') {
        $refs = join('   |   ', map {
            ($_->{name} ? $_->{name} : '') . (($_->{url} && $_->{name}) ? ':' : '') . ($_->{url} // '')
        } @{ $data->{containers}->{cna}->{references} });
    }
    # Version extraction
    my @versions;
    # Try affected array first, but always apply fallback extraction from description
    my $has_real_version = 0;
    if (ref $data->{containers}->{cna}->{affected} eq 'ARRAY') {
        foreach my $aff (@{ $data->{containers}->{cna}->{affected} }) {
            if ($aff->{versions} && ref $aff->{versions} eq 'ARRAY') {
                foreach my $ver (@{ $aff->{versions} }) {
                    if ($ver->{version} && $ver->{version} ne 'n/a' && $ver->{version} ne '*') {
                        push @versions, $ver->{version};
                        $has_real_version = 1;
                    }
                    # Always push lessThan and lessThanOrEqual if present
                    push @versions, apply_before_logic($ver->{lessThan}) if $ver->{lessThan};
                    push @versions, $ver->{lessThanOrEqual} if $ver->{lessThanOrEqual};
                }
            }
        }
    }
    # Only apply fallback: try to extract from description if no versions are defined
    if (!@versions and $desc) {
        # Match digit.digit.digit
        my @desc_versions = $desc =~ /(\d{1,2}\.\d+\.[\d]+)/g;
        # Also try for patterns like "mysql 4.0.20 and earlier"
        if ($desc =~ /mysql\s+(\d+\.\d+\.\d+)/i) {
            push @desc_versions, $1;
        }
        # Only match digit.digit.x (e.g., 5.0.x) if no versions matched so far
        if (!@desc_versions) {
            push @desc_versions, $desc =~ /(\d{1,2}\.\d+\.x)/g;
        }
        # Apply 'before' logic to fallback versions
        foreach my $v (@desc_versions) {
            if ($desc =~ /before/i) {
                my $v_mod = apply_before_logic($v);
                push @versions, $v_mod unless grep { $_ eq $v_mod } @versions;
            } else {
                push @versions, $v unless grep { $_ eq $v } @versions;
            }
        }
    }
    # If no version, fallback to n/a
    @versions = ('n/a') unless @versions;

    # Exclude CVEs where affected product is not n/a and does not match mysql, mariadb, or percona
    my $exclude_due_to_product = 0;
    if (ref $data->{containers}->{cna}->{affected} eq 'ARRAY') {
        foreach my $aff (@{ $data->{containers}->{cna}->{affected} }) {
            if (
                exists $aff->{product}
                && defined $aff->{product}
                && $aff->{product} ne 'n/a'
                && $aff->{product} !~ /(mysql|mariadb|percona)/i
            ) {
                $exclude_due_to_product = 1;
                last;
            }
        }
    }
    # Filtering logic (adapted from old script)
    if (
        !$exclude_due_to_product
        && ($desc =~ /(mysql|mariadb|percona)/i || $title =~ /(mysql|mariadb|percona)/i)
        && ($desc =~ /server/i || $title =~ /server/i)
        && $desc !~ /MaxDB/i
        && $desc !~ /\*\* REJECT \*\*/i
        && $desc !~ /\*\* DISPUTED \*\*/i
        && $desc !~ /(Radius|Proofpoint|Active\ Record|XAMPP|TGS\ Content|e107|post-installation|Apache\ HTTP|Zmanda|pforum|phpMyAdmin|Proxy\ Server|on\ Windows|ADOdb|Mac\ OS|Dreamweaver|InterWorx|libapache2|cisco|ProFTPD)/i
    ) {
        foreach my $vers (uniq(@versions)) {
            # Clean version: replace 'x' with '99', remove 'and earlier', 'andearlier', and 'MySQL Server '
            my $vers_mod = $vers;
            $vers_mod =~ s/\.x$/'.' . MAX_VERSION_PART/e;
            $vers_mod =~ s/\s*and earlier//ig;
            $vers_mod =~ s/andearlier//ig;
            $vers_mod =~ s/MySQL Server //ig;
            $vers_mod =~ s/[^0-9\.]+//g; # Remove any non-numeric, non-dot chars
            my @nb = split(/\./, $vers_mod);
            $nb[0] //= '';
            $nb[1] //= '';
            $nb[2] //= '';
            # Remove newlines from description and references
            my $desc_oneline = $desc;
            $desc_oneline =~ s/[\r\n]+/ /g;
            my $refs_oneline = $refs;
            $refs_oneline =~ s/[\r\n]+/ /g;
            # Compose output line
            my $vers_out = join('.', ($nb[0] // ''), ($nb[1] // ''), ($nb[2] // ''));
            next unless $vers_out ne '..'; # Skip empty versions
            my $out = join(";",
                $vers_out,
                ($nb[0] // ''),
                ($nb[1] // ''),
                ($nb[2] // ''),
                $cveid,
                $status,
                '"' . $desc_oneline . '"',
                '"' . $refs_oneline . '"',
                $assigned,
                $proposal,
                $extra
            );
            print $outfh "$out\n";
            $reported++;
        }
    }
}
print "\nProcessing: 100% ($processed/$total)\n";
close $outfh;
chmod 0644, $output_csv;
my $elapsed = time() - $start_time;
printf("Done! Time: %.2fs, CVEs reported: %d\n", $elapsed, $reported);
exit(0);
