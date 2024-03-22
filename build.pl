#!/usr/bin/env perl

use warnings;
use strict;

sub getconf;
sub hasconf;

# = Project configuration ==================================== #

# Directories in which source files may be found
my @source_directories = qw(
	3rd/nnc/source
	source
);

# Directories to add to the include path
my @include_directories = qw(
	include
	3rd
	3rd/3rd
	.
);

# Directories to search for data files in
my @data_directories = qw(
	data
);

# Directory to search for grahpics in
my $graphics_directory = "gfx";

# Defines the romfs directory location
my $romfs_dir = "romfs";

# Output directory for graphics build
my $graphics_output = "$romfs_dir/gfx";

# Name of the project, name of the binary
my $binary_name = "3hs";

# These are in addition to "-lcitro2d -lcitro3d -lctru -lm"
my $libraries = "-lmbedcrypto";

# Define to 1 if this project contains C++ files, otherwise 0
my $cpp_project = 1;

# Defines the C++ and C versions used to build
my $cpp_version = "gnu++11";
my $c_version   = "gnu11";

# Always "arm-none-eabi-" for 3DS projects
my $compiler_prefix = "arm-none-eabi-";

# RSF file for compiling a CIA
my $cia_rsf = "cia_stuff/3hs.rsf";

my $app_title = "3hs";
my $app_description = "An on-device client for hShop";
my $app_author = "hShop";
my $app_icon = "cia_stuff/icon.png";
my $app_banner = "cia_stuff/banner.png";
my $app_jingle = "cia_stuff/audio.cwav";

# Configuration subroutine, this is called when a new target is made
#  and should contain additional configuration (i.e. set CFLAGS, LDFLAGS, etc)
#  special: you can set PREDEPS to define additional dependencies for the ELF file
#  which will be execute *before* the objects compile
#  you can also set EXTRA_CLEAN to add extra files to delete with `./build.pl clean`
sub configure {
	my $debug     = hasconf "debug";
	my $full_log  = hasconf "full_log";
	my $release   = hasconf "release";
	my $devid     = getconf "device_id";
	my $dserv     = getconf "debug_server", "HS_DEBUG_SERVER";
	my $upbase    = getconf "update_base", "HS_UPDATE_BASE";
	my $cdnbase   = getconf "cdn_base", "HS_CDN_BASE";
	my $siteloc   = getconf "site_url", "HS_WEBSITE";
	my $nbloc     = getconf "nb_base", "HS_NB_BASE";

	die "Must provide hShop server URLs, see the README"
		unless $upbase && ($dserv || ($cdnbase && $siteloc && $nbloc));

	my $cflags = "";
	$cflags .= " -DFULL_LOG=1" if $full_log;
	$cflags .= " -ggdb3" if $debug || !$release;
	$cflags .= " -DRELEASE=1 -O2" if $release;
	$cflags .= " -DDEVICE_ID=$devid" if $devid;
	$cflags .= " -DHS_DEBUG_SERVER=\\\"$dserv\\\"" if $dserv;
	$cflags .= " -DHS_UPDATE_BASE=\\\"$upbase\\\"" if $upbase;
	$cflags .= " -DHS_NB_BASE=\\\"$nbloc\\\"" if $nbloc;
	$cflags .= " -DHS_CDN_BASE=\\\"$cdnbase\\\"" if $cdnbase;
	$cflags .= " -DHS_SITE_LOC=\\\"$siteloc\\\"" if $siteloc;

	return <<EOF;
CFLAGS   :=$cflags
CXXFLAGS := \$(CFLAGS)

PREDEPS := \$(BUILD)/i18n_tab.cc data/dark.hstx data/light.hstx
EOF
}

# Configure rules subroutine, this subroutine should return additional rules you need
#  for your makefile
sub configure_rules {
	return <<EOF;
\$(BUILD)/i18n_tab.cc: \$(shell find lang/ -not -name '*.pl' -type f)
	\@echo i18n_tab.cc
	\@echo i18n_tab.hh
	\$(SILENT)mkdir -p \$(BUILD)
	\$(SILENT)./lang/make.pl --build \$(BUILD) --lang 'lang/'

data/dark.hstx data/light.hstx: 3hstool/3hstool 3hstool/dark.cfg 3hstool/light.cfg
	\$(SILENT)./3hstool/make_default_themes.sh

3hstool/3hstool:
	\$(SILENT)cd 3hstool; make -f Makefile
EOF
}

# ============================================================ #

use Getopt::Long qw(:config no_auto_abbrev no_ignore_case bundling);
use File::Path qw(rmtree);
use File::Find qw(find);
use File::Basename;

my $build_dir = ".build-stage";
my $update_file_list = 0;
my $config_string = 0;
my $target = 0;
my $explicit_init = 0;
my $new_default = 0;
my $jobs = int `nproc`;

GetOptions(
	"build|b=s", \$build_dir,
	"update-file-list|u", \$update_file_list,
	"init|i", \$explicit_init,
	"set-default-target=s", \$new_default,
	"target|t=s", \$target,
	"configure|c=s", \$config_string,
	"jobs|j=i", \$jobs,
) or die "couldn't parse options";

if (!$target && -f "$build_dir/default-target.txt") {
	open my $fh, "$build_dir/default-target.txt" or die $!;
	$target = <$fh>;
	close $fh;
} elsif (!$target) {
	$target = "debug";
}

if ($new_default) {
	mkdir $build_dir;
	open my $fh, ">$build_dir/default-target.txt" or die $!;
	print $fh $new_default;
	close $fh;
	exit 0;
}

my %conf_kv;
sub getconf {
	my ($key, $env) = @_;
	$env = uc $key if !$env;
	return
		  exists $conf_kv{$key} ? $conf_kv{$key}
		: exists $ENV{$env} ? $ENV{$env}
		: undef;

}

sub hasconf {
	my ($key, $env) = @_;
	$env = uc $key if !$env;
	return exists $conf_kv{$key} || exists $ENV{$env};
}

sub make_file_list {
	my (@files, @data_files, @gfx_files);
	find { no_chdir => 1, wanted => sub { push @files, $_ if /\.(cpp|cc|c)$/; } }, @source_directories;
	find { no_chdir => 1, wanted => sub { push @data_files, $_ if -f; } }, @data_directories;
	find { no_chdir => 1, wanted => sub { push @gfx_files, $_ if -f; } }, $graphics_directory;
	my $str = "\nSOURCE_FILES := \\\n";
	for my $f (@files) {
		$str .= "\t$f \\\n";
	}
	$str .= "\nOBJECT_FILES := \\\n";
	for my $f (@files) {
		$f =~ s/\.(cpp|cc|c)/\.o/;
		$str .= "\t$f \\\n";
	}
	$str .= "\n";
	for my $f (@gfx_files) {
		if ($f =~ /\.t3s$/) {
			$f = basename $f;
			$f =~ s/\.t3s/\.t3x/;
			$str .= "T3XFILES += $f\n";
		}
	}
	$str .= "\nDATA_OBJECTS := \\\n";
	rmtree "$build_dir/build";
	mkdir "$build_dir/build";
	for my $f (@data_files) {
		my $name = basename $f;
		symlink "../../$f", "$build_dir/build/$name.bin";
		$str .= "\t$name.o \\\n";
	}
	$str .= "\n";
	open my $fh, ">$build_dir/file-list.mk" or die $!;
	print $fh $str;
	close $fh;
}

sub execute_make {
	print "Executing make for target '$target' ...\n";
	system "make -f $build_dir/$target.target.mk -j$jobs " . join ' ', @ARGV;
}

sub make_target {
	my ($name) = @_;

	if ($config_string) {
		for (split /[ ]*,[ ]*/, $config_string) {
			my ($k, $v) = /=/ ? m/([^=]+)=(.+)/ : ($_, "");
			$conf_kv{$k} = $v;
		}
	}

	my $config_extra_rules = configure_rules;
	my $config_makefile = configure;

	print "Configuring target $target...\n";
	print "Options (excluding environment):\n";
	for my $val (keys %conf_kv) {
		print "  $val => $conf_kv{$val}\n";
	}

	my $targets = (getconf 'targets') || '3dsx';

	my $makefile = <<EOF;
TARGETS := $targets
BUILD := $build_dir/$name

# == Generated by sub configure ============

$config_makefile
# ==========================================

include $build_dir/base-makefile.mk

# == Generated by sub configure_rules ======

$config_extra_rules
# ==========================================
EOF
	rmtree "$build_dir/$name";
	open my $fh, ">$build_dir/$name.target.mk" or die $!;
	print $fh $makefile;
	close $fh;
	mkdir "$build_dir/$name";
}

if (! -d $build_dir || $explicit_init) {
	if (!exists $ENV{DEVKITPRO}) {
		print STDERR "Please set DEVKITPRO in your environment. export DEVKITPRO=<path to>devkitPro\n";
		exit 1;
	}

	my $devkitpro = $ENV{DEVKITPRO};
	my $portlibs_path = "$devkitpro/portlibs/3ds";
	my $libctru_path  = "$devkitpro/libctru";

	$app_icon = "$libctru_path/default_icon.png" if !$app_icon;

	my $cc = "${compiler_prefix}gcc";
	my $cxx = "${compiler_prefix}g++";
	my $as = "${compiler_prefix}as";
	my $_3dsxtool = "3dsxtool";
	my $smdhtool = "smdhtool";
	my $bin2s = "bin2s";
	my $tex3ds = "tex3ds";
	my $bannertool = "bannertool";
	my $makerom = "makerom";
	my $_3dslink = "3dslink";
	my $citra = "citra-qt";
	my $ld = $cpp_project ? $cxx : $cc;

	my $depflags = "-MMD -MP -MF \$(\@:.o=.d)";
	my $data_build = "$build_dir/build";

	rmtree $build_dir;
	mkdir $build_dir;
	make_file_list;
	my $include_flags = join ' ', map { "-I$_" } @include_directories;
	my $sys_include_flags = "-I\$(BUILD) -I$build_dir -I$portlibs_path/include -I$libctru_path/include";
	my $base_makefile = <<EOF;
include $build_dir/file-list.mk

# 3DS configuration
SYSFLAGS := -march=armv6k -mtune=mpcore -mfloat-abi=hard -mtp=soft \\
	-isystem/opt/devkitpro/devkitARM/arm-none-eabi/include/c++/12.2.0 -isystem/opt/devkitpro/devkitARM/arm-none-eabi/include/c++/12.2.0/arm-none-eabi

SOURCE_FLAGS := \\
	\$(SYSFLAGS) \\
	-fcompare-debug-second -ffunction-sections \\
	$sys_include_flags \\
	$include_flags \\
	-D__3DS__ -D_3DS

CXXFLAGS += \$(SOURCE_FLAGS) -fno-rtti -fno-exceptions -std=$cpp_version
CFLAGS += \$(SOURCE_FLAGS) -std=$c_version

LDFLAGS += \$(SYSFLAGS) -specs=3dsx.specs
ASFLAGS += \$(SYSFLAGS)

LIBS += $libraries -lcitro2d -lcitro3d -lctru -lm -L$portlibs_path/lib -L$libctru_path/lib
# end

# Tools setup
export PATH := $devkitpro/tools/bin:$devkitpro/portlibs/3ds/bin:\$(PATH)

ifeq (\$(VERSION),)
	VERSION := 0
endif

GRAPHICS     := \$(addprefix $graphics_output/,\$(T3XFILES)) \$(foreach f,\$(T3XFILES),$data_build/\$(f:.t3x=.h))
DATA_OBJECTS := \$(addprefix $data_build/,\$(DATA_OBJECTS))
OBJECT_FILES := \$(addprefix \$(BUILD)/,\$(OBJECT_FILES))

ifeq (\$(V),)
	SILENT := \@
else
	SILENT :=
endif

.PHONY: all clean clean-data
all: \$(TARGETS)
clean:
	\$(SILENT)rm -f \$(OBJECT_FILES) \$(DATA_OBJECTS) \$(GRAPHICS) \$(EXTRA_CLEAN)
clean-data:
	\$(SILENT)rm -f \$(DATA_OBJECTS)

.PHONY: 3dsx elf cia
3dsx: $binary_name.3dsx
cia: $binary_name.cia
elf: $binary_name.elf

.PHONY: 3dslink citra
3dslink: $binary_name.3dsx
	\$(SILENT)$_3dslink \$<
citra: $binary_name.3dsx
	\$(SILENT)$citra \$<

$binary_name.3dsx: $binary_name.elf \$(BUILD)/$binary_name.smdh
	\$(SILENT)$_3dsxtool $binary_name.elf $binary_name.3dsx --smdh=\$(BUILD)/$binary_name.smdh --romfs=$romfs_dir
	\@echo built ... \$@

$binary_name.cia: $binary_name.elf \$(BUILD)/$binary_name.smdh \$(BUILD)/$binary_name.bnr
	\$(SILENT)$makerom -f cia -o \$@ -target t -elf $binary_name.elf -icon \$(BUILD)/$binary_name.smdh -banner \$(BUILD)/$binary_name.bnr -rsf $cia_rsf -DROMFS_PATH="$romfs_dir" -ver \$(VERSION)
	\@echo built ... \$@

$binary_name.elf: \$(PREDEPS) \$(GRAPHICS) \$(DATA_OBJECTS) \$(OBJECT_FILES)
	\$(SILENT)$ld \$(DATA_OBJECTS) \$(OBJECT_FILES) \$(LDFLAGS) \$(LIBS) -o \$@
	\@echo built ... \$@

\$(BUILD)/$binary_name.smdh: $app_icon
	\$(SILENT)$bannertool makesmdh -f visible,nosavebackups -i \$< -s "$app_title" -l "$app_description" -p "$app_author" -o \$@ >/dev/null
	\@echo built ... `basename \$@`

\$(BUILD)/$binary_name.bnr: $app_banner $app_jingle
	\$(SILENT)$bannertool makebanner -ca $app_jingle -i $app_banner -o \$@ >/dev/null
	\@echo built ... `basename \$@`

\$(BUILD)/%.o: %.cc
	\@echo \$(notdir \$<)
	\$(SILENT)mkdir -p \$(dir \$@)
	\$(SILENT)$cxx -c \$< -o \$@ \$(CXXFLAGS) $depflags

\$(BUILD)/%.o: %.cpp
	\@echo \$(notdir \$<)
	\$(SILENT)mkdir -p \$(dir \$@)
	\$(SILENT)$cxx -c \$< -o \$@ \$(CXXFLAGS) $depflags

\$(BUILD)/%.o: %.c
	\@echo \$(notdir \$<)
	\$(SILENT)mkdir -p \$(dir \$@)
	\$(SILENT)$cc -c \$< -o \$@ \$(CFLAGS) $depflags

$graphics_output/%.t3x $data_build/%.h: $graphics_directory/%.t3s
	\@echo \$(notdir \$<)
	\$(SILENT)$tex3ds -i \$< -H $data_build/\$*.h -o $graphics_output/\$*.t3x

$data_build/%.o: $data_build/%.bin
	\@echo `basename \$< | sed 's/\.bin//'`
	\$(SILENT)$bin2s -a 4 -H $data_build/`echo \$* | tr . _`.h \$< | $as -o \$@

-include \$(OBJECT_FILES:.o=.d)
EOF
	open my $basefh, ">$build_dir/base-makefile.mk" or die $!;
	print $basefh $base_makefile;
	close $basefh;
	open my $deffh, ">$build_dir/default-target.txt" or die $!;
	print $deffh $target;
	close $deffh;
	make_target $target;
	execute_make if !$explicit_init;
}
elsif ($update_file_list) {
	make_file_list;
} elsif ($config_string) {
	make_target $target;
} else {
	make_target $target unless -f "$build_dir/$target.target.mk";
	execute_make;
}

