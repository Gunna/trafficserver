#!/bin/bash

export name=$1
export version=$2
export release=${3:-0}

TOP_DIR="/tmp/.rpm_create_"$name"_"`whoami`

LANG=C
export LANG

usage()
{
  echo "Usage:"
  echo "$0 packagename version release"
  exit 0
}


RPM_MACROS=$HOME/.rpmmacros
if [ -e $RPM_MACROS ]; then
  mv -f $RPM_MACROS $RPM_MACROS.bak
fi


echo "%_topdir $TOP_DIR" > $RPM_MACROS
echo "%packager " `whoami` >> $RPM_MACROS
echo "%vendor XXY Inc." >> $RPM_MACROS
echo "%_release $release" >> $RPM_MACROS
#echo "%_prefix /home/a" >> $RPM_MACROS
#echo "%_libdir /home/a/lib64" >> $RPM_MACROS
#echo "%_mandir /home/a/share/man" >> $RPM_MACROS
#echo "%debug_package %{nil}" >> $RPM_MACROS

rm -rf $TOP_DIR
mkdir -p $TOP_DIR/RPMS
mkdir -p $TOP_DIR/SRPMS
mkdir -p $TOP_DIR/BUILD
mkdir -p $TOP_DIR/SOURCES
mkdir -p $TOP_DIR/SPECS

export fullname=$name-$version

mv trafficserver-*.tar.bz2  $TOP_DIR/SOURCES

export RELEASE=$release
## create spec file from template
sed -e "s/_VERSION_/$version/g" -e "s/_RELEASE_/$release/g"  -e "s/SVN_REVISION/$svn_revision/g" < rpm/$name.spec > $TOP_DIR/SPECS/$name.spec

echo "$TOP_DIR/SPECS/$name.spec"

rpmbuild --ba $TOP_DIR/SPECS/$name.spec

find $TOP_DIR/RPMS -name "*.rpm"  -exec mv {} ./rpm \;

rm -rf $TOP_DIR $RPM_MACROS
if [ -e $RPM_MACROS.bak ]; then
  mv -f $RPM_MACROS.bak $RPM_MACROS
fi

