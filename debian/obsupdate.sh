#!/bin/bash
# update ../packaging/debian/packageName.dsc
# That file is used by build.opensuse.org's Open Build Service
# After the file is updated, it needs to be separately committed to git.

HERE="`dirname $0`"
ME="`basename $0`"
cd $HERE
PKG="`sed -n 's/^Source: //p' control`"
SPECFILE="../rpm/$PKG.spec"
VERSION="$(grep ^Version: $SPECFILE | awk '{print $2}')"
RPMREL="$(grep '^%define release_prefix' $SPECFILE | awk '{print $3}')"
if [ -z "$RPMREL" ]; then
    RPMREL="$(grep '^Release:' $SPECFILE | awk '{print $2}' | cut -d% -f1)"
fi
# if the version is current, increment the release number, else choose 1
DEBREL="`sed -n "s/^Version: ${VERSION}\.${RPMREL}-//p" $PKG.dsc 2>/dev/null`"
if [ -z "$DEBREL" ]; then
    DEBREL=1
else
    let DEBREL+=1
fi
(
echo "# created by $ME, do not edit by hand"
# The following two lines are OBS "magic" to use the tarball from the rpm
echo "Debtransform-Tar: ${PKG}-${VERSION}.tar.gz"
#echo "Debtransform-Files-Tar: "
echo "Format: 3.0"
echo "Version: ${VERSION}.${RPMREL}-${DEBREL}"
echo "Binary: $PKG"
cat control
echo "Files:"
echo "  ffffffffffffffffffffffffffffffff 99999 file1"
echo "  ffffffffffffffffffffffffffffffff 99999 file2"
) > $PKG.dsc
#
echo "Updated $PWD/$PKG.dsc"
