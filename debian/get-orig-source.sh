# Generate a source tarball including submodules
if [ -z "${1}" ] ; then
    echo No tag or branch given
    exit 1
fi
ver=${1}
# Remove initial v from tag name for use in filenames
if [ ${ver:0:1} = 'v' ] ; then
    fver=${ver:1}
else
    fver=${ver}
fi
if [ -r scitokens-cpp_${fver}.orig.tar.gz ] ; then
    echo scitokens-cpp_${fver}.orig.tar.gz already exists
    exit 1
fi
curdir=$(pwd)
tdir=$(mktemp -d)
cd ${tdir}
git clone https://github.com/scitokens/scitokens-cpp.git
cd scitokens-cpp
git checkout ${ver}
if [ $? -ne 0 ] ; then
    echo No such tag or branch: ${ver}
    cd ${curdir}
    rm -rf ${tdir}
    exit 1
fi
git archive --prefix scitokens-cpp_${fver}/ ${ver} -o ${tdir}/scitokens-cpp_${fver}.orig.tar
git submodule update --init
git submodule foreach --recursive "git archive --prefix scitokens-cpp_${fver}/\$path/ \$sha1 -o ${tdir}/\$sha1.tar ; tar -A -f ${tdir}/scitokens-cpp_${fver}.orig.tar ${tdir}/\$sha1.tar ; rm ${tdir}/\$sha1.tar"
cd ${tdir}
gzip scitokens-cpp_${fver}.orig.tar
mv scitokens-cpp_${fver}.orig.tar.gz ${curdir}
cd ${curdir}
rm -rf ${tdir}
