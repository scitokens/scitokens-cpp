# created by obsupdate.sh, do not edit by hand
Debtransform-Tar: scitokens-cpp-0.6.3.tar.gz
Format: 3.0
Version: 0.6.3.1-2
Binary: scitokens-cpp
Source: scitokens-cpp
Section: science
Priority: optional
Maintainer: Tim Theisen <tim@cs.wisc.edu>
Build-Depends:
    cmake (>=2.6),
    debhelper (>=9),
    libcurl4-openssl-dev | libcurl4-gnutls-dev,
    libsqlite3-dev,
    libssl-dev,
    pkg-config,
    uuid-dev
Standards-Version: 3.9.8
Homepage: https://github.com/scitokens/scitokens-cpp

Package: libscitokens0
Section: libs
Architecture: any
Multi-Arch: same
Pre-Depends: ${misc:Pre-Depends}
Depends: ${misc:Depends}, ${shlibs:Depends}
Description: C++ Implementation of the SciTokens Library
 SciTokens provide a token format for distributed authorization
 The tokens are self-describing, can be verified in a distributed fashion
 (no need to contact the issuer to determine if the token is valid).
 This is convenient for a federated environment where several
 otherwise-independent storage endpoints want to delegate trust for
 an issuer for managing a storage allocation.

Package: libscitokens-dev
Section: libdevel
Architecture: any
Multi-Arch: same
Depends: libscitokens0 (= ${binary:Version}), ${misc:Depends}
Description: Header files for the libscitokens public interfaces
 SciTokens provide a token format for distributed authorization.
 The tokens are self-describing, can be verified in a distributed fashion
 (no need to contact the issuer to determine if the token is valid).
 This is convenient for a federated environment where several
 otherwise-independent storage endpoints want to delegate trust for
 an issuer for managing a storage allocation.
Files:
  ffffffffffffffffffffffffffffffff 99999 file1
  ffffffffffffffffffffffffffffffff 99999 file2
