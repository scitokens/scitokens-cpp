
SciTokens C++ Library
=====================

This repository implements a minimal library for creating and using SciTokens from C or C++.

[SciTokens](https://scitokens.org) provide a token format for distributed authorization.  The
tokens are self-describing, can be verified in a distributed fashion (no need to contact the
issuer to determine if the token is valid).  This is convenient for a federated environment where
several otherwise-independent storage endpoints want to delegate trust for an issuer for
managing a storage allocation.

Building
--------

To build the `scitokens-cpp` library, the following dependencies are needed:

   - [jwt-cpp](https://github.com/Thalhammer/jwt-cpp): A header-only C++ library for manipulating
     JWTs.
   - OpenSSL 1.0 or later.
   - `sqlite3`

CMake is used for the build system.  To build, from the source directory:

```
mkdir build
cd build
JWT_CPP_DIR=~/path/to/jwt-cpp cmake ..
make
```

Testing
-------

The easiest way to test `scitokens-cpp` is to head to the [SciTokens Demo app](https://demo.scitokens.org)
and copy the generated token.  Then, from the build directory:

```
./scitokens-verify  eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImtleS1yczI1NiJ9.eyJpc3MiOiJodHRwczovL2RlbW8uc2NpdG9rZW5zLm9yZyIsImV4cCI6MTU0NjQ1NjMwOSwiaWF0IjoxNTQ2NDU1NzA5LCJuYmYiOjE1NDY0NTU3MDksImp0aSI6ImRlYmNkZDRjLTU1MzgtNDkxNS1hY2U2LTgyNTg3NGQwZjEzNyJ9.Vu9TRfDi5WJujeAGl-wP-atvNqh31-gteKqqu_IEcxoCfGYdmoIM3xOOY1GmHcmXfclkrl724ldxBBChsDpcdi_8914N9EGwGVApJLQU0SaPPdtcoCrqvVJE3bD9fs6UKooGwuk_e20ml9g0R4100fTdsD7pkIOABYGTbhxioEb1dP1o-17l2t2kUXpd8KhIyZZjmtmnMdmO5bxaY_V60OOWekwelT8ACK8ao39Ocf_wmUiS0VVX21hD1KqO0bgBU9AsVJ5prAL9ytElr_UB2X5KowPODbj6LPFNhpCwXcoG4w4Gw9VueuxCuIPhlcHBhP83i5LPgtk2YOjygdSahA
```

Replace the given token above with the fresh one you just generated; using the above token should give an expired
token error.


Instructions for Generating a Release
-------------------------------------

SciTokens-cpp includes a submodule, jwt-cpp.  Therefore, to create a release, you have to include the submodule into the release.

    VER=0.3.3 # for example
    git archive --prefix "scitokens-cpp-$VER/" -o "scitokens-cpp-$VER.tar" v$VER
    git submodule update --init
    git submodule foreach --recursive "git archive --prefix=scitokens-cpp-$VER/\$path/ --output=\$sha1.tar HEAD && tar --concatenate --file=$(pwd)/scitokens-cpp-$VER.tar \$sha1.tar && rm \$sha1.tar"
    gzip "scitokens-cpp-$VER.tar"

Before tagging a new release, make sure that the RPM spec file has an updated
version number and an associated changelog entry.
Also, make sure that the ``debian/changelog`` has an entry that matches the
RPM changelog entry.

This package is built on the
[cvmfs-config OpenSUSE Build Service](https://build.opensuse.org/project/show/home:cvmfs:contrib).
In order to support that run `debian/obsupdate.sh` whenever the version
or release number is changed in `rpm/scitokens-cpp.spec`, and commit the
generated `debian/scitokens-cpp.dsc` before tagging the release.

