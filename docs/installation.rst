Installation
============

Dependencies
------------

To build the ``scitokens-cpp`` library, the following dependencies are needed:

* `jwt-cpp <https://github.com/Thalhammer/jwt-cpp>`_ v0.5.0 or later: A header-only C++ library for manipulating JWTs.
* OpenSSL 1.0 or later
* ``sqlite3``
* ``libcurl``
* ``libuuid``

On Ubuntu/Debian systems::

    sudo apt install libcurl4-openssl-dev libssl-dev libsqlite3-dev uuid-dev pkg-config

On CentOS/RHEL systems::

    sudo yum install libcurl-devel openssl-devel sqlite-devel libuuid-devel pkgconfig

Building from Source
--------------------

CMake is used for the build system. To build, from the source directory::

    mkdir build
    cd build
    cmake ..
    make

The library will be built as ``libSciTokens.so`` and the following utilities will be created:

* ``scitokens-verify`` - Verify a SciToken
* ``scitokens-create`` - Create a new SciToken  
* ``scitokens-test`` - Test utility
* ``scitokens-test-access`` - Test access patterns
* ``scitokens-list-access`` - List access permissions

Installation
------------

To install the library and headers::

    sudo make install

This will install:

* Library: ``libSciTokens.so`` to ``/usr/local/lib``
* Headers: ``scitokens.h`` to ``/usr/local/include/scitokens/``
* Utilities: Command-line tools to ``/usr/local/bin``

Package Installation
--------------------

RPM packages are available for CentOS/RHEL systems. Check the project releases page for available packages.

Testing the Installation
------------------------

The easiest way to test ``scitokens-cpp`` is to head to the `SciTokens Demo app <https://demo.scitokens.org>`_
and copy the generated token. Then, from the build directory::

    echo "<your_token_here>" | ./scitokens-verify

Replace the given token above with the fresh one you just generated; using an old token should give an expired
token error. The token must be provided via standard input (stdin).