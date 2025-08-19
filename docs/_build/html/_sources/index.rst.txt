SciTokens C++ Library Documentation
====================================

SciTokens provide a token format for distributed authorization. The tokens are self-describing, 
can be verified in a distributed fashion (no need to contact the issuer to determine if the token is valid). 
This is convenient for a federated environment where several otherwise-independent storage endpoints 
want to delegate trust for an issuer for managing a storage allocation.

The SciTokens C++ library implements a minimal library for creating and using SciTokens from C or C++.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   installation
   api
   examples

Quick Start
-----------

This library provides both C and C++ APIs for working with SciTokens. The primary interface 
is through the C API defined in ``scitokens.h``.

Key Features:

* Create and sign SciTokens
* Validate and verify SciTokens  
* Generate Access Control Lists (ACLs) from tokens
* Support for multiple token profiles (SciTokens 1.0/2.0, WLCG, AT+JWT)
* Asynchronous token operations

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`