%undefine __cmake_in_source_build
%undefine __cmake3_in_source_build

Name: scitokens-cpp
Version: 1.3.0
Release: 1%{?dist}
Summary: C++ Implementation of the SciTokens Library
License: ASL 2.0
URL: https://github.com/scitokens/scitokens-cpp

Source0: https://github.com/scitokens/scitokens-cpp/releases/download/v%{version}/%{name}-%{version}.tar.gz

# Scitokens-cpp bundles jwt-cpp, a header only dependency
# Since it doesn't create a library that can be used by others, it seems
# inappropriate to include a "Provides", as jwt-cpp is not provided
# by this package.

BuildRequires: gcc-c++
BuildRequires: make
BuildRequires: cmake3
BuildRequires: sqlite-devel
BuildRequires: openssl-devel
BuildRequires: libcurl-devel
BuildRequires: libuuid-devel
BuildRequires: gtest-devel

%if 0%{?el7}
# needed for ldconfig_scriptlets
BuildRequires: epel-rpm-macros
%endif

%description
%{summary}

%package devel
Summary: Header files for the scitokens-cpp public interfaces

Requires: %{name}%{?_isa} = %{version}

%description devel
%{summary}

%prep
%setup -q

%build
%cmake3 -DSCITOKENS_BUILD_UNITTESTS:BOOL=ON \
        -DSCITOKENS_EXTERNAL_GTEST:BOOL=ON
%cmake3_build

%install
%cmake3_install

%check
# Filter out tests that require network connection
export GTEST_FILTER=-KeycacheTest.RefreshTest:KeycacheTest.RefreshExpiredTest
%ctest3

# Run the ldconfig
%ldconfig_scriptlets

%files
%{_libdir}/libSciTokens.so.0*
%{_bindir}/scitokens-*
%license LICENSE
%doc README.md

%files devel
%{_libdir}/libSciTokens.so
%{_includedir}/scitokens/scitokens.h
%dir %{_includedir}/scitokens

%changelog

* Thu Dec 11 2025 Brian Bockelman <bbockelman@morgridge.org> - 1.3.0-1
- Add scitokens-generate-jwks CLI for key generation.
- Add environment variable-based configuration on library initialization.
- Add per-issuer lock to prevent multiple concurrent queries against issuers without a known key
- Add negative cache for failed issuer lookups (preventing frequent re-queries)
- Add monitoring API for per-issuer validation statistics
- Add optional background thread for JWKS refresh
- Add keycache load, metadata, and delete APIs
- Revert "Fix memory leak in rs256_from_coords" by @djw8605
- Add CTest-based integration test with JWKS server and TLS infrastructure

* Fri Dec 05 2025 Derek Weitzel <dweitzel@unl.edu> - 1.2.0-1
- Fix segfault if the JSON parser cannot parse the JWKS
- Fix float time claims issue and improve error handling
- Fix security issue with malicious issuer handling in error messages
- Improve JWTVerificationException message to include the invalid issuer
- Update usage on verify command to make the TOKENFILE explicit
- Read token for scitokens-verify from stdin
- Set CURLOPT_NOSIGNAL option in SimpleCurlGet to prevent signal interruptions
- Adding asan value to the job name
- Turn off building unit tests by default.
- Add cmake option SCITOKENS_WITH_ASAN which enables memory checking with the address sanitizer.  Also enable this in CI, so that tests fail if they hit a memory leak or other memory problem.
- Fix memory leak in store_public_ec_key
- Fix memory leaks in the unit tests
- Fix memory leak in rs256_from_coords
- Fix memory leak in scitokens_verify

* Mon Feb 24 2025 Derek Weitzel <dweitzel@unl.edu> - 1.1.3-1
- Include cstdint import for jwt library to support newer compilers

* Wed Oct 30 2024 Derek Weitzel <dweitzel@unl.edu> - 1.1.2-1
- Turn off CMAKE unity builds
- Add a mutex around requesting public keys to stop overloading issuers

* Wed Feb 28 2024 Derek Weitzel <dweitzel@unl.edu> - 1.1.1-1
- Improve error handling around the sqlite3 library
- Fix test failures and compiler warnings

* Tue Nov 07 2023 Derek Weitzel <dweitzel@unl.edu> - 1.1.0-1
- Allow the scitokens library user to setup a custom CA file
- Fix typecast errors in scitoken_status_get_*() that caused async queries to fail
- Fix logic error in deserialize_continue() that caused async deserialization to fail

* Thu Jun 15 2023 Derek Weitzel <dweitzel@unl.edu> - 1.0.2-1
- Add support for API-configurable cache home
- Fix enforcer_acl_free logic
- scitokens_internal: catch matching exception type after jwt-cpp update

* Wed Apr 26 2023 Derek Weitzel <dweitzel@unl.edu> - 1.0.1-1
- Fix bug in generate acls which would cause a timeout

* Tue Mar 21 2023 Derek Weitzel <dweitzel@unl.edu> - 1.0.0-1
- Add async API for parsing and verifying tokens
- Add configuration API
- Make nbf claim optional for non-scitokens tokens
- Update to OpenSSL 3.0

* Wed Jun 22 2022 Derek Weitzel <dweitzel@unl.edu> - 0.7.1-1
- Add scitokens-* binaries to the package
- Bug: close sqlite db handle on return

* Fri Feb 18 2022 Derek Weitzel <dweitzel@unl.edu> - 0.7.0-1
- Changes from static analysis
- If only one key is available, do not error on no kid
- Support at+jwt profile

* Fri Sep 03 2021 Dave Dykstra <dwd@fnal.gov> - 0.6.3-1
- Add support for building Debian packages on the OpenSUSE Build System
- Add patch to jwt-cpp to update its picojson dependency in order to
  enable it to compile on Debian 11 and Ubuntu 21.04
- Fix el7 build by requiring epel-rpm-macros

* Thu Aug 26 2021 Dave Dykstra <dwd@fnal.gov> - 0.6.2-2
- Make the build require cmake3 instead of cmake

* Thu Jun 03 2021 Derek Weitzel <dweitzel@unl.edu> - 0.6.2-1
- Correct WLCG compat for condor read permissions

* Thu May 20 2021 Derek Weitzel <dweitzel@unl.edu> - 0.6.1-1
- Fix vector resize for el8+ builds

* Tue May 18 2021 Derek Weitzel <dweitzel@unl.edu> - 0.6.0-2
- Add back paren patch

* Tue Mar 09 2021 Derek Weitzel <dweitzel@unl.edu> - 0.6.0-1
- Fix compilation errors on c++11
- Update to jwt-cpp-0.4.0 vendor
- Change scitoken profile name to match spec, scitoken:2.0

* Wed Jun 24 2020 Derek Weitzel <dweitzel@unl.edu> - 0.5.1-1
- Add storage.modify as write permission

* Fri Feb 28 2020 Derek Weitzel <dweitzel@unl.edu> - 0.5.0-1
- Add API for retrieving string list attributes

* Fri Nov 08 2019 Derek Weitzel <dweitzel@unl.edu> - 0.4.0-1
- Add support for WLCG profile

* Fri Nov 08 2019 Derek Weitzel <dweitzel@unl.edu> - 0.3.5-1
- Fix EC public key handling

* Wed Sep 18 2019 Derek Weitzel <dweitzel@unl.edu> - 0.3.4-1
- Fix bugs for support with IAM

* Thu Aug 01 2019 Derek Weitzel <dweitzel@unl.edu> - 0.3.3-3
- Update the packaging to bring it line with EPEL (fedora) guidelines

* Tue Jul 30 2019 Derek Weitzel <dweitzel@unl.edu> - 0.3.3-2
- Change the Source URL
- Use make_build in the packaging

* Thu Jul 25 2019 Derek Weitzel <dweitzel@unl.edu> - 0.3.3-1
- Merge OSG changes
- Use a newer, still supported version of devtoolset
- Fix bug in verifying EC signed tokens #13

* Thu Jul 25 2019 Derek Weitzel <dweitzel@unl.edu> - 0.3.2-1
- Update RPM to v0.3.2 of the packaging.
- Fix downloading public key bug #12

* Thu Jun 20 2019 Brian Bockelman <brian.bockelman@cern.ch> - 0.3.1-1
- Update RPM to v0.3.1 of the packaging.

* Wed May 29 2019 Mátyás Selmeci <matyas@cs.wisc.edu> - 0.3.0-4
- Use double layer of const for deserialize
  (patch from https://github.com/scitokens/scitokens-cpp/commit/ac0b2f0679488fa91c14ed781268efbcdb69ed3c)

* Mon May 13 2019 Mátyás Selmeci <matyas@cs.wisc.edu> - 0.3.0-3
- Add Force-aud-test-in-the-validator.patch from
  https://github.com/scitokens/scitokens-cpp/pull/8

* Fri May 03 2019 Mátyás Selmeci <matyas@cs.wisc.edu> - 0.3.0-2
- Fix requirements

* Thu May 02 2019 Mátyás Selmeci <matyas@cs.wisc.edu> - 0.3.0-1
- Update to v0.3.0
- Add dependencies on libcurl-devel, libuuid-devel

* Thu Jan 03 2019 Brian Bockelman <bbockelm@cse.unl.edu> - 0.1.0-1
- Initial version of the SciTokens C++ RPM.
