Name: scitokens-cpp
Version: 0.7.0
Release: 1%{?dist}
Summary: C++ Implementation of the SciTokens Library
License: ASL 2.0
URL: https://github.com/scitokens/scitokens-cpp

# Directions to generate a proper release:
# VER=0.3.3 # for example
# git archive --prefix "scitokens-cpp-$VER/" -o "scitokens-cpp-$VER.tar" v$VER
# git submodule update --init
# git submodule foreach --recursive "git archive --prefix=scitokens-cpp-$VER/\$path/ --output=\$sha1.tar HEAD && tar --concatenate --file=$(pwd)/scitokens-cpp-$VER.tar \$sha1.tar && rm \$sha1.tar"
# gzip "scitokens-cpp-$VER.tar"
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
%cmake3
%cmake3_build

%install
%cmake3_install

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
#- Add scitokens-* binaries to the package

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
