Name: scitokens-cpp
Version: 0.3.5
Release: 1%{?dist}
Summary: C++ Implementation of the SciTokens Library
License: ASL 2.0
URL: https://github.com/scitokens/scitokens-cpp

# Directions to generate a proper release:
# git archive --prefix "scitokens-cpp-0.3.3/" -o "scitokens-cpp-0.3.3.tar" v0.3.3
# git submodule update --init
# git submodule foreach --recursive "git archive --prefix=scitokens-cpp-0.3.3/\$path/ --output=\$sha1.tar HEAD && tar --concatenate --file=$(pwd)/scitokens-cpp-0.3.3.tar \$sha1.tar && rm \$sha1.tar"
# gzip "scitokens-cpp-0.3.3.tar"
Source0: https://github.com/scitokens/scitokens-cpp/releases/download/v%{version}/%{name}-%{version}.tar.gz

# Scitokens-cpp bundles jwt-cpp, a header only dependency
# Since it doesn't create a library that can be used by others, it seems
# inappropriate to include a "Provides", as jwt-cpp is not provided
# by this package.

BuildRequires: gcc-c++
BuildRequires: cmake
BuildRequires: sqlite-devel
BuildRequires: openssl-devel
BuildRequires: libcurl-devel
BuildRequires: libuuid-devel

# Needed for C++11
%if 0%{?el6}
BuildRequires: devtoolset-8-toolchain
BuildRequires: scl-utils
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
do_build () {
    set -ex
    mkdir build
    cd build
    %cmake ..
    %make_build
}
export -f do_build
%if 0%{?el6}
scl enable devtoolset-8 do_build
%else
do_build
%endif

%install
%make_install -C build

# Run the ldconfig
%ldconfig_scriptlets

%files
%{_libdir}/libSciTokens.so.0*
%license LICENSE
%doc README.md

%files devel
%{_libdir}/libSciTokens.so
%{_includedir}/scitokens/scitokens.h
%dir %{_includedir}/scitokens

%changelog
* Fri Nov 08 2019 Derek Weitzel <dweitzel@unl.edu> - 0.3.5-1
- Fix EC public key handling

* Thu Sep 18 2019 Derek Weitzel <dweitzel@unl.edu> - 0.3.4-1
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
