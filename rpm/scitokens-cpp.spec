Name: scitokens-cpp
Version: 0.3.2
Release: 1%{?dist}
Summary: C++ Implementation of the SciTokens Library
License: Apache 2.0
URL: https://github.com/scitokens/scitokens-cpp

# Generated from:
# git_archive_all.py --prefix=scitokens-cpp-0.3.2/ --force-submodules -9 scitokens-cpp-0.3.2.tar.gz
# Where git_archive_all.py is from https://github.com/Kentzo/git-archive-all.git
Source0: %{name}-%{version}.tar.gz

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
Summary: Header files for the scitokens-cpp public interfaces.

Requires: %{name} = %{version}

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
    make
}
export -f do_build
%if 0%{?el6}
scl enable devtoolset-8 do_build
%else
do_build
%endif

%install
pushd build
make install DESTDIR=$RPM_BUILD_ROOT
popd

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%files
%{_libdir}/libSciTokens.so*

%files devel
%{_includedir}/scitokens/scitokens.h

%defattr(-,root,root,-)

%changelog
* Thu Jul 25 2019 Mátyás Selmeci <matyas@cs.wisc.edu> - 0.3.2-1.osg
- Merge OSG changes
- Use a newer, still supported version of devtoolset

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
