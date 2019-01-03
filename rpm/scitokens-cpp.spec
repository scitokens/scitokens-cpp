Name: scitokens-cpp
Version: 0.1.0
Release: 1%{?dist}
Summary: C++ Implementation of the SciTokens Library
License: Apache 2.0
URL: https://github.com/scitokens/scitokens-cpp

# Generated from:
# git_archive_all.py --prefix=scitokens-cpp-0.1.0/ -9 ~/rpmbuild/SOURCES/scitokens-cpp-0.1.0.tar.gz
# Where git_archive_all.py is from https://github.com/Kentzo/git-archive-all.git
Source0: %{name}-%{version}.tar.gz

BuildRequires: gcc-c++
BuildRequires: cmake
BuildRequires: sqlite-devel
BuildRequires: openssl-devel

%description
%{summary}

%package devel
Summary: Header files for the scitokens-cpp public interfaces.

Requires: %{name}-%{version}

%description devel
%{summary}

%prep
%setup -q

%build
mkdir build
cd build
%cmake ..
make 

%install
pushd build
rm -rf $RPM_BUILD_ROOT
echo $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
popd

%clean
rm -rf $RPM_BUILD_ROOT

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
* Thu Jan 03 2019 Brian Bockelman <bbockelm@cse.unl.edu> - 0.1.0-1
- Initial version of the SciTokens C++ RPM.
