%define unmangled_name protonvpn-cli
%define version 3.4.0
%define release 2

Prefix: %{_prefix}

Name: protonvpn-cli
Version: %{version}
Release: %{release}
Summary: Official ProtonVPN CLI

Group: ProtonVPN
License: GPLv3
Url: https://github.com/ProtonVPN
Vendor: Proton Technologies AG <opensource@proton.me>
Source0: %{unmangled_name}-%{version}.tar.gz
Group: Development/Libraries
BuildArch: noarch
BuildRoot: %{_tmppath}/%{unmangled_name}-%{version}-%{release}-buildroot

BuildRequires: python3-devel
BuildRequires: python3-setuptools
Requires: python3-protonvpn-nm-lib >= 0.5.0, python3-protonvpn-nm-lib < 0.6.0
Requires: python3-dialog

%{?python_disable_dependency_generator}

%description
Official ProtonVPN CLI.


%prep
%setup -n %{unmangled_name}-%{version} -n %{unmangled_name}-%{version}

%build
python3 setup.py build

%install
python3 setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%{python3_sitelib}/protonvpn_cli/
%{python3_sitelib}/protonvpn_cli-%{version}*.egg-info/
%defattr(-,root,root)

%changelog
* Mon Feb 22 2021 Proton Technologies AG <opensource@proton.me> 3.4.0-2
- Add support for protonvpn-nm-lib 0.5.0

* Tue Feb 02 2021 Proton Technologies AG <opensource@proton.me> 3.3.0-1
- Apply server label if it exists

* Wed Jan 27 2021 Proton Technologies AG <opensource@proton.me> 3.2.1-2
- Update .spec file for public release
