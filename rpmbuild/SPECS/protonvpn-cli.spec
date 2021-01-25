%define unmangled_name protonvpn-cli
%define version 3.2.1
%define release 1

Summary: ProtonVPN CLI
Name: protonvpn-cli
Version: %{version}
Release: %{release}
Source0: %{unmangled_name}-%{version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{unmangled_name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: Proton Technologies AG <opensource@proton.me>
Url: https://github.com/ProtonVPN
Requires: python3-protonvpn-nm-lib
Requires: python3-dialog


%{?python_disable_dependency_generator}

%description
Official Linux CLI client.


%prep
%setup -n %{unmangled_name}-%{version} -n %{unmangled_name}-%{version}

%build
python3 setup.py build

%install
python3 setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)
