Name:           luksmith
Version:        0.1.0
Release:        1%{?dist}
Summary:        Org-grade LUKS management for RHEL/Fedora (BitLocker + Intune parity)

License:        MIT
URL:            https://github.com/cdmx-in/luksmith
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

# On rhel-family the systemd-cryptenroll native path (dracut) is the default,
# but clevis is still Required so `--mode clevis` and the suspend path work.
Requires:       python3
Requires:       clevis
Requires:       clevis-luks
Requires:       tpm2-tools
Requires:       systemd
Requires:       cryptsetup
Requires:       openssl

%description
luksmith brings BitLocker-style management to LUKS: TPM2 auto-unlock
enrollment, recovery-key generation, E2E-encrypted escrow to a self-hosted
portal, post-boot verification, and PCR-drift re-enrollment. On RHEL/Fedora
the default TPM bind mode is systemd-cryptenroll (dracut regenerates the
initramfs natively); the clevis mode remains available.

%prep
%autosetup

%install
install -d %{buildroot}/opt/%{name}
install -m 0755 agent/luksmith.py %{buildroot}/opt/%{name}/luksmith.py
install -d %{buildroot}%{_bindir}
printf '#!/bin/sh\nexec python3 /opt/%{name}/luksmith.py "$@"\n' > %{buildroot}%{_bindir}/%{name}
chmod 0755 %{buildroot}%{_bindir}/%{name}
install -d %{buildroot}%{_unitdir}
install -m 0644 packaging/luksmith-verify.service %{buildroot}%{_unitdir}/luksmith-verify.service
install -m 0644 packaging/luksmith-verify.timer %{buildroot}%{_unitdir}/luksmith-verify.timer

%files
/opt/%{name}/luksmith.py
%{_bindir}/%{name}
%{_unitdir}/luksmith-verify.service
%{_unitdir}/luksmith-verify.timer

%post
%systemd_post luksmith-verify.timer

%preun
%systemd_preun luksmith-verify.timer

%postun
%systemd_postun_with_restart luksmith-verify.timer

%changelog
* Sat Jul 19 2026 Codemax IT Solutions <licensing-qa@cdmx.in> - 0.1.0-1
- Initial RPM: agent, luksmith wrapper, post-boot verify timer.
