#!/usr/bin/env bash
set -uo pipefail
id="${1:-}"
ok(){ echo "$* compliant"; exit 0; }
bad(){ echo "$*"; exit 1; }
mount_opt(){ local p="$1" opt="$2" o; o="$(findmnt -n -o OPTIONS --target "$p" 2>/dev/null || true)"; echo "mount=$p options=$o"; printf ",%s," "$o" | grep -q ",$opt," || bad "missing_mount_option=$opt"; ok "mount_option=$opt"; }
separate_mount(){ local p="$1" t; t="$(findmnt -n -o TARGET --target "$p" 2>/dev/null || true)"; echo "mount_target=$t required=$p"; test "$t" = "$p" || bad "separate_filesystem_missing=$p"; ok "separate_filesystem=$p"; }
package_absent(){ local p="$1"; if rpm -q "$p" >/dev/null 2>&1; then bad "package=$p installed=true"; fi; ok "package=$p installed=false"; }
package_present(){ local p="$1"; rpm -q "$p" >/dev/null 2>&1 || bad "package=$p installed=false"; v="$(rpm -q "$p")"; ok "package=$v installed=true"; }

case "$id" in
  V-257778)
    if dnf -q updateinfo list --security --available 2>/dev/null | grep -q '^RHSA-'; then bad 'security_updates_available=true'; fi
    ok 'security_updates_available=false'
    ;;
  V-257779)
    test -r /etc/issue || bad 'issue_file=missing'
    grep -Fq 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.' /etc/issue || bad 'dod_banner=first_clause_missing'
    grep -Fq 'At any time, the USG may inspect and seize data stored on this IS.' /etc/issue || bad 'dod_banner=inspection_clause_missing'
    grep -Fq 'Notwithstanding the above, using this IS does not constitute consent' /etc/issue || bad 'dod_banner=privileged_communications_clause_missing'
    ok 'dod_cli_banner=present'
    ;;
  V-257781)
    target="$(systemctl get-default 2>/dev/null || true)"
    echo "default_target=$target"
    test "$target" != graphical.target || bad "default_target=graphical.target"
    ok "default_target_not_graphical=true"
    ;;
  V-257787)
    if grep -RqsE '^[[:space:]]*GRUB2_PASSWORD=.*grub\.pbkdf2' /boot/grub2/user.cfg /boot/efi/EFI/*/user.cfg 2>/dev/null || grep -RqsE '^[[:space:]]*password_pbkdf2[[:space:]]+' /boot/grub2/grub.cfg /boot/efi/EFI/*/grub.cfg 2>/dev/null; then ok 'grub_superuser_password=configured'; fi
    bad 'grub_superuser_password=missing'
    ;;
  V-257788)
    state="$(systemctl is-enabled debug-shell.service 2>/dev/null || true)"
    echo "debug_shell_state=$state"
    case "$state" in masked|disabled|not-found) ok "interactive_boot_shell_disabled=true";; *) bad "interactive_boot_shell_disabled=false";; esac
    ;;
  V-257790)
    p="$(readlink -f /etc/grub2.cfg 2>/dev/null || true)"; test -n "$p" || p=/boot/grub2/grub.cfg
    test -e "$p" || bad "grub_cfg=missing"
    g="$(stat -c %G "$p")"; echo "grub_cfg_group=$g path=$p"; test "$g" = root || bad "grub_cfg_group=$g"; ok "grub_cfg_group=root"
    ;;
  V-257791)
    p="$(readlink -f /etc/grub2.cfg 2>/dev/null || true)"; test -n "$p" || p=/boot/grub2/grub.cfg
    test -e "$p" || bad "grub_cfg=missing"
    u="$(stat -c %U "$p")"; echo "grub_cfg_owner=$u path=$p"; test "$u" = root || bad "grub_cfg_owner=$u"; ok "grub_cfg_owner=root"
    ;;
  V-257792)
    args="$(cat /proc/cmdline 2>/dev/null)"
    echo "kernel_cmdline=$args"
    printf "%s\n" "$args" | grep -qw "vsyscall=none" || bad "kernel_parameter_missing=vsyscall=none"
    ok "kernel_parameter=vsyscall=none"
    ;;
  V-257793)
    args="$(cat /proc/cmdline 2>/dev/null)"
    echo "kernel_cmdline=$args"
    printf "%s\n" "$args" | grep -qw "init_on_alloc=1" || bad "kernel_parameter_missing=init_on_alloc=1"
    ok "kernel_parameter=init_on_alloc=1"
    ;;
  V-257794)
    args="$(cat /proc/cmdline 2>/dev/null)"
    echo "kernel_cmdline=$args"
    printf "%s\n" "$args" | grep -qw "init_on_free=1" || bad "kernel_parameter_missing=init_on_free=1"
    ok "kernel_parameter=init_on_free=1"
    ;;
  V-257796)
    args="$(cat /proc/cmdline 2>/dev/null)"
    echo "kernel_cmdline=$args"
    printf "%s\n" "$args" | grep -qw "audit=1" || bad "kernel_parameter_missing=audit=1"
    ok "kernel_parameter=audit=1"
    ;;
  V-257795)
    args="$(cat /proc/cmdline 2>/dev/null)"
    echo "kernel_cmdline=$args"
    ! printf "%s\n" "$args" | grep -qw "mitigations=off" || bad "processor_mitigations=off"
    ok "processor_mitigations_not_disabled=true"
    ;;
  V-257812)
    v="$(grep -RhsE "^[[:space:]]*ProcessSizeMax[[:space:]]*=" /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d "[:space:]")"
    echo "ProcessSizeMax=$v"; test "$v" = 0 || bad "ProcessSizeMax=$v"; ok "ProcessSizeMax=0"
    ;;
  V-257813)
    v="$(grep -RhsE "^[[:space:]]*Storage[[:space:]]*=" /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d "[:space:]")"
    echo "Storage=$v"; test "$v" = none || bad "Storage=$v"; ok "Storage=none"
    ;;
  V-257814)
    line="$(grep -RhsE "^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0([[:space:]]|$)" /etc/security/limits.conf /etc/security/limits.d 2>/dev/null | head -n1)"
    test -n "$line" || bad "hard_core_limit=missing"; ok "hard_core_limit=0"
    ;;
  V-257815)
    state="$(systemctl is-enabled systemd-coredump.socket 2>/dev/null || true)"
    echo "systemd_coredump_socket=$state"; case "$state" in masked|disabled|not-found) ok "systemd_coredump_disabled=true";; *) bad "systemd_coredump_disabled=false";; esac
    ;;
  V-257817)
    grep -qw nx /proc/cpuinfo 2>/dev/null || bad "cpu_nx_feature=missing"; ok "cpu_nx_feature=present"
    ;;
  V-257819)
    badpkgs="$(rpm -qa --qf "%{NAME} %{SIGPGP:pgpsig}\n" 2>/dev/null | awk '/\(none\)/{print $1}' | head -n20)"
    echo "unsigned_packages=${badpkgs:-none}"; test -z "$badpkgs" || bad "unsigned_packages_found=true"; ok "vendor_package_signatures=present"
    ;;
  V-257823)
    mismatch="$(rpm -Va 2>/dev/null | awk 'length($1)>=8 && substr($1,3,1)=="5"{print $NF}' | head -n20)"
    echo "digest_mismatches=${mismatch:-none}"; test -z "$mismatch" || bad "rpm_digest_mismatch=true"; ok "rpm_file_digests_match=true"
    ;;
  V-257824)
    old="$(dnf repoquery --installonly --latest-limit=-2 -q 2>/dev/null | head -n20 || true)"
    echo "obsolete_installonly_packages=${old:-none}"; test -z "$old" || bad "obsolete_installonly_packages_found=true"; ok "obsolete_installonly_packages=none"
    ;;
  V-257830)
    enabled="$(dnf -q repolist --enabled 2>/dev/null | awk 'tolower($0) ~ /(^|[[:space:]])epel([[:space:]-]|$)/{print}' | head -n20)"
    echo "enabled_epel_repositories=${enabled:-none}"; test -z "$enabled" || bad "epel_enabled=true"; ok "epel_enabled=false"
    ;;
  V-257837)
    package_absent gdm
    ;;
  V-257843)
    separate_mount "/home"
    ;;
  V-257844)
    separate_mount "/tmp"
    ;;
  V-257845)
    separate_mount "/var"
    ;;
  V-257846)
    separate_mount "/var/log"
    ;;
  V-257847)
    separate_mount "/var/log/audit"
    ;;
  V-257848)
    separate_mount "/var/tmp"
    ;;
  V-257849)
    if ! rpm -q autofs >/dev/null 2>&1; then ok "autofs_installed=false"; fi
    state="$(systemctl is-enabled autofs.service 2>/dev/null || true)"; echo "autofs_state=$state"; test "$state" != enabled || bad "autofs_state=enabled"; ok "autofs_disabled=true"
    ;;
  V-257850)
    mount_opt "/home" "nodev"
    ;;
  V-257851)
    mount_opt "/home" "nosuid"
    ;;
  V-257852)
    mount_opt "/home" "noexec"
    ;;
  V-257860)
    mount_opt "/boot" "nodev"
    ;;
  V-257861)
    mount_opt "/boot" "nosuid"
    ;;
  V-257862)
    mount_opt "/boot/efi" "nosuid"
    ;;
  V-257863)
    mount_opt "/dev/shm" "nodev"
    ;;
  V-257864)
    mount_opt "/dev/shm" "noexec"
    ;;
  V-257865)
    mount_opt "/dev/shm" "nosuid"
    ;;
  V-257866)
    mount_opt "/tmp" "nodev"
    ;;
  V-257867)
    mount_opt "/tmp" "noexec"
    ;;
  V-257868)
    mount_opt "/tmp" "nosuid"
    ;;
  V-257869)
    mount_opt "/var" "nodev"
    ;;
  V-257870)
    mount_opt "/var/log" "nodev"
    ;;
  V-257871)
    mount_opt "/var/log" "noexec"
    ;;
  V-257872)
    mount_opt "/var/log" "nosuid"
    ;;
  V-257873)
    mount_opt "/var/log/audit" "nodev"
    ;;
  V-257874)
    mount_opt "/var/log/audit" "noexec"
    ;;
  V-257875)
    mount_opt "/var/log/audit" "nosuid"
    ;;
  V-257876)
    mount_opt "/var/tmp" "nodev"
    ;;
  V-257877)
    mount_opt "/var/tmp" "noexec"
    ;;
  V-257878)
    mount_opt "/var/tmp" "nosuid"
    ;;
  V-257854)
    badflag=0
    while read -r target opts; do test -n "$target" || continue; echo "nfs_mount=$target options=$opts"; printf ",%s," "$opts" | grep -q ",nodev," || badflag=1; done < <(findmnt -rn -t nfs,nfs4 -o TARGET,OPTIONS 2>/dev/null)
    test "$badflag" -eq 0 || bad "nfs_nodev=missing"; ok "nfs_nodev=compliant"
    ;;
  V-257855)
    badflag=0
    while read -r target opts; do test -n "$target" || continue; echo "nfs_mount=$target options=$opts"; printf ",%s," "$opts" | grep -q ",noexec," || badflag=1; done < <(findmnt -rn -t nfs,nfs4 -o TARGET,OPTIONS 2>/dev/null)
    test "$badflag" -eq 0 || bad "nfs_noexec=missing"; ok "nfs_noexec=compliant"
    ;;
  V-257856)
    badflag=0
    while read -r target opts; do test -n "$target" || continue; echo "nfs_mount=$target options=$opts"; printf ",%s," "$opts" | grep -q ",nosuid," || badflag=1; done < <(findmnt -rn -t nfs,nfs4 -o TARGET,OPTIONS 2>/dev/null)
    test "$badflag" -eq 0 || bad "nfs_nosuid=missing"; ok "nfs_nosuid=compliant"
    ;;
  V-257857)
    badflag=0
    while read -r name rm mnt; do test "$rm" = 1 || continue; test -n "$mnt" || continue; opts="$(findmnt -n -o OPTIONS --target "$mnt" 2>/dev/null || true)"; echo "removable=$name mount=$mnt options=$opts"; printf ",%s," "$opts" | grep -q ",noexec," || badflag=1; done < <(lsblk -nrpo NAME,RM,MOUNTPOINT 2>/dev/null)
    test "$badflag" -eq 0 || bad "removable_noexec=missing"; ok "removable_noexec=compliant"
    ;;
  V-257858)
    badflag=0
    while read -r name rm mnt; do test "$rm" = 1 || continue; test -n "$mnt" || continue; opts="$(findmnt -n -o OPTIONS --target "$mnt" 2>/dev/null || true)"; echo "removable=$name mount=$mnt options=$opts"; printf ",%s," "$opts" | grep -q ",nodev," || badflag=1; done < <(lsblk -nrpo NAME,RM,MOUNTPOINT 2>/dev/null)
    test "$badflag" -eq 0 || bad "removable_nodev=missing"; ok "removable_nodev=compliant"
    ;;
  V-257859)
    badflag=0
    while read -r name rm mnt; do test "$rm" = 1 || continue; test -n "$mnt" || continue; opts="$(findmnt -n -o OPTIONS --target "$mnt" 2>/dev/null || true)"; echo "removable=$name mount=$mnt options=$opts"; printf ",%s," "$opts" | grep -q ",nosuid," || badflag=1; done < <(lsblk -nrpo NAME,RM,MOUNTPOINT 2>/dev/null)
    test "$badflag" -eq 0 || bad "removable_nosuid=missing"; ok "removable_nosuid=compliant"
    ;;
  V-257880)
    loaded="$(lsmod | awk '$1=="cramfs"{print $1}')"
    rule="$(grep -RhsE "^[[:space:]]*install[[:space:]]+cramfs[[:space:]]+/bin/(true|false)" /etc/modprobe.d 2>/dev/null | head -n1)"
    echo "cramfs_loaded=${loaded:-false} install_rule=${rule:-missing}"; test -z "$loaded" || bad "cramfs_loaded=true"; test -n "$rule" || bad "cramfs_install_rule=missing"; ok "cramfs_disabled=true"
    ;;
  V-257881)
    badflag=0
    while read -r target opts; do test "$target" = / && continue; echo "local_mount=$target options=$opts"; printf ",%s," "$opts" | grep -q ",nodev," || badflag=1; done < <(findmnt -rn -t ext2,ext3,ext4,xfs,btrfs -o TARGET,OPTIONS 2>/dev/null)
    test "$badflag" -eq 0 || bad "nonroot_local_mount_nodev=missing"; ok "nonroot_local_mounts_nodev=true"
    ;;
  V-257882)
    found="$(find /bin /sbin /usr/bin /usr/sbin -xdev -type f -perm /022 -print 2>/dev/null | head -n20)"
    echo "writable_system_commands=${found:-none}"; test -z "$found" || bad "system_command_mode_violation=true"; ok "system_command_modes=compliant"
    ;;
  V-257883)
    found="$(find /lib /lib64 /usr/lib /usr/lib64 -xdev -type d -perm /022 -print 2>/dev/null | head -n20)"
    echo "writable_library_dirs=${found:-none}"; test -z "$found" || bad "library_dir_mode_violation=true"; ok "library_directory_modes=compliant"
    ;;
  V-257884)
    found="$(find /lib /lib64 /usr/lib /usr/lib64 -xdev -type f -perm /022 -print 2>/dev/null | head -n20)"
    echo "writable_library_files=${found:-none}"; test -z "$found" || bad "library_file_mode_violation=true"; ok "library_file_modes=compliant"
    ;;
  V-257889)
    badentry=""
    while IFS=: read -r u _ uid _ _ home shell; do test "$uid" -ge 1000 || continue; case "$shell" in */nologin|*/false) continue;; esac; test -d "$home" || continue; found="$(find "$home" -maxdepth 1 -type f -name ".*" -perm /0037 -print 2>/dev/null | head -n1)"; test -z "$found" || { badentry="$u:$found"; break; }; done < /etc/passwd
    echo "insecure_init_file=${badentry:-none}"; test -z "$badentry" || bad "interactive_init_mode_violation=true"; ok "interactive_init_modes=compliant"
    ;;
  V-257890)
    badentry=""
    while IFS=: read -r u _ uid _ _ home shell; do test "$uid" -ge 1000 || continue; case "$shell" in */nologin|*/false) continue;; esac; test -d "$home" || continue; mode="$(stat -c %a "$home")"; test $((8#$mode & 8#0027)) -eq 0 || { badentry="$u:$home:$mode"; break; }; done < /etc/passwd
    echo "insecure_home=${badentry:-none}"; test -z "$badentry" || bad "home_mode_violation=true"; ok "home_directory_modes=compliant"
    ;;
  V-257918)
    found="$(find /bin /sbin /usr/bin /usr/sbin -xdev -type f ! -user root -print 2>/dev/null | head -n20)"
    echo "nonroot_system_commands=${found:-none}"; test -z "$found" || bad "system_command_owner_violation=true"; ok "system_command_ownership=compliant"
    ;;
  V-257919)
    badentry=""
    while IFS= read -r f; do gid="$(stat -c %g "$f")"; test "$gid" -lt 1000 || { badentry="$f gid=$gid"; break; }; done < <(find /bin /sbin /usr/bin /usr/sbin -xdev -type f -print 2>/dev/null)
    echo "invalid_system_command_group=${badentry:-none}"; test -z "$badentry" || bad "system_command_group_violation=true"; ok "system_command_group_ownership=compliant"
    ;;
  V-257920)
    found="$(find /lib /lib64 /usr/lib /usr/lib64 -xdev -type f ! -user root -print 2>/dev/null | head -n20)"
    echo "nonroot_library_files=${found:-none}"; test -z "$found" || bad "library_file_owner_violation=true"; ok "library_file_ownership=compliant"
    ;;
  V-257921)
    badentry=""
    while IFS= read -r f; do gid="$(stat -c %g "$f")"; test "$gid" -lt 1000 || { badentry="$f gid=$gid"; break; }; done < <(find /lib /lib64 /usr/lib /usr/lib64 -xdev -type f -print 2>/dev/null)
    echo "invalid_library_file_group=${badentry:-none}"; test -z "$badentry" || bad "library_file_group_violation=true"; ok "library_file_group_ownership=compliant"
    ;;
  V-257922)
    found="$(find /lib /lib64 /usr/lib /usr/lib64 -xdev -type d ! -user root -print 2>/dev/null | head -n20)"
    echo "nonroot_library_dirs=${found:-none}"; test -z "$found" || bad "library_dir_owner_violation=true"; ok "library_directory_ownership=compliant"
    ;;
  V-257923)
    badentry=""
    while IFS= read -r f; do gid="$(stat -c %g "$f")"; test "$gid" -lt 1000 || { badentry="$f gid=$gid"; break; }; done < <(find /lib /lib64 /usr/lib /usr/lib64 -xdev -type d -print 2>/dev/null)
    echo "invalid_library_dir_group=${badentry:-none}"; test -z "$badentry" || bad "library_dir_group_violation=true"; ok "library_directory_group_ownership=compliant"
    ;;
  V-257928)
    badentry=""
    while IFS= read -r d; do uid="$(stat -c %u "$d")"; test "$uid" -lt 1000 || { badentry="$d uid=$uid"; break; }; done < <(find / -xdev -type d -perm -0002 -print 2>/dev/null)
    echo "world_writable_dir_invalid_owner=${badentry:-none}"; test -z "$badentry" || bad "world_writable_directory_owner_violation=true"; ok "world_writable_directory_owners=compliant"
    ;;
  V-257929)
    found="$(find / -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | head -n20)"
    echo "world_writable_without_sticky=${found:-none}"; test -z "$found" || bad "sticky_bit_missing=true"; ok "public_directory_sticky_bit=compliant"
    ;;
  V-257930)
    found="$(find / -xdev -nogroup -print 2>/dev/null | head -n20)"
    echo "invalid_group_objects=${found:-none}"; test -z "$found" || bad "invalid_group_objects_found=true"; ok "all_objects_have_valid_group=true"
    ;;
  V-257931)
    found="$(find / -xdev -nouser -print 2>/dev/null | head -n20)"
    echo "invalid_owner_objects=${found:-none}"; test -z "$found" || bad "invalid_owner_objects_found=true"; ok "all_objects_have_valid_owner=true"
    ;;
  V-257932)
    command -v restorecon >/dev/null 2>&1 || bad "restorecon=missing"
    found="$(restorecon -nRv /dev 2>&1 | head -n20)"
    echo "device_label_drift=${found:-none}"; test -z "$found" || bad "device_selinux_label_drift=true"; ok "device_selinux_labels=compliant"
    ;;
  V-257934)
    mode="$(stat -c %a /etc/shadow)"; echo "shadow_mode=$mode"; test "$mode" = 0 || bad "shadow_mode=$mode"; ok "shadow_mode=0000"
    ;;
  V-257937)
    state="$(firewall-cmd --state 2>/dev/null || true)"; echo "firewalld_state=$state"; test "$state" = running || bad "firewalld_state=$state"
    zones="$(firewall-cmd --get-active-zones 2>/dev/null | awk 'NF==1{print $1}')"; test -n "$zones" || bad "active_zones=none"
    for z in $zones; do t="$(firewall-cmd --zone="$z" --get-target 2>/dev/null)"; echo "zone=$z target=$t"; test "$t" = DROP || bad "zone=$z target=$t"; done
    ok "firewall_default_deny=true"
    ;;
  V-257939)
    v="$(awk -F= 'tolower($1) ~ /^[[:space:]]*firewallbackend[[:space:]]*$/{gsub(/[[:space:]]/,"",$2); print tolower($2)}' /etc/firewalld/firewalld.conf 2>/dev/null | tail -n1)"
    test -n "$v" || v=nftables
    echo "FirewallBackend=$v"; test "$v" = nftables || bad "FirewallBackend=$v"; ok "firewall_backend=nftables"
    ;;
  V-257941)
    found="$(ip -o link show 2>/dev/null | grep -E "<[^>]*PROMISC[^>]*>" | head -n20)"
    echo "promiscuous_interfaces=${found:-none}"; test -z "$found" || bad "promiscuous_mode=true"; ok "promiscuous_mode=false"
    ;;
  V-257945)
    src="$(chronyc -n sources 2>/dev/null | awk '$1 ~ /^\^\*/{print $2; exit}')"
    echo "chrony_selected_source=${src:-none}"; test -n "$src" || bad "chrony_synchronized=false"; ok "chrony_synchronized=true"
    ;;
  V-257946)
    found="$(grep -RhsE "^[[:space:]]*allow([[:space:]]|$)" /etc/chrony.conf /etc/chrony.d 2>/dev/null | head -n20)"
    echo "chrony_allow_directives=${found:-none}"; test -z "$found" || bad "chrony_server_mode=true"; ok "chrony_server_mode_disabled=true"
    ;;
  V-257947)
    found="$(grep -RhsE "^[[:space:]]*cmdallow([[:space:]]|$)" /etc/chrony.conf /etc/chrony.d 2>/dev/null | head -n20)"
    echo "chrony_cmdallow=${found:-none}"; test -z "$found" || bad "chrony_network_management_enabled=true"; ok "chrony_network_management_restricted=true"
    ;;
  V-257948)
    n="$(grep -Ec "^[[:space:]]*nameserver[[:space:]]+" /etc/resolv.conf 2>/dev/null || true)"
    echo "nameserver_count=$n"; test "$n" -ge 2 || bad "nameserver_count=$n"; ok "dns_nameservers_at_least_two=true"
    ;;
  V-257949)
    v="$(NetworkManager --print-config 2>/dev/null | awk -F= '/^[[:space:]]*dns[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}')"
    echo "NetworkManager_dns=${v:-missing}"
    case "$v" in default|none|systemd-resolved) ok "networkmanager_dns_mode=$v";; *) bad "networkmanager_dns_mode=${v:-missing}";; esac
    ;;
  V-257950)
    state="$(systemctl is-active ipsec 2>/dev/null || true)"
    echo "ipsec_state=$state"; test "$state" != active || bad "ipsec_state=active requires_approved_exception"; ok "unauthorized_ip_tunnels=none"
    ;;
  V-257951)
    if ! rpm -q postfix >/dev/null 2>&1; then ok "postfix_installed=false"; fi
    v="$(postconf -h smtpd_client_restrictions 2>/dev/null | tr -d "[:space:]")"
    echo "smtpd_client_restrictions=$v"; test "$v" = permit_mynetworks,reject || bad "smtpd_client_restrictions=$v"; ok "postfix_relay_restrictions=compliant"
    ;;
  V-257953)
    line="$(grep -E "^[[:space:]]*postmaster:[[:space:]]*root[[:space:]]*$" /etc/aliases 2>/dev/null | head -n1)"
    echo "postmaster_alias=${line:-missing}"; test -n "$line" || bad "postmaster_alias=missing"; ok "postmaster_to_root_alias=present"
    ;;
  V-257981)
    cfg="$(/usr/sbin/sshd -T 2>/dev/null | awk '$1=="banner"{print $2; exit}')"
    echo "sshd_banner=${cfg:-none}"; test -n "$cfg" && test "$cfg" != none || bad "sshd_banner=none"; test -r "$cfg" || bad "sshd_banner_file=missing"
    grep -Fq "You are accessing a U.S. Government (USG) Information System (IS)" "$cfg" || bad "sshd_banner_text=invalid"; ok "sshd_banner=compliant"
    ;;
  *) echo "unsupported_check=$id"; exit 64 ;;
esac
