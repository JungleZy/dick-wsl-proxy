#!/bin/sh
# Fixed read-only probe. Values cross the boundary as hex, never as shell code.
LC_ALL=C
export LC_ALL
for tool in awk cat od tr readlink stat sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || exit 70
done
emit() {
    printf '%s\t%s\t' "$1" "$2"
    printf '%s' "$3" | od -An -v -tx1 | tr -d ' \n'
    printf '\n'
}
observe() {
    key=$1
    shift
    if value=$("$@" 2>&1); then
        emit "$key" ok "$value"
        case "$key" in baseline.*)
            digest=$(printf '%s' "$value" | sha256sum)
            emit "fingerprint.${key#baseline.}" ok "${digest%% *}"
        esac
    else emit "$key" failed "$value"; fi
}
read_cgroup() {
    awk 'BEGIN { n=0 } /^0::/ { sub(/^0::/, ""); print; n++ } END { if (n != 1) exit 1 }' "$1"
}
workload_tree() {
    failed=0
    for entry in /proc/[0-9]*; do
        [ -d "$entry" ] || continue
        if path=$(read_cgroup "$entry/cgroup" 2>/dev/null); then
            # WSL's own /init processes may live above the distro cgroup root.
            # Identify the actual executable inode, never a comm name or fixed PID.
            case "$path" in /..|/../*)
                if [ "$entry/exe" -ef /init ]; then
                    printf 'wsl-init\t%s\t%s\n' "${entry##*/}" "$path"
                    continue
                fi ;;
            esac
            printf '%s\t%s\n' "${entry##*/}" "$path"
        elif [ -d "$entry" ]; then
            failed=1
        fi
    done
    return "$failed"
}
emit protocol ok wsl-proxy-m0-v1
emit identity.guest_name ok "${WSL_DISTRO_NAME-}"
observe identity.uid id -u
observe identity.status cat "/proc/$$/status"
observe identity.boot_id cat /proc/sys/kernel/random/boot_id
observe identity.pid1_comm cat /proc/1/comm
observe identity.pid1_cgroup read_cgroup /proc/1/cgroup
observe identity.self_cgroup read_cgroup /proc/self/cgroup
observe identity.cgroup_ns readlink /proc/self/ns/cgroup
observe identity.pid1_cgroup_ns readlink /proc/1/ns/cgroup
observe identity.pid_ns readlink /proc/self/ns/pid
observe identity.pid1_pid_ns readlink /proc/1/ns/pid
observe identity.mountinfo cat /proc/self/mountinfo
if processes=$(workload_tree); then
    emit identity.outside_wsl_init ok "$(printf '%s\n' "$processes" | awk -F '\t' '$1 == "wsl-init" {print $2 "\t" $3}')"
    workloads=$(printf '%s\n' "$processes" | awk -F '\t' '$1 != "wsl-init"')
    emit identity.workloads ok "$workloads"
    # Each path is component-normalized by procfs; find their common ancestor.
    candidate=$(printf '%s\n' "$workloads" | awk -F '\t' '
        NR == 1 { root=$2; next }
        { while (root != "/" && $2 != root && index($2, root "/") != 1) {
            sub(/\/[^\/]*$/, "", root); if (root == "") root="/"
        } }
        END { print root }')
    emit identity.cgroup_path ok "$candidate"
    mountpoint=$(awk '$0 ~ / - cgroup2 / { n++; point=$5 } END { if (n == 1) print point; else exit 1 }' /proc/self/mountinfo)
    mountroot=$(awk '$0 ~ / - cgroup2 / { n++; root=$4 } END { if (n == 1) print root; else exit 1 }' /proc/self/mountinfo)
    relative=
    case "$mountroot" in
        /) relative=$candidate ;;
        '') ;;
        *) case "$candidate" in
            "$mountroot") relative=/ ;;
            "$mountroot"/*) relative=${candidate#"$mountroot"} ;;
        esac ;;
    esac
    if [ -n "$candidate" ] && [ -n "$mountpoint" ] && [ -n "$relative" ]; then
        # Reject escaped mount paths rather than guessing mountinfo decoding.
        case "$mountpoint$mountroot$relative" in
        *\\*|*/../*|*/..|*/./*|*/.) emit identity.cgroup_root failed 'escaped or non-normalized cgroup path unsupported' ;;
        *) observe identity.cgroup_root stat -Lc '%d:%i' "$mountpoint$relative" ;;
        esac
    else
        emit identity.cgroup_root failed 'no unique cgroup2 mount or no workload subtree'
    fi
else
    emit identity.workloads failed "$workloads"
    emit identity.cgroup_path failed 'workload tree incomplete'
    emit identity.cgroup_root failed 'workload tree incomplete'
fi
if command -v wslinfo >/dev/null 2>&1; then
    observe identity.networking_mode wslinfo --networking-mode
elif [ -x /usr/lib/wsl/wslinfo ]; then
    observe identity.networking_mode /usr/lib/wsl/wslinfo --networking-mode
else
    emit identity.networking_mode failed 'wslinfo absent'
fi
observe baseline.resolv_conf cat /etc/resolv.conf
observe baseline.resolv_target readlink -f /etc/resolv.conf
observe baseline.nsswitch cat /etc/nsswitch.conf
observe baseline.hosts cat /etc/hosts
observe baseline.links ip -details -oneline link show
observe baseline.addresses_v4 ip -4 -oneline address show
observe baseline.addresses_v6 ip -6 -oneline address show
observe baseline.routes_v4 ip -4 -oneline route show table all
observe baseline.routes_v6 ip -6 -oneline route show table all
observe baseline.rules_v4 ip -4 -oneline rule show
observe baseline.rules_v6 ip -6 -oneline rule show
observe network.default_routes ip -4 -oneline route show default
if [ -x /usr/sbin/ip ]; then
    gateway=$(ip -4 route show default | awk '$1 == "default" && $2 == "via" {print $3; exit}')
    if [ -n "$gateway" ]; then observe network.gateway_route ip -4 route get "$gateway"; fi
fi
if command -v resolvectl >/dev/null 2>&1; then
    observe baseline.resolved_dns resolvectl dns
    observe baseline.resolved_domains resolvectl domain
    observe baseline.resolved_default_route resolvectl default-route
elif [ -d /run/systemd/resolve ]; then
    emit baseline.resolved_dns failed 'systemd-resolved state exists but resolvectl absent'
else
    emit baseline.resolved_dns not_applicable 'systemd-resolved state directory absent'
fi
observe tooling.iptables_legacy iptables-legacy --version
observe tooling.ip6tables_legacy ip6tables-legacy --version
firewall_save() {
    # No table argument: do not ask xtables to load any missing table/module.
    saved=$("$1" 2>&1) || { printf '%s' "$saved"; return 1; }
    printf '%s\n' "$saved" | awk '!/^#/ { if (/^:/) sub(/\[[0-9]+:[0-9]+\]$/, "[COUNTERS]"); if (length) print }'
}
if [ -r /proc/net/ip_tables_names ]; then
    observe baseline.iptables_legacy firewall_save iptables-legacy-save
else
    emit baseline.iptables_legacy failed 'legacy IPv4 tables not present; no query that might load them'
fi
if [ -r /proc/net/ip6_tables_names ]; then
    observe baseline.ip6tables_legacy firewall_save ip6tables-legacy-save
else
    emit baseline.ip6tables_legacy failed 'legacy IPv6 tables not present; no query that might load them'
fi
if [ -d /sys/module/nf_tables ]; then
    observe baseline.iptables_nft firewall_save iptables-nft-save
    observe baseline.ip6tables_nft firewall_save ip6tables-nft-save
    observe baseline.nft nft --stateless list ruleset
else
    emit baseline.iptables_nft not_applicable 'nf_tables not observed; no query that might load it'
    emit baseline.ip6tables_nft not_applicable 'nf_tables not observed; no query that might load it'
    emit baseline.nft not_applicable 'nf_tables not observed; no query that might load it'
fi
observe kernel.release cat /proc/sys/kernel/osrelease
observe kernel.matches_v4 cat /proc/net/ip_tables_matches
observe kernel.targets_v4 cat /proc/net/ip_tables_targets
observe kernel.tables_v4 cat /proc/net/ip_tables_names
observe kernel.matches_v6 cat /proc/net/ip6_tables_matches
observe kernel.targets_v6 cat /proc/net/ip6_tables_targets
observe kernel.tables_v6 cat /proc/net/ip6_tables_names
for module in xt_cgroup nf_conntrack nf_nat iptable_nat ip6table_nat; do
    if [ -d "/sys/module/$module" ]; then emit "kernel.module.$module" ok present
    else emit "kernel.module.$module" failed 'not observed in /sys/module'; fi
done
# Check procfs readability without ever emitting connection tuples.
conntrack_readable() {
    if [ -e /proc/net/nf_conntrack ]; then
        awk 'NR == 1 { print "readable (sample suppressed)"; exit } END { if (NR == 0) print "readable empty table" }' /proc/net/nf_conntrack
    elif [ -e /proc/net/ip_conntrack ]; then
        awk 'NR == 1 { print "readable (sample suppressed)"; exit } END { if (NR == 0) print "readable empty table" }' /proc/net/ip_conntrack
    else
        printf '%s' 'conntrack procfs reader unavailable; netlink tuple reads not attempted'
        return 1
    fi
}
observe kernel.conntrack_readable conntrack_readable
observe tooling.conntrack conntrack --version
if [ -d /sys/module/nf_conntrack ]; then
    observe kernel.conntrack_count conntrack -C
else
    emit kernel.conntrack_count failed 'nf_conntrack not observed; no query that might load it'
fi
if [ -r /proc/config.gz ] && command -v zcat >/dev/null 2>&1; then
    if config=$(zcat /proc/config.gz 2>&1); then
        value=$(printf '%s\n' "$config" | awk '/^(CONFIG_(CGROUPS|CGROUP_NET_CLASSID|NETFILTER_XT_MATCH_CGROUP|NF_CONNTRACK|NF_NAT|IP_NF_IPTABLES|IP_NF_NAT|IP6_NF_IPTABLES|IP6_NF_NAT)=|# CONFIG_(CGROUPS|NETFILTER_XT_MATCH_CGROUP|NF_CONNTRACK|NF_NAT) is not set)/')
        emit kernel.config ok "$value"
    else emit kernel.config failed "$config"; fi
else
    emit kernel.config unavailable 'readable /proc/config.gz and zcat not available; loaded-module evidence reported separately'
fi
