/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2026 WireGuard LLC. All Rights Reserved.
 */

package tun

// GRETun is a tun.Device for systems that have the ip_gre kmod but not tun.
//
// It uses a mirrored L3 GRE pair (<name> / <name>_) as a TUN substitute.
// <name> is the user-facing interface: assign the WireGuard IP here and
// configure it with wg(8).  <name>_ is the hidden peer end used internally
// by Write(); users never need to reference it.
//
// WireGuard's encrypted UDP travels over the normal routing table (WAN
// interface) — no outer GRE wrapper is needed and NAT traversal works as usual.
//
// Packet flow — outbound (local app → WireGuard peer):
//
//	local app writes to socket
//	  → kernel routes via <name> (GRE with WireGuard IP)
//	  → AF_PACKET SOCK_DGRAM on <name> captures raw IP packet (our Read())
//	  → wireguard-go encrypts + sends UDP out via normal routing
//
// Packet flow — inbound (WireGuard peer → local app):
//
//	UDP arrives on WAN interface
//	  → wireguard-go decrypts, calls Write()
//	  → we sendto AF_PACKET SOCK_DGRAM on <name>_ (GRE peer end)
//	  → kernel delivers packet inbound on <name>
//	  → local socket receives it

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/rwcancel"
)

const (
	// greTunPeerSuffix is appended to the interface name to form the hidden
	// peer end of the GRE pair.  The user-facing interface keeps the bare
	// name; this one is internal plumbing only.
	greTunPeerSuffix = "_"

	// greLoIface is the loopback interface used to host the GRE tunnel
	// endpoint addresses.
	greLoIface = "lo"

	// Set WG_TUN_GRE=1 to explicitly use a GRE pair instead of /dev/net/tun.
	ENV_WG_TUN_GRE = "WG_TUN_GRE"
)

// GRETun implements tun.Device using a GRE pair as the inner TUN substitute.
type GRETun struct {
	mtu    int
	ifaces [2]greIface
	nlSock int
	events chan Event

	// readFile: AF_PACKET SOCK_DGRAM on <name>, captures outbound raw IP packets.
	// readFile.Close() deregisters from epoll, unblocking any pending Read().
	// readRaw is the RawConn for recvfrom with sockaddr_ll (pkttype filtering).
	readFile *os.File
	readRaw  syscall.RawConn
	shutdown chan struct{}
}

type greIface struct {
	name    string
	ifIndex int32
	loAddr  netip.Addr
	fd      int
}

// CreateGRETun creates a mirrored GRE pair as a TUN substitute:
// ip link add 0.name type gre local 0.loAddr remote 1.loAddr (Read side, assign WG IP here)
// ip link add 1.name type gre local 1.loAddr remote 0.loAddr (Write side, inject packets here)
//
// WireGuard's encrypted UDP uses the normal routing table; no outer GRE link is
// visible to the user, so NAT traversal works as with any standard WireGuard setup.
func CreateGRETun(name string, mtu int) (_ Device, err error) {
	t := &GRETun{
		mtu: mtu,
		ifaces: [2]greIface{
			{fd: -1, name: name},
			{fd: -1, name: name + greTunPeerSuffix},
		},
		nlSock: -1,
	}

	// Clean up any stale interfaces from a previous run.
	t.Close()

	defer func() {
		if err != nil {
			t.Close()
		}
	}()

	if err = nlAddrAddLoPair(t); err != nil {
		return nil, fmt.Errorf("gre: claim lo addr pair: %w", err)
	}

	// Create the GRE interfaces.
	// Packets written to <name>_ are encapsulated and delivered inbound on <name>.
	// Addresses are mirrored: each side's remote is the other's local.
	for i := range t.ifaces {
		iface := &t.ifaces[i]
		if err = nlLinkAddGRE(iface.name, iface.loAddr, t.ifaces[1-i].loAddr); err != nil {
			return nil, fmt.Errorf("gre: create %s: %w", iface.name, err)
		}
		if err = setMTU(iface.name, mtu); err != nil {
			return nil, fmt.Errorf("gre: set MTU %s: %w", iface.name, err)
		}
		if err = setIfUp(iface.name); err != nil {
			return nil, fmt.Errorf("gre: set up %s: %w", iface.name, err)
		}
		if iface.ifIndex, err = getIFIndex(iface.name); err != nil {
			return nil, fmt.Errorf("gre: get ifIndex %s: %w", iface.name, err)
		}
		if iface.fd, err = openPacketSock(iface.ifIndex); err != nil {
			return nil, fmt.Errorf("gre: AF_PACKET %s: %w", iface.name, err)
		}
	}

	if err = nlRuleAdd(t.ifaces[1].name); err != nil {
		return nil, fmt.Errorf("gre: blackhole rule %s: %w", t.ifaces[1].name, err)
	}

	// Netlink monitor socket for link events on <name>.
	if t.nlSock, err = createNetlinkSocket(); err != nil {
		return nil, fmt.Errorf("gre: netlink socket: %w", err)
	}
	t.readFile = os.NewFile(uintptr(t.ifaces[0].fd), t.ifaces[0].name)
	if t.readRaw, err = t.readFile.SyscallConn(); err != nil {
		return nil, fmt.Errorf("gre: SyscallConn: %w", err)
	}

	t.shutdown = make(chan struct{})
	t.events = make(chan Event, 5)
	t.events <- EventUp
	go t.routineNetlinkListener()
	return t, nil
}

// File returns nil; GRETun does not expose a file descriptor to callers.
func (t *GRETun) File() *os.File { return nil }

// Read captures one outbound IP packet from <name> (the user-facing GRE interface).
// AF_PACKET SOCK_DGRAM on a GRE interface delivers raw IP packets (no link-layer header).
// Only PACKET_OUTGOING frames are forwarded to WireGuard; inbound packets injected by
// our own Write() have pkttype=PACKET_HOST and must be skipped to avoid a loop.
func (t *GRETun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		pkt := bufs[0][offset:]
		var (
			n    int
			sll  unix.RawSockaddrLinklayer
			serr error
		)
		sllLen := uint32(unsafe.Sizeof(sll))
		rerr := t.readRaw.Read(func(fd uintptr) bool {
			r, _, errno := unix.Syscall6(
				unix.SYS_RECVFROM,
				fd,
				uintptr(unsafe.Pointer(&pkt[0])),
				uintptr(len(pkt)),
				0,
				uintptr(unsafe.Pointer(&sll)),
				uintptr(unsafe.Pointer(&sllLen)),
			)
			if errno == unix.EAGAIN {
				return false
			}
			if errno != 0 {
				serr = errno
				return true
			}
			n = int(r)
			return true
		})
		if rerr != nil {
			return 0, rerr
		}
		if serr != nil {
			select {
			case <-t.shutdown:
				return 0, os.ErrClosed
			default:
			}
			if serr == unix.EINTR {
				continue
			}
			return 0, serr
		}
		if n == 0 {
			continue
		}
		if sll.Pkttype != unix.PACKET_OUTGOING {
			continue
		}
		version := pkt[0] >> 4
		if version != 4 && version != 6 {
			continue
		}
		sizes[0] = n
		return 1, nil
	}
}

// Write injects decrypted IP packets inbound into <name>_ (the peer GRE interface) so
// the kernel delivers them via <name> to local sockets.
// AF_PACKET SOCK_DGRAM on a GRE interface accepts raw IP packets; the protocol field
// in sockaddr_ll selects IPv4 vs IPv6.
func (t *GRETun) Write(bufs [][]byte, offset int) (int, error) {
	sll := unix.RawSockaddrLinklayer{
		Family:  unix.AF_PACKET,
		Ifindex: t.ifaces[1].ifIndex,
	}

	for i, buf := range bufs {
		pkt := buf[offset:]
		if len(pkt) == 0 {
			continue
		}
		if pkt[0]>>4 == 6 {
			sll.Protocol = htons(unix.ETH_P_IPV6)
		} else {
			sll.Protocol = htons(unix.ETH_P_IP)
		}
		if _, _, errno := unix.Syscall6(
			unix.SYS_SENDTO,
			uintptr(t.ifaces[1].fd),
			uintptr(unsafe.Pointer(&pkt[0])),
			uintptr(len(pkt)),
			0,
			uintptr(unsafe.Pointer(&sll)),
			unsafe.Sizeof(sll),
		); errno != 0 {
			return i, errno
		}
	}
	return len(bufs), nil
}

// Name returns the user-facing GRE interface name (<name>), which holds the
// WireGuard IP address and is the name wireguard-go advertises via UAPI.
func (t *GRETun) Name() (string, error) { return t.ifaces[0].name, nil }
func (t *GRETun) Events() <-chan Event  { return t.events }
func (t *GRETun) MTU() (int, error)     { return t.mtu, nil }
func (t *GRETun) BatchSize() int        { return 1 }

func (t *GRETun) Close() error {
	var firstErr error
	if t.shutdown != nil {
		close(t.shutdown)
	}
	if t.nlSock >= 0 {
		unix.Close(t.nlSock)
	}
	if t.readFile != nil {
		if err := t.readFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	} else if t.ifaces[0].fd >= 0 {
		unix.Close(t.ifaces[0].fd)
	}
	if t.ifaces[1].fd >= 0 {
		unix.Close(t.ifaces[1].fd)
	}
	for i := range t.ifaces {
		if err := nlLinkDel(t.ifaces[i].name); err != nil && firstErr == nil {
			firstErr = err
		}
		if t.ifaces[i].loAddr.IsValid() {
			if err := nlAddrDelLo(t.ifaces[i].loAddr); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	if err := nlRuleDel(t.ifaces[1].name); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// routineNetlinkListener watches RTM_NEWLINK for <name> and emits EventMTUUpdate.
func (t *GRETun) routineNetlinkListener() {
	defer close(t.events)

	buf := make([]byte, 1<<16)
	for {
		n, _, _, _, err := unix.Recvmsg(t.nlSock, buf, nil, 0)
		if err != nil {
			select {
			case <-t.shutdown:
				return
			default:
			}
			if !rwcancel.RetryAfterError(err) {
				return
			}
			continue
		}

		select {
		case <-t.shutdown:
			return
		default:
		}

		for remain := buf[:n]; len(remain) >= unix.SizeofNlMsghdr; {
			hdr := *(*unix.NlMsghdr)(unsafe.Pointer(&remain[0]))
			if int(hdr.Len) > len(remain) {
				break
			}
			msgData := remain[:hdr.Len]
			remain = remain[nlAlign4(int(hdr.Len)):]

			if hdr.Type != unix.RTM_NEWLINK {
				continue
			}
			if len(msgData) < unix.SizeofNlMsghdr+unix.SizeofIfInfomsg {
				continue
			}
			info := *(*unix.IfInfomsg)(unsafe.Pointer(&msgData[unix.SizeofNlMsghdr]))
			if info.Index != t.ifaces[0].ifIndex {
				continue
			}
			select {
			case t.events <- EventMTUUpdate:
			default:
			}
		}
	}
}

// ── socket helpers ────────────────────────────────────────────────────────────

func openPacketSock(ifIndex int32) (int, error) {
	fd, err := unix.Socket(
		unix.AF_PACKET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK,
		int(htons(unix.ETH_P_ALL)),
	)
	if err != nil {
		return -1, err
	}
	sll := unix.RawSockaddrLinklayer{
		Family:   unix.AF_PACKET,
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifIndex,
	}
	if _, _, errno := unix.Syscall(
		unix.SYS_BIND,
		uintptr(fd),
		uintptr(unsafe.Pointer(&sll)),
		unsafe.Sizeof(sll),
	); errno != 0 {
		unix.Close(fd)
		return -1, errno
	}
	return fd, nil
}

// htons converts a uint16 from host to network (big-endian) byte order.
func htons(v uint16) uint16 {
	b := [2]byte{}
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// ── netlink helpers ───────────────────────────────────────────────────────────

// nlLinkAddGRE creates a single GRE (L3) interface.
// Equivalent to: ip link add <name> type gre local <local> remote <remote>
func nlLinkAddGRE(name string, local, remote netip.Addr) error {
	const (
		iflaInfoKind  = 1
		iflaInfoData  = 2
		iflaGreLocal  = 6
		iflaGreRemote = 7
	)
	local4 := local.As4()
	remote4 := remote.As4()
	infoData := nlAttr(iflaInfoData,
		append(
			nlAttr(iflaGreLocal, local4[:]),
			nlAttr(iflaGreRemote, remote4[:])...,
		),
	)
	linkInfo := nlAttr(unix.IFLA_LINKINFO,
		append(
			nlAttr(iflaInfoKind, append([]byte("gre"), 0)),
			infoData...,
		),
	)
	ifNameAttr := nlAttr(unix.IFLA_IFNAME, append([]byte(name), 0))
	ifInfo := unix.IfInfomsg{Family: unix.AF_UNSPEC}
	return nlRequest(
		unix.RTM_NEWLINK,
		unix.NLM_F_REQUEST|unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK,
		(*[unix.SizeofIfInfomsg]byte)(unsafe.Pointer(&ifInfo))[:],
		append(ifNameAttr, linkInfo...),
	)
}

// nlAddrAddLoPair claims two free loopback /32 addresses from 127.255.0.0/16
// using a single RTM_GETADDR scan. Each address is added with NLM_F_EXCL;
// EEXIST means another instance raced us — skip to the next candidate.
// On success both addresses have been added to lo; the caller must remove
// them on cleanup.
func nlAddrAddLoPair(t *GRETun) error {
	used, err := nlAddrGetLo()
	if err != nil {
		return err
	}

	for i, addr := 0, netip.AddrFrom4([4]byte{127, 255, 0, 0}); i < len(t.ifaces) && addr.IsLoopback(); addr = addr.Next() {
		if used[addr] {
			continue
		}
		if err = nlAddrAddLo(addr); err == unix.EEXIST {
			continue
		} else if err != nil {
			return err
		}
		t.ifaces[i].loAddr = addr
		i++
	}

	if t.ifaces[1].loAddr.IsValid() {
		return nil
	}
	return errors.New("gre: no free loopback address pair in 127.255.0.0/16")
}

// nlAddrGetLo returns the set of IPv4 addresses currently on lo.
// Equivalent to: ip -4 addr show dev lo
func nlAddrGetLo() (map[netip.Addr]bool, error) {
	loIndex, err := getIFIndex(greLoIface)
	if err != nil {
		return nil, err
	}

	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(sock)
	if err = unix.Bind(sock, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}

	// Send RTM_GETADDR dump request.
	ifAddr := unix.IfAddrmsg{Family: unix.AF_INET}
	if err = nlSend(sock, unix.RTM_GETADDR, unix.NLM_F_REQUEST|unix.NLM_F_DUMP,
		(*[unix.SizeofIfAddrmsg]byte)(unsafe.Pointer(&ifAddr))[:], nil); err != nil {
		return nil, err
	}

	used := make(map[netip.Addr]bool)
	reply := make([]byte, 1<<16)
	for {
		n, err := unix.Read(sock, reply)
		if err != nil {
			return nil, err
		}
		done, err := nlParseReply(reply[:n], loIndex, used)
		if err != nil {
			return nil, err
		}
		if done {
			return used, nil
		}
	}
}

func nlParseReply(reply []byte, loIndex int32, used map[netip.Addr]bool) (done bool, err error) {
	for remain := reply; len(remain) >= unix.SizeofNlMsghdr; {
		hdr := *(*unix.NlMsghdr)(unsafe.Pointer(&remain[0]))
		if int(hdr.Len) > len(remain) {
			break
		}
		msg := remain[:hdr.Len]
		remain = remain[nlAlign4(int(hdr.Len)):]

		switch hdr.Type {
		case unix.NLMSG_DONE:
			return true, nil
		case unix.NLMSG_ERROR:
			if len(msg) < unix.SizeofNlMsghdr+4 {
				return false, errors.New("gre: truncated NLMSG_ERROR")
			}
			if e := *(*int32)(unsafe.Pointer(&msg[unix.SizeofNlMsghdr])); e != 0 {
				return false, unix.Errno(-e)
			}
			return true, nil
		case unix.RTM_NEWADDR:
			if len(msg) < unix.SizeofNlMsghdr+unix.SizeofIfAddrmsg {
				continue
			}
			ifa := *(*unix.IfAddrmsg)(unsafe.Pointer(&msg[unix.SizeofNlMsghdr]))
			if int32(ifa.Index) != loIndex || ifa.Family != unix.AF_INET {
				continue
			}
			for attrs := msg[unix.SizeofNlMsghdr+unix.SizeofIfAddrmsg:]; len(attrs) >= 4; {
				alen := int(binary.NativeEndian.Uint16(attrs[0:2]))
				if alen < 4 || alen > len(attrs) {
					break
				}
				atyp := binary.NativeEndian.Uint16(attrs[2:4])
				if (atyp == unix.IFA_LOCAL || atyp == unix.IFA_ADDRESS) && alen >= 8 {
					used[netip.AddrFrom4([4]byte(attrs[4:8]))] = true
				}
				attrs = attrs[nlAlign4(alen):]
			}
		}
	}
	return false, nil
}

// nlAddrAddLo adds a /32 address to greLoIface.
// Equivalent to: ip addr add <addr>/32 dev lo
func nlAddrAddLo(addr netip.Addr) error {
	return nlAddrMod(
		greLoIface, addr, 32,
		unix.RTM_NEWADDR,
		unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
}

// nlAddrDelLo removes a /32 address from greLoIface.
// Equivalent to: ip addr del <addr>/32 dev lo
func nlAddrDelLo(addr netip.Addr) error {
	return nlAddrMod(
		greLoIface, addr, 32,
		unix.RTM_DELADDR,
		unix.NLM_F_REQUEST|unix.NLM_F_ACK)
}

func nlAddrMod(iface string, addr netip.Addr, prefixLen uint8, typ, flags uint16) error {
	ifIndex, err := getIFIndex(iface)
	if err != nil {
		return err
	}
	addr4 := addr.As4()
	addrAttr := append(
		nlAttr(unix.IFA_ADDRESS, addr4[:]),
		nlAttr(unix.IFA_LOCAL, addr4[:])...,
	)
	ifAddr := unix.IfAddrmsg{
		Family:    unix.AF_INET,
		Prefixlen: prefixLen,
		Index:     uint32(ifIndex),
	}
	return nlRequest(
		typ,
		flags,
		(*[unix.SizeofIfAddrmsg]byte)(unsafe.Pointer(&ifAddr))[:],
		addrAttr,
	)
}

// nlLinkDel removes an interface.
// Equivalent to: ip link del <name>
func nlLinkDel(name string) error {
	ifIndex, err := getIFIndex(name)
	if err != nil {
		return err
	}
	ifInfo := unix.IfInfomsg{
		Family: unix.AF_UNSPEC,
		Index:  ifIndex,
	}
	return nlRequest(
		unix.RTM_DELLINK,
		unix.NLM_F_REQUEST|unix.NLM_F_ACK,
		(*[unix.SizeofIfInfomsg]byte)(unsafe.Pointer(&ifInfo))[:],
		nil,
	)
}

// nlRuleAdd adds a blackhole FIB rule for packets arriving on <name>_.
// Prevents a routing loop: packets injected by Write() via <name>_ would
// otherwise re-enter the IP stack and be re-routed back indefinitely.
// Equivalent to: ip rule add iif <name>_ blackhole priority 100
func nlRuleAdd(iface string) error {
	return nlRuleMod(
		iface, 100,
		unix.RTM_NEWRULE,
		unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
}

// nlRuleDel removes the blackhole FIB rule for <name>_.
// Equivalent to: ip rule del iif <name>_ blackhole priority 100
func nlRuleDel(iface string) error {
	return nlRuleMod(
		iface, 100,
		unix.RTM_DELRULE,
		unix.NLM_F_REQUEST|unix.NLM_F_ACK)
}

func nlRuleMod(iface string, prio uint32, typ, flags uint16) error {
	rule := unix.RtMsg{
		Family: unix.AF_INET,
		Type:   unix.RTN_BLACKHOLE,
		Table:  unix.RT_TABLE_UNSPEC,
	}
	prioBuf := [4]byte{}
	binary.NativeEndian.PutUint32(prioBuf[:], prio)
	prioAttr := nlAttr(unix.FRA_PRIORITY, prioBuf[:])
	ifAttr := nlAttr(unix.FRA_IIFNAME, append([]byte(iface), 0))
	return nlRequest(
		typ, flags,
		(*[unix.SizeofRtMsg]byte)(unsafe.Pointer(&rule))[:],
		append(prioAttr, ifAttr...),
	)
}

// nlRequest sends a single NETLINK_ROUTE request and waits for ACK.
func nlRequest(typ, flags uint16, ifInfoBuf, attrs []byte) error {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(sock)
	if err = unix.Bind(sock, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	if err = nlSend(sock, typ, flags, ifInfoBuf, attrs); err != nil {
		return err
	}
	reply := make([]byte, os.Getpagesize())
	for {
		n, err := unix.Read(sock, reply)
		if err != nil {
			return err
		}
		done, err := nlParseReply(reply[:n], 0, nil)
		if err != nil || done {
			return err
		}
	}
}

// nlSend writes a single netlink message to sock.
func nlSend(sock int, typ, flags uint16, ifInfoBuf, attrs []byte) error {
	msgLen := unix.SizeofNlMsghdr + len(ifInfoBuf) + len(attrs)
	msg := make([]byte, nlAlign4(msgLen))
	hdr := (*unix.NlMsghdr)(unsafe.Pointer(&msg[0]))
	hdr.Len = uint32(msgLen)
	hdr.Type = typ
	hdr.Flags = flags
	hdr.Seq = 1
	copy(msg[unix.SizeofNlMsghdr:], ifInfoBuf)
	copy(msg[unix.SizeofNlMsghdr+len(ifInfoBuf):], attrs)
	return unix.Sendmsg(sock, msg, nil, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, 0)
}

// nlAttr encodes a netlink attribute: 4-byte NLA header + padded data.
func nlAttr(typ int, data []byte) []byte {
	l := 4 + len(data)
	b := make([]byte, nlAlign4(l))
	binary.NativeEndian.PutUint16(b[0:2], uint16(l))
	binary.NativeEndian.PutUint16(b[2:4], uint16(typ))
	copy(b[4:], data)
	return b
}

// nlAlign4 rounds n up to the nearest 4-byte boundary.
func nlAlign4(n int) int {
	return (n + 3) &^ 3
}

// setIfUp brings an interface up.
// Equivalent to: ip link set <name> up
func setIfUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return errno
	}

	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) |= unix.IFF_UP

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return errno
	}
	return nil
}
