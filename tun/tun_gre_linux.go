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
	"sync"
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

	greLoAddrADefault = "127.0.0.3"
	greLoAddrBDefault = "127.0.0.4"

	// Env vars to override the default loopback tunnel endpoint addresses.
	// Each wireguard-go instance must use a unique pair to avoid conflicts
	// when running multiple instances.
	ENV_WG_GRE_LOCAL_IP  = "WG_GRE_LOCAL_IP"
	ENV_WG_GRE_REMOTE_IP = "WG_GRE_REMOTE_IP"

	// Set WG_TUN_GRE=1 to explicitly use a GRE pair instead of /dev/net/tun.
	ENV_WG_TUN_GRE = "WG_TUN_GRE"
)

// GRETun implements tun.Device using a GRE pair as the inner TUN substitute.
type GRETun struct {
	name    string
	mtu     int
	ifIndex int32 // ifIndex of <name> (the read side)
	loAddrA netip.Addr
	loAddrB netip.Addr

	// readFile: AF_PACKET SOCK_DGRAM on <name> — captures outbound raw IP packets.
	// readRaw is the RawConn for recvfrom with sockaddr_ll (pkttype filtering).
	readFile *os.File
	readRaw  syscall.RawConn

	// writeFd: AF_PACKET SOCK_DGRAM on <name>_ — injects raw IP packets inbound.
	writeFd      int
	writeIfIndex int32

	events chan Event

	netlinkSock   int
	netlinkCancel *rwcancel.RWCancel

	shutdown  chan struct{}
	closeOnce sync.Once
}

// CreateGRETun creates a mirrored GRE pair as a TUN substitute:
// - A: <name>  local=$WG_GRE_LOCAL_IP  remote=$WG_GRE_REMOTE_IP  (Read side — assign WG IP here)
// - B: <name>_ local=$WG_GRE_REMOTE_IP remote=$WG_GRE_LOCAL_IP   (Write side — inject packets here)
//
// WireGuard's encrypted UDP uses the normal routing table; no outer GRE link is
// visible to the user, so NAT traversal works as with any standard WireGuard setup.
func CreateGRETun(nameA string, mtu int) (Device, error) {
	nameB := nameA + greTunPeerSuffix
	loAddrA := getLoAddr(ENV_WG_GRE_LOCAL_IP, greLoAddrADefault)
	loAddrB := getLoAddr(ENV_WG_GRE_REMOTE_IP, greLoAddrBDefault)

	ifaces := []struct {
		local   netip.Addr
		remote  netip.Addr
		name    string
		ifIndex int32
		fd      int
	}{
		{local: loAddrA, remote: loAddrB, name: nameA, fd: -1},
		{local: loAddrB, remote: loAddrA, name: nameB, fd: -1},
	}
	var (
		nlSock   = -1
		nlCancel *rwcancel.RWCancel
		readFile *os.File
	)
	cleanup := func() {
		if readFile != nil {
			readFile.Close()
		} else if ifaces[0].fd >= 0 {
			unix.Close(ifaces[0].fd)
		}
		if ifaces[1].fd >= 0 {
			unix.Close(ifaces[1].fd)
		}
		if nlCancel != nil {
			nlCancel.Close()
		} else if nlSock >= 0 {
			unix.Close(nlSock)
		}
		_ = nlLinkDel(nameA)
		_ = nlLinkDel(nameB)
		_ = nlAddrDelLo(loAddrA)
		_ = nlAddrDelLo(loAddrB)
		_ = nlRuleDel(nameB)
	}

	// Clean up any stale interfaces and loopback aliases from a previous run.
	cleanup()

	// Add loopback aliases and create each GRE interface.
	// Packets written to nameB are encapsulated and delivered inbound on nameA.
	for i := range ifaces {
		iface := &ifaces[i]
		if err := nlAddrAddLo(iface.local); err != nil {
			cleanup()
			return nil, fmt.Errorf("gre: add lo alias %s: %w", iface.local, err)
		}
		if err := nlLinkAddGRE(iface.name, iface.local, iface.remote); err != nil {
			cleanup()
			return nil, fmt.Errorf("gre: create %s: %w", iface.name, err)
		}
		if err := setMTU(iface.name, mtu); err != nil {
			cleanup()
			return nil, fmt.Errorf("gre: set MTU %s: %w", iface.name, err)
		}
		if err := setIfUp(iface.name); err != nil {
			cleanup()
			return nil, fmt.Errorf("gre: set up %s: %w", iface.name, err)
		}
		ifIndex, err := getIFIndex(iface.name)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("gre: get ifIndex %s: %w", iface.name, err)
		}
		iface.ifIndex = ifIndex
		fd, err := openPacketSock(ifIndex)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("gre: AF_PACKET %s: %w", iface.name, err)
		}
		iface.fd = fd
	}

	if err := nlRuleAdd(nameB); err != nil {
		cleanup()
		return nil, fmt.Errorf("gre: blackhole rule %s: %w", nameB, err)
	}

	// Netlink monitor socket for link events on nameA.
	nlSock, err := createNetlinkSocket()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("gre: netlink socket: %w", err)
	}
	nlCancel, err = rwcancel.NewRWCancel(nlSock)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("gre: rwcancel: %w", err)
	}

	readFile = os.NewFile(uintptr(ifaces[0].fd), nameA)
	readRaw, err := readFile.SyscallConn()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("gre: SyscallConn: %w", err)
	}

	t := &GRETun{
		name:          nameA,
		mtu:           mtu,
		ifIndex:       ifaces[0].ifIndex,
		loAddrA:       loAddrA,
		loAddrB:       loAddrB,
		readFile:      readFile,
		readRaw:       readRaw,
		writeFd:       ifaces[1].fd,
		writeIfIndex:  ifaces[1].ifIndex,
		events:        make(chan Event, 5),
		netlinkSock:   nlSock,
		netlinkCancel: nlCancel,
		shutdown:      make(chan struct{}),
	}

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
		Ifindex: t.writeIfIndex,
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
			uintptr(t.writeFd),
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

func (t *GRETun) MTU() (int, error) { return t.mtu, nil }

// Name returns the user-facing GRE interface name (<name>), which holds the
// WireGuard IP address and is the name wireguard-go advertises via UAPI.
func (t *GRETun) Name() (string, error) { return t.name, nil }
func (t *GRETun) Events() <-chan Event  { return t.events }
func (t *GRETun) BatchSize() int        { return 1 }

func (t *GRETun) Close() error {
	var firstErr error
	t.closeOnce.Do(func() {
		close(t.shutdown)
		t.netlinkCancel.Close()
		if err := t.readFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		unix.Close(t.writeFd)
		if err := nlLinkDel(t.name); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := nlLinkDel(t.name + greTunPeerSuffix); err != nil && firstErr == nil {
			firstErr = err
		}
		_ = nlAddrDelLo(t.loAddrA)
		_ = nlAddrDelLo(t.loAddrB)
		_ = nlRuleDel(t.name + greTunPeerSuffix)
	})
	return firstErr
}

// routineNetlinkListener watches RTM_NEWLINK for <name> and emits EventMTUUpdate.
func (t *GRETun) routineNetlinkListener() {
	defer func() {
		unix.Close(t.netlinkSock)
		close(t.events)
	}()

	buf := make([]byte, 1<<16)
	for {
		n, _, _, _, err := unix.Recvmsg(t.netlinkSock, buf, nil, 0)
		if err != nil {
			select {
			case <-t.shutdown:
				return
			default:
			}
			if !rwcancel.RetryAfterError(err) {
				return
			}
			if !t.netlinkCancel.ReadyRead() {
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
			if info.Index != t.ifIndex {
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

// getLoAddr returns the loopback tunnel endpoint address from the given env
// var, falling back to def if unset or invalid.
func getLoAddr(env, def string) netip.Addr {
	if s := os.Getenv(env); s != "" {
		if addr, err := netip.ParseAddr(s); err == nil {
			return addr
		}
	}
	return netip.MustParseAddr(def)
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
	sock, err := unix.Socket(
		unix.AF_NETLINK,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC,
		unix.NETLINK_ROUTE,
	)
	if err != nil {
		return err
	}
	defer unix.Close(sock)

	if err = unix.Bind(sock, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	msgLen := unix.SizeofNlMsghdr + len(ifInfoBuf) + len(attrs)
	msg := make([]byte, nlAlign4(msgLen))
	hdr := (*unix.NlMsghdr)(unsafe.Pointer(&msg[0]))
	hdr.Len = uint32(msgLen)
	hdr.Type = typ
	hdr.Flags = flags
	hdr.Seq = 1
	copy(msg[unix.SizeofNlMsghdr:], ifInfoBuf)
	copy(msg[unix.SizeofNlMsghdr+len(ifInfoBuf):], attrs)

	if err = unix.Sendmsg(sock, msg, nil, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, 0); err != nil {
		return err
	}

	reply := make([]byte, 4096)
	for {
		n, err := unix.Read(sock, reply)
		if err != nil {
			return err
		}
		if n < unix.SizeofNlMsghdr {
			return errors.New("gre: short netlink reply")
		}
		rh := *(*unix.NlMsghdr)(unsafe.Pointer(&reply[0]))
		switch rh.Type {
		case unix.NLMSG_ERROR:
			if n < unix.SizeofNlMsghdr+4 {
				return errors.New("gre: truncated NLMSG_ERROR")
			}
			errno := *(*int32)(unsafe.Pointer(&reply[unix.SizeofNlMsghdr]))
			if errno == 0 {
				return nil
			}
			return unix.Errno(-errno)
		case unix.NLMSG_DONE:
			return nil
		}
	}
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
