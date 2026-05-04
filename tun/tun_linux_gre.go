/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package tun

// GRETun is a tun.Device for systems that have ip_gre (with gretap support)
// but not the tun/tap kernel module.
//
// It uses a mirrored GRETap pair (<name> / <name>_) as a TUN substitute.
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
//	  → kernel routes via <name> (gretap with WireGuard IP)
//	  → AF_PACKET on <name> captures packet  [our Read()]
//	  → wireguard-go encrypts + sends UDP out via normal routing
//
// Packet flow — inbound (WireGuard peer → local app):
//
//	UDP arrives on WAN interface
//	  → wireguard-go decrypts, calls Write()
//	  → we sendto AF_PACKET on <name>_ (gretap peer end)
//	  → kernel delivers frame inbound on <name>
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
	// Default MTU for WireGuard traffic (1500 - 20 IPv4 - 8 UDP - 32 WireGuard overhead headroom).
	greDefaultMTU = 1420

	// greTapPeerSuffix is appended to the interface name to form the hidden
	// peer end of the GRETap pair.  The user-facing interface keeps the bare
	// name; this one is internal plumbing only.
	greTapPeerSuffix = "_"

	// greTapLoopback is the loopback interface used to host the GRETap tunnel
	// endpoint addresses.
	greTapLoopback = "lo"

	// Env vars to override the loopback tunnel endpoint addresses.
	// Each wireguard-go instance must use a unique pair to avoid conflicts.
	envGRELocal  = "WG_GRE_LOCAL_IP"
	envGRERemote = "WG_GRE_REMOTE_IP"

	greLoAddrADefault = "127.0.0.3"
	greLoAddrBDefault = "127.0.0.4"
)

// htons converts a uint16 from host to network (big-endian) byte order.
func htons(v uint16) uint16 {
	b := [2]byte{}
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// ETH_P_* in network byte order, ready to pass to the kernel.
var (
	ethPAll = htons(0x0003)
	ethPIP  = htons(0x0800)
	ethPIP6 = htons(0x86DD)
)

// GRETun implements tun.Device using a GRETap pair as the inner TUN substitute.
type GRETun struct {
	name    string
	mtu     int
	ifIndex int32 // ifIndex of <name> (the read side)
	loAddrA netip.Addr
	loAddrB netip.Addr

	// readFile: AF_PACKET on <name> — captures outbound IP packets from local stack.
	// readRaw is the RawConn for recvfrom with sockaddr_ll (pkttype filtering).
	readFile *os.File
	readRaw  syscall.RawConn

	// writeFd: AF_PACKET SOCK_DGRAM on <name>_ — injects packets inbound to <name>.
	// writeDstMAC is the MAC of <name>; the kernel requires the correct dst MAC
	// so received frames have pkttype=PACKET_HOST and are delivered to local sockets.
	writeFd      int
	writeIfIndex int32
	writeDstMAC  [6]byte

	events chan Event

	netlinkSock   int
	netlinkCancel *rwcancel.RWCancel

	shutdownOnce sync.Once
	shutdown     chan struct{}
	closeOnce    sync.Once
}

// CreateGRETap creates a mirrored GRETap pair as a TUN substitute:
//   - name:  local=WG_GRE_LOCAL_IP  remote=WG_GRE_REMOTE_IP  (Read side — assign WG IP here)
//   - name_: local=WG_GRE_REMOTE_IP remote=WG_GRE_LOCAL_IP   (Write side — inject frames here)
//
// Default loopback addresses are 127.0.0.3/127.0.0.4; set WG_GRE_LOCAL_IP and
// WG_GRE_REMOTE_IP to unique values when running multiple instances.
//
// WireGuard's encrypted UDP uses the normal routing table; no outer GRE link is
// created, so NAT traversal works as with any standard WireGuard setup.
//
// Requires: ip_gre (with gretap) loaded. NET_ADMIN capability.
// mtu ≤ 0 uses greDefaultMTU (1420).
func CreateGRETap(nameA string, mtu int) (Device, error) {
	if mtu <= 0 {
		mtu = greDefaultMTU
	}

	nameB := nameA + greTapPeerSuffix
	greLoAddrA := greGetLoAddr(envGRELocal, greLoAddrADefault)
	greLoAddrB := greGetLoAddr(envGRERemote, greLoAddrBDefault)

	ifaces := []struct {
		local   netip.Addr
		remote  netip.Addr
		name    string
		ifIndex int32
		fd      int
	}{
		{local: greLoAddrA, remote: greLoAddrB, name: nameA, fd: -1},
		{local: greLoAddrB, remote: greLoAddrA, name: nameB, fd: -1},
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
		_ = greNetlinkDelLink(nameA)
		_ = greNetlinkDelLink(nameB)
		_ = greLoAddrDel(greLoAddrA)
		_ = greLoAddrDel(greLoAddrB)
	}

	// Clean up any stale interfaces and loopback aliases from a previous run.
	cleanup()

	// 1. Add loopback aliases and create each GRETap interface.
	//    Frames written to nameB are encapsulated and delivered inbound on nameA.
	for i := range ifaces {
		iface := &ifaces[i]
		if err := greLoAddrAdd(iface.local); err != nil {
			cleanup()
			return nil, fmt.Errorf("gretap: add lo alias %s: %w", iface.local, err)
		}
		if err := greNetlinkAddGRETap(iface.name, iface.local, iface.remote); err != nil {
			cleanup()
			return nil, fmt.Errorf("gretap: create %s: %w", iface.name, err)
		}
		if err := greIoctlSetMTU(iface.name, mtu); err != nil {
			cleanup()
			return nil, fmt.Errorf("gretap: set MTU %s: %w", iface.name, err)
		}
		if err := greIoctlSetUpNoARP(iface.name); err != nil {
			cleanup()
			return nil, fmt.Errorf("gretap: set up %s: %w", iface.name, err)
		}
		ifIndex, err := greIoctlGetIndex(iface.name)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("gretap: get ifIndex %s: %w", iface.name, err)
		}
		iface.ifIndex = ifIndex
		fd, err := greOpenPacketSock(ifIndex)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("gretap: AF_PACKET %s: %w", iface.name, err)
		}
		iface.fd = fd
	}

	macA, err := greIoctlGetMAC(nameA)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("gretap: get MAC %s: %w", nameA, err)
	}

	// 5. Netlink monitor socket for link events on nameA.
	nlSock, err = greCreateNetlinkSocket()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("gretap: netlink socket: %w", err)
	}
	nlCancel, err = rwcancel.NewRWCancel(nlSock)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("gretap: rwcancel: %w", err)
	}

	readFile = os.NewFile(uintptr(ifaces[0].fd), nameA)
	readRaw, err := readFile.SyscallConn()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("gretap: SyscallConn: %w", err)
	}

	t := &GRETun{
		name:          nameA,
		mtu:           mtu,
		ifIndex:       ifaces[0].ifIndex,
		loAddrA:       greLoAddrA,
		loAddrB:       greLoAddrB,
		readFile:      readFile,
		readRaw:       readRaw,
		writeFd:       ifaces[1].fd,
		writeIfIndex:  ifaces[1].ifIndex,
		writeDstMAC:   macA,
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

// Read captures one outbound IP packet from <name> (the user-facing GRETap).
// Only PACKET_OUTGOING (4) frames — packets the local stack is sending out —
// are forwarded to WireGuard.  Inbound packets injected by our own Write()
// have pkttype=PACKET_HOST (0) and must not be re-sent (would cause a loop).
// We use RawConn.Read so the read integrates with Go's network poller (non-
// blocking fd + goroutine scheduling) while still obtaining the sockaddr_ll.
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
				return false // not ready; tell poller to wait
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

// Write injects decrypted IP packets inbound into <name>_ (the peer GRETap) so
// the kernel delivers them to local sockets via <name>.
// The dst MAC must be set to <name>'s real MAC so the kernel marks the frame
// as PACKET_HOST and passes it up the IP stack (zero dst → PACKET_OTHERHOST → dropped).
func (t *GRETun) Write(bufs [][]byte, offset int) (int, error) {
	sll := unix.RawSockaddrLinklayer{
		Family:  unix.AF_PACKET,
		Ifindex: t.writeIfIndex,
		Halen:   6,
	}
	copy(sll.Addr[:6], t.writeDstMAC[:])

	for i, buf := range bufs {
		pkt := buf[offset:]
		if len(pkt) == 0 {
			continue
		}
		if pkt[0]>>4 == 6 {
			sll.Protocol = ethPIP6
		} else {
			sll.Protocol = ethPIP
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

// Name returns the user-facing GRETap interface name (<name>), which holds the
// WireGuard IP address and is the name wireguard-go advertises via UAPI.
func (t *GRETun) Name() (string, error) { return t.name, nil }
func (t *GRETun) Events() <-chan Event  { return t.events }
func (t *GRETun) BatchSize() int        { return 1 }

func (t *GRETun) Close() error {
	var firstErr error
	t.closeOnce.Do(func() {
		t.shutdownOnce.Do(func() { close(t.shutdown) })
		t.netlinkCancel.Close()
		if err := t.readFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		unix.Close(t.writeFd)
		if err := greNetlinkDelLink(t.name); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := greNetlinkDelLink(t.name + greTapPeerSuffix); err != nil && firstErr == nil {
			firstErr = err
		}
		_ = greLoAddrDel(t.loAddrA)
		_ = greLoAddrDel(t.loAddrB)
	})
	return firstErr
}

// routineNetlinkListener watches RTM_NEWLINK for <name> and emits EventMTUUpdate.
// Up/Down events are handled at startup only.
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
			remain = remain[greAlign4(int(hdr.Len)):]

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

func greOpenPacketSock(ifIndex int32) (int, error) {
	fd, err := unix.Socket(
		unix.AF_PACKET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK,
		int(ethPAll),
	)
	if err != nil {
		return -1, err
	}
	sll := unix.RawSockaddrLinklayer{
		Family:   unix.AF_PACKET,
		Protocol: ethPAll,
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

// ── netlink helpers ───────────────────────────────────────────────────────────

func greCreateNetlinkSocket() (int, error) {
	sock, err := unix.Socket(
		unix.AF_NETLINK,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC,
		unix.NETLINK_ROUTE,
	)
	if err != nil {
		return -1, err
	}
	saddr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_LINK,
	}
	if err = unix.Bind(sock, saddr); err != nil {
		unix.Close(sock)
		return -1, err
	}
	return sock, nil
}

// greNetlinkAddGRETap creates a single GRETAP interface.
// Equivalent to: ip link add <name> type gretap local <local> remote <remote>
func greNetlinkAddGRETap(name string, local, remote netip.Addr) error {
	const (
		iflaInfoKind  = 1
		iflaInfoData  = 2
		iflaGreLocal  = 6
		iflaGreRemote = 7
	)
	local4 := local.As4()
	remote4 := remote.As4()
	infoData := greNlattr(iflaInfoData,
		append(
			greNlattr(iflaGreLocal, local4[:]),
			greNlattr(iflaGreRemote, remote4[:])...,
		),
	)
	linkInfo := greNlattr(unix.IFLA_LINKINFO,
		append(
			greNlattr(iflaInfoKind, append([]byte("gretap"), 0)),
			infoData...,
		),
	)
	ifNameAttr := greNlattr(unix.IFLA_IFNAME, append([]byte(name), 0))
	ifInfo := unix.IfInfomsg{Family: unix.AF_UNSPEC}
	return greNetlinkRequest(
		unix.RTM_NEWLINK,
		unix.NLM_F_REQUEST|unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK,
		(*[unix.SizeofIfInfomsg]byte)(unsafe.Pointer(&ifInfo))[:],
		append(ifNameAttr, linkInfo...),
	)
}

// greGetLoAddr returns the loopback tunnel endpoint address from the given env
// var, falling back to def if unset or invalid.
func greGetLoAddr(env, def string) netip.Addr {
	if s := os.Getenv(env); s != "" {
		if addr, err := netip.ParseAddr(s); err == nil {
			return addr
		}
	}
	return netip.MustParseAddr(def)
}

// greAddrAdd adds a /32 address to greTapLoopback via RTM_NEWADDR.
// Equivalent to: ip addr add <addr>/32 dev lo
func greLoAddrAdd(addr netip.Addr) error {
	return greAddrMod(greTapLoopback, addr, 32, true)
}

// greAddrDel removes a /32 address from greTapLoopback via RTM_DELADDR.
func greLoAddrDel(addr netip.Addr) error {
	return greAddrMod(greTapLoopback, addr, 32, false)
}

func greAddrMod(iface string, addr netip.Addr, prefixLen uint8, add bool) error {
	ifIndex, err := greIoctlGetIndex(iface)
	if err != nil {
		return err
	}
	addr4 := addr.As4()
	// IFA_ADDRESS and IFA_LOCAL both set to the same address.
	addrAttr := append(
		greNlattr(unix.IFA_ADDRESS, addr4[:]),
		greNlattr(unix.IFA_LOCAL, addr4[:])...,
	)
	ifAddr := unix.IfAddrmsg{
		Family:    unix.AF_INET,
		Prefixlen: prefixLen,
		Index:     uint32(ifIndex),
	}
	typ := uint16(unix.RTM_NEWADDR)
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK)
	if add {
		flags |= unix.NLM_F_CREATE | unix.NLM_F_EXCL
	} else {
		typ = unix.RTM_DELADDR
	}
	return greNetlinkRequest(
		typ, flags,
		(*[unix.SizeofIfAddrmsg]byte)(unsafe.Pointer(&ifAddr))[:],
		addrAttr,
	)
}

// greNetlinkDelLink issues RTM_DELLINK to remove the named interface.
func greNetlinkDelLink(name string) error {
	ifIndex, err := greIoctlGetIndex(name)
	if err != nil {
		return err
	}
	ifInfo := unix.IfInfomsg{
		Family: unix.AF_UNSPEC,
		Index:  ifIndex,
	}
	return greNetlinkRequest(
		unix.RTM_DELLINK,
		unix.NLM_F_REQUEST|unix.NLM_F_ACK,
		(*[unix.SizeofIfInfomsg]byte)(unsafe.Pointer(&ifInfo))[:],
		nil,
	)
}

// greNetlinkRequest sends a single NETLINK_ROUTE request and waits for ACK.
func greNetlinkRequest(typ, flags uint16, ifInfoBuf, attrs []byte) error {
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
	msg := make([]byte, greAlign4(msgLen))
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
			return errors.New("gretun: short netlink reply")
		}
		rh := *(*unix.NlMsghdr)(unsafe.Pointer(&reply[0]))
		switch rh.Type {
		case unix.NLMSG_ERROR:
			if n < unix.SizeofNlMsghdr+4 {
				return errors.New("gretun: truncated NLMSG_ERROR")
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

// greNlattr encodes a netlink attribute: 4-byte NLA header + padded data.
func greNlattr(typ int, data []byte) []byte {
	l := 4 + len(data)
	b := make([]byte, greAlign4(l))
	binary.NativeEndian.PutUint16(b[0:2], uint16(l))
	binary.NativeEndian.PutUint16(b[2:4], uint16(typ))
	copy(b[4:], data)
	return b
}

// greAlign4 rounds n up to the nearest 4-byte boundary.
func greAlign4(n int) int {
	return (n + 3) &^ 3
}

// ── ioctl helpers ─────────────────────────────────────────────────────────────

const greIfReqSize = unix.IFNAMSIZ + 64

func greIoctlGetMAC(name string) ([6]byte, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return [6]byte{}, err
	}
	defer unix.Close(fd)
	var ifr [greIfReqSize]byte
	copy(ifr[:], name)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.SIOCGIFHWADDR), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return [6]byte{}, errno
	}
	// SIOCGIFHWADDR: sa_family (2 bytes) + MAC (6 bytes) at offset IFNAMSIZ
	var mac [6]byte
	copy(mac[:], ifr[unix.IFNAMSIZ+2:unix.IFNAMSIZ+8])
	return mac, nil
}

func greIoctlGetIndex(name string) (int32, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	var ifr [greIfReqSize]byte
	copy(ifr[:], name)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.SIOCGIFINDEX), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return 0, errno
	}
	return *(*int32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])), nil
}

func greIoctlSetMTU(name string, mtu int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var ifr [greIfReqSize]byte
	copy(ifr[:], name)
	*(*int32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = int32(mtu)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.SIOCSIFMTU), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return errno
	}
	return nil
}

// greIoctlSetUpNoARP brings the interface up and disables ARP so the kernel
// does not issue ARP requests for peer IPs on the interface (matching the
// behaviour of point-to-point tunnel interfaces like TUN).
func greIoctlSetUpNoARP(name string) error {
	return greIoctlSetFlags(name, unix.IFF_UP|unix.IFF_NOARP, 0)
}

func greIoctlSetFlags(name string, set, clear uint16) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var ifr [greIfReqSize]byte
	copy(ifr[:], name)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return errno
	}
	flags := *(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ]))
	flags = (flags | set) &^ clear
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return errno
	}
	return nil
}
