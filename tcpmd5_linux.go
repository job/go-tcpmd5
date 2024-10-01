// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcpmd5

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/sys/unix"
)

func buildTcpMD5Sig(address, key string) *unix.TCPMD5Sig {
	t := unix.TCPMD5Sig{}

	var addr net.IP
	if strings.Contains(address, "/") {
		var err error
		var ipnet *net.IPNet
		addr, ipnet, err = net.ParseCIDR(address)
		if err != nil {
			return nil
		}
		prefixlen, _ := ipnet.Mask.Size()
		t.Prefixlen = uint8(prefixlen)
		t.Flags = unix.TCP_MD5SIG_FLAG_PREFIX
	} else {
		addr = net.ParseIP(address)
	}

	if addr.To4() != nil {
		t.Addr.Family = unix.AF_INET
		copy(t.Addr.Data[2:], addr.To4())
	} else {
		t.Addr.Family = unix.AF_INET6
		copy(t.Addr.Data[6:], addr.To16())
	}

	t.Keylen = uint16(len(key))
	copy(t.Key[0:], []byte(key))

	return &t
}

func setTCPMD5SigSockopt(l *net.TCPListener, address string, key string) error {
	sc, err := l.SyscallConn()
	if err != nil {
		return err
	}

	var sockerr error
	t := buildTcpMD5Sig(address, key)
	if t == nil {
		return fmt.Errorf("unable to generate TcpMD5Sig from %s", address)
	}
	if err := sc.Control(func(s uintptr) {
		opt := unix.TCP_MD5SIG

		if t.Prefixlen != 0 {
			opt = unix.TCP_MD5SIG_EXT
		}

		sockerr = unix.SetsockoptTCPMD5Sig(int(s), unix.IPPROTO_TCP, opt, t)
	}); err != nil {
		return err
	}
	return sockerr
}
