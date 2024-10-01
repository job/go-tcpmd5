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
	"syscall"
)

func setsockOptString(sc syscall.RawConn, level int, opt int, str string) error {
	var opterr error
	fn := func(s uintptr) {
		opterr = syscall.SetsockoptString(int(s), level, opt, str)
	}
	err := sc.Control(fn)
	if opterr == nil {
		return err
	}
	return opterr
}

func setsockOptInt(sc syscall.RawConn, level, name, value int) error {
	var opterr error
	fn := func(s uintptr) {
		opterr = syscall.SetsockoptInt(int(s), level, name, value)
	}
	err := sc.Control(fn)
	if opterr == nil {
		return err
	}
	return opterr
}
