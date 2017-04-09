package nmxutil

import (
	"math/rand"
	"sync"

	"mynewt.apache.org/newt/util"
)

var nextNmpSeq uint8
var beenRead bool
var seqMutex sync.Mutex

func NextNmpSeq() uint8 {
	seqMutex.Lock()
	defer seqMutex.Unlock()

	if !beenRead {
		nextNmpSeq = uint8(rand.Uint32())
		beenRead = true
	}

	val := nextNmpSeq
	nextNmpSeq++

	return val
}

type DbgMutex struct {
	mtx      sync.Mutex
	stateMtx sync.Mutex
	locked   bool
	owner    uint64
}

func (m *DbgMutex) Lock() {
	m.stateMtx.Lock()
	defer m.stateMtx.Unlock()

	gid := util.GetGID()

	if m.locked && m.owner == gid {
		panic("Mutex double lock")
	}

	m.mtx.Lock()
	m.locked = true
	m.owner = gid
}

func (m *DbgMutex) Unlock() {
	m.stateMtx.Lock()
	defer m.stateMtx.Unlock()

	if !m.locked {
		panic("Mutex double unlock")
	}

	m.mtx.Unlock()
	m.locked = false
}

func (m *DbgMutex) AssertLocked() {
	m.stateMtx.Lock()
	defer m.stateMtx.Unlock()

	if !m.locked || m.owner != util.GetGID() {
		panic("Mutex not locked when it should be")
	}
}
