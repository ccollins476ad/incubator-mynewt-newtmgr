package nmble

import (
	"encoding/hex"
	"fmt"
	"time"

	log "github.com/Sirupsen/logrus"

	. "mynewt.apache.org/newtmgr/nmxact/bledefs"
	"mynewt.apache.org/newtmgr/nmxact/nmp"
	"mynewt.apache.org/newtmgr/nmxact/nmxutil"
	"mynewt.apache.org/newtmgr/nmxact/sesn"
)

const DFLT_ATT_MTU = 23

type BleSesnState int32

const (
	SESN_STATE_UNCONNECTED     BleSesnState = 0
	SESN_STATE_SCANNING                     = 1
	SESN_STATE_CONNECTING                   = 2
	SESN_STATE_EXCHANGE_MTU                 = 3
	SESN_STATE_DISCOVER_SVC                 = 4
	SESN_STATE_DISCOVER_CHR                 = 5
	SESN_STATE_SUBSCRIBE                    = 6
	SESN_STATE_DONE                         = 7
	SESN_STATE_TERMINATING                  = 8
	SESN_STATE_CONN_CANCELLING              = 9
)

type BleFsmDisconnectType int

const (
	FSM_DISCONNECT_TYPE_UNOPENED BleFsmDisconnectType = iota
	FSM_DISCONNECT_TYPE_IMMEDIATE_TIMEOUT
	FSM_DISCONNECT_TYPE_OPENED
	FSM_DISCONNECT_TYPE_REQUESTED
)

type BleRxNmpFn func(data []byte)
type BleDisconnectFn func(dt BleFsmDisconnectType, peer BleDev, err error)

type BleFsmParams struct {
	Bx           *BleXport
	OwnAddrType  BleAddrType
	PeerSpec     sesn.BlePeerSpec
	SvcUuid      BleUuid
	ReqChrUuid   BleUuid
	RspChrUuid   BleUuid
	RxNmpCb      BleRxNmpFn
	DisconnectCb BleDisconnectFn
}

type BleFsm struct {
	params BleFsmParams

	peerDev         *BleDev
	connHandle      uint16
	nmpSvc          *BleSvc
	nmpReqChr       *BleChr
	nmpRspChr       *BleChr
	attMtu          int
	connChan        chan error
	lastStateChange time.Time
	stateMtx        nmxutil.DbgMutex
	blsMtx          nmxutil.DbgMutex
	openMtx         nmxutil.DbgMutex

	// These variables must be protected by the mutex.
	bls   map[*BleListener]struct{}
	state BleSesnState
}

func NewBleFsm(p BleFsmParams) *BleFsm {
	bf := &BleFsm{
		params: p,

		bls:    map[*BleListener]struct{}{},
		attMtu: DFLT_ATT_MTU,
	}

	return bf
}

func (bf *BleFsm) disconnectError(reason int) error {
	str := fmt.Sprintf("BLE peer disconnected; "+
		"reason=\"%s\" (%d) peer=%s handle=%d",
		ErrCodeToString(reason), reason, bf.peerDev.String(), bf.connHandle)
	return nmxutil.NewBleSesnDisconnectError(reason, str)
}

func (bf *BleFsm) closedError(msg string) error {
	return nmxutil.NewSesnClosedError(fmt.Sprintf(
		"%s; state=%d last-state-change=%s",
		msg, bf.getState(), bf.lastStateChange))
}

func (bf *BleFsm) getState() BleSesnState {
	bf.stateMtx.Lock()
	defer bf.stateMtx.Unlock()

	return bf.state
}

func (bf *BleFsm) setStateNoLock(toState BleSesnState) {
	bf.stateMtx.AssertLocked()

	bf.state = toState
	bf.lastStateChange = time.Now()
}

func (bf *BleFsm) setState(toState BleSesnState) {
	bf.stateMtx.Lock()
	defer bf.stateMtx.Unlock()

	return bf.setStateNoLock(toState)
}

func (bf *BleFsm) addBleListener(base BleMsgBase) (*BleListener, error) {
	bl := NewBleListener()

	bf.blsMtx.Lock()
	defer bf.blsMtx.Unlock()

	if err := bf.params.Bx.Bd.AddListener(base, bl); err != nil {
		return nil, err
	}

	bf.bls[bl] = struct{}{}
	return bl, nil
}

func (bf *BleFsm) addBleSeqListener(seq BleSeq) (*BleListener, error) {
	base := BleMsgBase{
		Op:         -1,
		Type:       -1,
		Seq:        seq,
		ConnHandle: -1,
	}
	bl, err := bf.addBleListener(base)
	if err != nil {
		return nil, err
	}

	return bl, nil
}

func (bf *BleFsm) removeBleListener(base BleMsgBase) {
	bf.blsMtx.Lock()
	defer bf.blsMtx.Unlock()

	bl := bf.params.Bx.Bd.RemoveListener(base)
	if bl != nil {
		delete(bf.bls, bl)
	}
}

func (bf *BleFsm) removeBleSeqListener(seq BleSeq) {
	base := BleMsgBase{
		Op:         -1,
		Type:       -1,
		Seq:        seq,
		ConnHandle: -1,
	}

	bf.removeBleListener(base)
}

func (bf *BleFsm) logConnection() {
	desc, err := ConnFindXact(bf.params.Bx, bf.connHandle)
	if err != nil {
		return
	}

	log.Debugf("BLE connection attempt succeeded; %s", desc.String())
}

func calcDisconnectType(state BleSesnState) BleFsmDisconnectType {
	switch state {
	case SESN_STATE_EXCHANGE_MTU:
		return FSM_DISCONNECT_TYPE_IMMEDIATE_TIMEOUT

	case SESN_STATE_DONE:
		return FSM_DISCONNECT_TYPE_OPENED

	case SESN_STATE_TERMINATING, SESN_STATE_CONN_CANCELLING:
		return FSM_DISCONNECT_TYPE_REQUESTED

	default:
		return FSM_DISCONNECT_TYPE_UNOPENED
	}
}

func (bf *BleFsm) errorAll(err error) {
	bf.blsMtx.Lock()
	defer bf.blsMtx.Unlock()

	for bl, _ := range bf.bls {
		bl.ErrChan <- err
	}
}

func (bf *BleFsm) resetState(err error) {
	// Subsequent start attempts will block until the reset is complete.
	bf.openMtx.Lock()
	defer bf.openMtx.Unlock()

	bf.errorAll(err)

	bf.stateMtx.Lock()
	defer bf.stateMtx.Unlock()

	bf.setStateNoLock(SESN_STATE_UNCONNECTED)
	bf.peerDev = nil
}

func (bf *BleFsm) blockUntilReset() {
	bf.openMtx.Lock()
	bf.openMtx.Unlock()
}

func (bf *BleFsm) onDisconnect(err error) {
	// Remember some fields before we clear them.
	dt := calcDisconnectType(bf.state)
	peer := *bf.peerDev

	bf.resetState(err)

	bf.params.DisconnectCb(dt, peer, err)
}

func (bf *BleFsm) connectListen(seq BleSeq) error {
	bf.connChan = make(chan error, 1)

	bl, err := bf.addBleSeqListener(seq)
	if err != nil {
		return err
	}

	go func() {
		defer bf.removeBleSeqListener(seq)
		for {
			select {
			case err := <-bl.ErrChan:
				// Transport reported error.  Assume the connection has
				// dropped.
				bf.onDisconnect(err)
				return

			case bm := <-bl.BleChan:
				switch msg := bm.(type) {
				case *BleConnectRsp:
					bl.Acked = true
					if msg.Status != 0 {
						str := fmt.Sprintf("BLE connection attempt failed; "+
							"status=%s (%d) peer=%s",
							ErrCodeToString(msg.Status), msg.Status,
							bf.peerDev.String())
						log.Debugf(str)
						bf.connChan <- nmxutil.NewBleHostError(msg.Status, str)
						return
					} else {
						bf.connChan <- nil
					}

				case *BleConnectEvt:
					if msg.Status == 0 {
						bl.Acked = true
						bf.connHandle = msg.ConnHandle
						bf.logConnection()
						if err := bf.nmpRspListen(); err != nil {
							bf.connChan <- err
							return
						}
						bf.connChan <- nil
					} else {
						str := fmt.Sprintf("BLE connection attempt failed; "+
							"status=%s (%d) peer=%s",
							ErrCodeToString(msg.Status), msg.Status,
							bf.peerDev.String())
						log.Debugf(str)
						bf.connChan <- nmxutil.NewBleHostError(msg.Status, str)
						return
					}

				case *BleMtuChangeEvt:
					if msg.Status != 0 {
						err := StatusError(MSG_OP_EVT,
							MSG_TYPE_MTU_CHANGE_EVT,
							msg.Status)
						log.Debugf(err.Error())
					} else {
						log.Debugf("BLE ATT MTU updated; from=%d to=%d",
							bf.attMtu, msg.Mtu)
						bf.attMtu = int(msg.Mtu)
					}

				case *BleDisconnectEvt:
					err := bf.disconnectError(msg.Reason)
					bf.onDisconnect(err)
					return

				default:
				}

			case <-bl.AfterTimeout(bf.params.Bx.RspTimeout()):
				bf.connChan <- BhdTimeoutError(MSG_TYPE_CONNECT)
			}
		}
	}()
	return nil
}

func (bf *BleFsm) nmpRspListen() error {
	base := BleMsgBase{
		Op:         MSG_OP_EVT,
		Type:       MSG_TYPE_NOTIFY_RX_EVT,
		Seq:        BLE_SEQ_NONE,
		ConnHandle: int(bf.connHandle),
	}

	bl, err := bf.addBleListener(base)
	if err != nil {
		return err
	}

	go func() {
		defer bf.removeBleListener(base)
		for {
			select {
			case <-bl.ErrChan:
				// The session encountered an error; stop listening.
				return
			case bm := <-bl.BleChan:
				switch msg := bm.(type) {
				case *BleNotifyRxEvt:
					if bf.nmpRspChr != nil &&
						msg.AttrHandle == bf.nmpRspChr.ValHandle {

						bf.params.RxNmpCb(msg.Data.Bytes)
					}

				default:
				}
			}
		}
	}()
	return nil
}

func (bf *BleFsm) connect() error {
	bf.stateMtx.AssertLocked()

	r := NewBleConnectReq()
	r.OwnAddrType = bf.params.OwnAddrType
	r.PeerAddrType = bf.peerDev.AddrType
	r.PeerAddr = bf.peerDev.Addr

	if err := bf.connectListen(r.Seq); err != nil {
		return err
	}

	if err := bf.params.Bx.AcquireMaster(); err != nil {
		return err
	}

	if err := connect(bf.params.Bx, bf.connChan, r); err != nil {
		bf.params.Bx.ReleaseMaster()
		return err
	}

	bf.state = SESN_STATE_CONNECTING

	err := <-bf.connChan
	if !nmxutil.IsXport(err) {
		if err := bf.connCancel(); err != nil {
			// Failed to cancel connect in progress.
			// XXX: Reset xport.
			return err
		}
		bf.params.Bx.ReleaseMaster()
	}

	return err
}

func (bf *BleFsm) scan() error {
	bf.stateMtx.AssertLocked()

	r := NewBleScanReq()
	r.OwnAddrType = bf.params.OwnAddrType
	r.DurationMs = 15000
	r.FilterPolicy = BLE_SCAN_FILT_NO_WL
	r.Limited = false
	r.Passive = false
	r.FilterDuplicates = true

	bl, err := bf.addBleSeqListener(r.Seq)
	if err != nil {
		return err
	}
	defer bf.removeBleSeqListener(r.Seq)

	abortChan := make(chan struct{})

	// This function gets called when scanning begins.
	scanSuccessCb := func() { bf.state = SESN_STATE_SCANNING }

	// This function gets called for each incoming advertisement.
	advRptCb := func(r BleAdvReport) {
		// Ask client if we should connect to this advertiser.
		if bf.params.PeerSpec.ScanPred(r) {
			bf.peerDev = &r.Sender
			abortChan <- struct{}{}
		}
	}

	if err := bf.params.Bx.AcquireMaster(); err != nil {
		return err
	}

	err = scan(bf.params.Bx, bl, r, abortChan, scanSuccessCb, advRptCb)
	if bf.state == SESN_STATE_SCANNING && !nmxutil.IsXport(err) {
		// Scanning still in progress; cancel the operation.
		if err := bf.scanCancel(); err != nil {
			// Failed to cancel scan in progress.
			// XXX: Reset xport.
			return err
		}
		bf.params.Bx.ReleaseMaster()
	}

	return err
}

func (bf *BleFsm) scanCancel() error {
	r := NewBleScanCancelReq()

	bl, err := bf.addBleSeqListener(r.Seq)
	if err != nil {
		return err
	}
	defer bf.removeBleSeqListener(r.Seq)

	if err := scanCancel(bf.params.Bx, bl, r); err != nil {
		return err
	}

	return nil
}

func (bf *BleFsm) terminateSetState() error {
	bf.stateMtx.Lock()
	defer bf.stateMtx.Unlock()

	switch bf.state {
	case SESN_STATE_UNCONNECTED,
		SESN_STATE_CONNECTING,
		SESN_STATE_CONN_CANCELLING:
		return fmt.Errorf("BLE terminate failed; not connected")
	case SESN_STATE_TERMINATING:
		return fmt.Errorf(
			"BLE terminate failed; session already being closed")
	default:
		bf.setStateNoLock(SESN_STATE_TERMINATING)
	}

	return nil
}

func (bf *BleFsm) terminate() error {
	if err := bf.terminateSetState(); err != nil {
		return err
	}

	r := NewBleTerminateReq()
	r.ConnHandle = bf.connHandle
	r.HciReason = ERR_CODE_HCI_REM_USER_CONN_TERM

	bl, err := bf.addBleSeqListener(r.Seq)
	if err != nil {
		return err
	}
	defer bf.removeBleSeqListener(r.Seq)

	if err := terminate(bf.params.Bx, bl, r); err != nil {
		return err
	}

	return nil
}

func (bf *BleFsm) connCancel() error {
	r := NewBleConnCancelReq()
	bl, err := bf.addBleSeqListener(r.Seq)
	if err != nil {
		return err
	}
	defer bf.removeBleSeqListener(r.Seq)

	if err := connCancel(bf.params.Bx, bl, r); err != nil {
		return err
	}

	return nil
}

func (bf *BleFsm) discSvcUuid() error {
	r := NewBleDiscSvcUuidReq()
	r.ConnHandle = bf.connHandle
	r.Uuid = bf.params.SvcUuid

	bl, err := bf.addBleSeqListener(r.Seq)
	if err != nil {
		return err
	}
	defer bf.removeBleSeqListener(r.Seq)

	bf.nmpSvc, err = discSvcUuid(bf.params.Bx, bl, r)
	if err != nil {
		return err
	}

	return nil
}

func (bf *BleFsm) discAllChrs() error {
	r := NewBleDiscAllChrsReq()
	r.ConnHandle = bf.connHandle
	r.StartHandle = bf.nmpSvc.StartHandle
	r.EndHandle = bf.nmpSvc.EndHandle

	bl, err := bf.addBleSeqListener(r.Seq)
	if err != nil {
		return err
	}
	defer bf.removeBleSeqListener(r.Seq)

	chrs, err := discAllChrs(bf.params.Bx, bl, r)
	if err != nil {
		return err
	}

	for _, c := range chrs {
		if CompareUuids(bf.params.ReqChrUuid, c.Uuid) == 0 {
			bf.nmpReqChr = c
		}
		if CompareUuids(bf.params.RspChrUuid, c.Uuid) == 0 {
			bf.nmpRspChr = c
		}
	}

	if bf.nmpReqChr == nil {
		return fmt.Errorf(
			"Peer doesn't support required characteristic: %s",
			bf.params.ReqChrUuid.String())
	}

	if bf.nmpRspChr == nil {
		return fmt.Errorf(
			"Peer doesn't support required characteristic: %s",
			bf.params.RspChrUuid.String())
	}

	return nil
}

func (bf *BleFsm) exchangeMtu() error {
	r := NewBleExchangeMtuReq()
	r.ConnHandle = bf.connHandle

	bl, err := bf.addBleSeqListener(r.Seq)
	if err != nil {
		return err
	}
	defer bf.removeBleSeqListener(r.Seq)

	mtu, err := exchangeMtu(bf.params.Bx, bl, r)
	if err != nil {
		return err
	}

	bf.attMtu = mtu
	return nil
}

func (bf *BleFsm) writeCmd(data []byte) error {
	r := NewBleWriteCmdReq()
	r.ConnHandle = bf.connHandle
	r.AttrHandle = bf.nmpReqChr.ValHandle
	r.Data.Bytes = data

	bl, err := bf.addBleSeqListener(r.Seq)
	if err != nil {
		return err
	}
	defer bf.removeBleSeqListener(r.Seq)

	if err := writeCmd(bf.params.Bx, bl, r); err != nil {
		return err
	}

	return nil
}

func (bf *BleFsm) subscribe() error {
	r := NewBleWriteCmdReq()
	r.ConnHandle = bf.connHandle
	r.AttrHandle = bf.nmpRspChr.ValHandle + 1
	r.Data.Bytes = []byte{1, 0}

	bl, err := bf.addBleSeqListener(r.Seq)
	if err != nil {
		return err
	}
	defer bf.removeBleSeqListener(r.Seq)

	if err := writeCmd(bf.params.Bx, bl, r); err != nil {
		return err
	}

	return nil
}

// Tries to populate the FSM's peerDev field.  This function succeeds if the
// client specified the address of the peer to connect to.
func (bf *BleFsm) tryFillPeerDev() bool {
	// The peer spec contains one of:
	//     * Peer address;
	//     * Predicate function to call during scanning.
	// If a peer address is specified, fill in the peer field now so the
	// scanning step can be skipped.  Otherwise, the peer field gets populated
	// during scanning.
	if bf.params.PeerSpec.ScanPred == nil {
		bf.peerDev = &bf.params.PeerSpec.Dev
		return true
	}

	return false
}

func (bf *BleFsm) executeState() (bool, error) {
	bf.stateMtx.Lock()
	defer bf.stateMtx.Unlock()

	switch bf.state {
	case SESN_STATE_UNCONNECTED:
		// Determine if we can immediately initiate a connection, or if we
		// need to scan for a peer first.  If the client specified a peer
		// address, or if we have already successfully scanned, we initiate
		// a connection now.  Otherwise, we need to scan to determine which
		// peer meets the specified scan criteria.
		bf.tryFillPeerDev()
		if bf.peerDev == nil {
			// Peer not inferred yet.  Initiate scan.
			if err := bf.scan(); err != nil {
				return false, err
			}
			bf.state = SESN_STATE_UNCONNECTED
		} else {
			// We already know the address we want to connect to.  Initiate
			// a connection.
			if err := bf.connect(); err != nil {
				return false, err
			}
			bf.state = SESN_STATE_EXCHANGE_MTU
		}

	case SESN_STATE_EXCHANGE_MTU:
		if err := bf.exchangeMtu(); err != nil {
			return false, err
		}
		bf.state = SESN_STATE_DISCOVER_SVC

	case SESN_STATE_DISCOVER_SVC:
		if err := bf.discSvcUuid(); err != nil {
			return false, err
		}
		bf.state = SESN_STATE_DISCOVER_CHR

	case SESN_STATE_DISCOVER_CHR:
		if err := bf.discAllChrs(); err != nil {
			return false, err
		}
		bf.state = SESN_STATE_SUBSCRIBE

	case SESN_STATE_SUBSCRIBE:
		if err := bf.subscribe(); err != nil {
			return false, err
		}
		bf.state = SESN_STATE_DONE

	case SESN_STATE_DONE:
		/* Open complete. */
		return false, fmt.Errorf("BleFsm already done being opened")

	default:
		return false, fmt.Errorf("BleFsm already being opened")
	}

	return false, nil
}

// @return bool                 Whether another start attempt should be made;
//         error                The error that caused the start attempt to
//                                  fail; nil on success.
func (bf *BleFsm) Start() (bool, error) {
	if !bf.IsClosed() {
		return false, nmxutil.NewSesnAlreadyOpenError(
			"Attempt to open an already-open BLE session")
	}

	bf.blockUntilReset()

	for {
		retry, err := bf.executeState()
		if err != nil {
			bf.resetState()
			return retry, err
		}

		if bf.getState() == SESN_STATE_DONE {
			return false, nil
		}
	}
}

// @return bool                 true if stop complete;
//                              false if disconnect is now pending.
func (bf *BleFsm) Stop() (bool, error) {
	state := bf.getState()

	switch state {
	case SESN_STATE_UNCONNECTED,
		SESN_STATE_TERMINATING,
		SESN_STATE_CONN_CANCELLING:

		return false,
			bf.closedError("Attempt to close an unopened BLE session")

	case SESN_STATE_CONNECTING:
		if err := bf.connCancel(); err != nil {
			return false, err
		}

		bf.connChan <- fmt.Errorf("Connection attempt cancelled")
		return true, nil

	default:
		if err := bf.terminate(); err != nil {
			return false, err
		}
		return false, nil
	}
}

func (bf *BleFsm) IsOpen() bool {
	return bf.getState() == SESN_STATE_DONE
}

func (bf *BleFsm) IsClosed() bool {
	return bf.getState() == SESN_STATE_UNCONNECTED
}

func (bf *BleFsm) TxNmp(payload []byte, nl *nmp.NmpListener,
	timeout time.Duration) (nmp.NmpRsp, error) {

	log.Debugf("Tx NMP request: %s", hex.Dump(payload))
	if err := bf.writeCmd(payload); err != nil {
		return nil, err
	}

	// Now wait for NMP response.
	for {
		select {
		case err := <-nl.ErrChan:
			return nil, err
		case rsp := <-nl.RspChan:
			// Only accept NMP responses if the session is still open.  This is
			// to help prevent race conditions in client code.
			if bf.IsOpen() {
				return rsp, nil
			}
		case <-nl.AfterTimeout(timeout):
			return nil, nmxutil.NewNmpTimeoutError("NMP timeout")
		}
	}
}
