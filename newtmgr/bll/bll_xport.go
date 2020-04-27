// +build !windows

/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package bll

import (
	"fmt"

	"github.com/go-ble/ble"
	"github.com/go-ble/ble/examples/lib/dev"
	"mynewt.apache.org/newtmgr/nmxact/bledefs"
	"mynewt.apache.org/newtmgr/nmxact/sesn"
)

type XportCfg struct {
	CtlrName    string
	OwnAddrType bledefs.BleAddrType
}

func NewXportCfg() XportCfg {
	return XportCfg{
		CtlrName: "default",
	}
}

type BllXport struct {
	cfg    XportCfg
	hciIdx int
}

func NewBllXport(cfg XportCfg, hciIdx int) *BllXport {
	return &BllXport{
		cfg:    cfg,
		hciIdx: hciIdx,
	}
}

func (bx *BllXport) BuildSesn(cfg sesn.SesnCfg) (sesn.Sesn, error) {
	return nil, fmt.Errorf("BllXport.BuildSesn() not supported; " +
		"use BllXport.BuildBllSesn instead")
}

func (bx *BllXport) BuildBllSesn(cfg BllSesnCfg) (sesn.Sesn, error) {
	return NewBllSesn(cfg), nil
}

type myreadhandler struct {
}

func (m *myreadhandler) ServeRead(req ble.Request, rsp ble.ResponseWriter) {
	rsp.Write([]byte{99, 1, 2, 3, 4, 5, 6, 7})
}
func (m *myreadhandler) ServeWrite(req ble.Request, rsp ble.ResponseWriter) {
	if len(req.Data())%2 != 0 {
		rsp.SetStatus(ble.ATTError(1))
	}
}

func (bx *BllXport) Start() error {
	d, err := dev.NewDevice(bx.cfg.CtlrName, ble.OptDeviceID(bx.hciIdx))
	if err != nil {
		return fmt.Errorf("[hci%d]: %s", bx.hciIdx, err)
	}

	// Set the connection parameters to use for all initiated connections.
	if err := BllXportSetConnParams(d, bx.cfg.OwnAddrType); err != nil {
		return err
	}

	ble.SetDefaultDevice(d)

	/*
		svc := ble.NewService(ble.UUID16(0x1234))
		chr := ble.NewCharacteristic(ble.UUID16(0x5678))
		chr.Property = ble.CharRead | ble.CharWriteNR
		chr.Value = nil
		chr.ReadHandler = &myreadhandler{}
		chr.WriteHandler = &myreadhandler{}
		svc.Characteristics = append(svc.Characteristics, chr)

		chr.HandleNotify(ble.NotifyHandlerFunc(func(req ble.Request, n ble.Notifier) {
			cnt := 0
			fmt.Printf("count: Notification subscribed")
			for {
				select {
				case <-n.Context().Done():
					fmt.Printf("count: Notification unsubscribed\n")
					return
				case <-time.After(time.Second):
					fmt.Printf("count: Notify: %d\n", cnt)
					if _, err := fmt.Fprintf(n, "Count: %d", cnt); err != nil {
						// Client disconnected prematurely before unsubscription.
						fmt.Printf("count: Failed to notify : %s\n", err)
						return
					}
					cnt++
				}
			}
		}))

		err = d.SetServices([]*ble.Service{svc})
		if err != nil {
			panic(err)
		}

		//err = d.AdvertiseIBeacon(context.TODO(), ble.UUID16(0x1234), 0x1234, 0x5678, 120)
		err = d.AdvertiseNameAndServices(context.TODO(), "yourMOM", ble.UUID16(0x1234))
		if err != nil {
			panic(err)
		}
	*/

	return nil
}

func (bx *BllXport) Stop() error {
	if err := ble.Stop(); err != nil {
		return err
	}

	return nil
}

func (bx *BllXport) Tx(data []byte) error {
	return fmt.Errorf("BllXport.Tx() not supported")
}
