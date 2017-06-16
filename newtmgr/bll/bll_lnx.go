// +build linux

package bll

import (
	"errors"

	"github.com/currantlabs/ble/linux"
)

func setConnParams(d *linux.Device) error {
	if err := d.HCI.Option(hci.OptConnParams(
		cmd.LECreateConnection{
			LEScanInterval:        0x0010,    // 0x0004 - 0x4000; N * 0.625 msec
			LEScanWindow:          0x0010,    // 0x0004 - 0x4000; N * 0.625 msec
			InitiatorFilterPolicy: 0x00,      // White list is not used
			PeerAddressType:       0x00,      // Public Device Address
			PeerAddress:           [6]byte{}, //
			OwnAddressType:        0x00,      // Public Device Address
			ConnIntervalMin:       0x0018,    // 0x0006 - 0x0C80; N * 1.25 msec
			ConnIntervalMax:       0x0028,    // 0x0006 - 0x0C80; N * 1.25 msec
			ConnLatency:           0x0000,    // 0x0000 - 0x01F3; N * 1.25 msec
			SupervisionTimeout:    0x0200,    // 0x000A - 0x0C80; N * 10 msec
			MinimumCELength:       0x0010,    // 0x0000 - 0xFFFF; N * 0.625 msec
			MaximumCELength:       0x0300,    // 0x0000 - 0xFFFF; N * 0.625 msec
		})); err != nil {
		return errors.Wrap(err, "can't set connection param")
	}
	return nil
}
