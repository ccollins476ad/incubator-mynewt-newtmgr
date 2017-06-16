// +build !linux

package bll

import (
	"github.com/currantlabs/ble/linux"
)

func setConnParams(d *linux.Device) error {
	return nil
}
