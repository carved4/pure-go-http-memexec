package vm

import (
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var suspicion int = 0

func CheckSleepDrift() {
	start := time.Now()
	time.Sleep(3 * time.Second)
	elapsed := time.Since(start).Milliseconds()
	if elapsed != 3000 {
		suspicion += 1
		return
	}
}

func CheckUptime() {
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	getTickCount64 := k32.NewProc("GetTickCount64")
	ret, _, _ := getTickCount64.Call()
	uptimeMinutes := ret / 1000 / 60
	if uptimeMinutes < 10 {
		suspicion += 1
		return
	}
}

var (
	user32                 = syscall.NewLazyDLL("user32.dll")
	procEnumDisplayDevices = user32.NewProc("EnumDisplayDevicesW")
)

type DisplayDevice struct {
	cb           uint32
	DeviceName   [32]uint16
	DeviceString [128]uint16
	StateFlags   uint32
	DeviceID     [128]uint16
	DeviceKey    [128]uint16
}

func CheckGPU() {
	var dev DisplayDevice
	dev.cb = uint32(unsafe.Sizeof(dev))
	// call EnumDisplayDevices(nil, 0, &dev, 0) to get the primary GPU
	r, _, _ := procEnumDisplayDevices.Call(
		0,
		0,
		uintptr(unsafe.Pointer(&dev)),
		0,
	)
	if r == 0 {
		return
	}
	name := syscall.UTF16ToString(dev.DeviceString[:])
	if !strings.Contains(strings.ToUpper(name), "NVIDIA") &&
		!strings.Contains(strings.ToUpper(name), "AMD") &&
		!strings.Contains(strings.ToUpper(name), "INTEL") {
		suspicion += 1
		return
	}
}

func CheckCoreCount() {
	count := runtime.NumCPU()
	if count < 4 {
		suspicion += 1
		return
	}
}
