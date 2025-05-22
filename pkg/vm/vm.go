package vm 


import (
    "github.com/klauspost/cpuid/v2"
    "strings"
)

var ignoreVendors = map[string]bool{
    "Microsoft Hv":     true,
    "TCGTCGTCGTCG":     true,
    "KVMKVMKVM":        true,
    "XenVMMXenVMM":     true, 
    "bhyve bhyve":      true, 
}

func IsVM() (bool, string) {
	if cpuid.CPU.VM() {
		vendor := cpuid.CPU.HypervisorVendorString
		if vendor == "" {
			vendor = cpuid.CPU.HypervisorVendorID.String()
		}

		if ignoreVendors[strings.TrimSpace(vendor)] {
			return false, vendor
		}
		return true, vendor
	}
	return false, ""
}
