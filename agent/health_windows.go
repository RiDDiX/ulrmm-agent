// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

const (
	nsStorage  = `root\Microsoft\Windows\Storage`
	nsStdCimv2 = `root\StandardCimv2`
)

// one WMI query for all nics, joined on the adapter name (= net.Interface name)
func wolStates(names []string) map[string]string {
	dst, err := wmiNS[struct {
		Name              string
		WakeOnMagicPacket uint32
	}]("SELECT Name, WakeOnMagicPacket FROM MSFT_NetAdapterPowerManagementSettingData", nsStdCimv2)
	if err != nil {
		return nil
	}
	ret := make(map[string]string)
	for _, d := range dst {
		if s := winWoL(d.WakeOnMagicPacket); s != "" {
			ret[d.Name] = s
		}
	}
	return ret
}

type wscProduct struct {
	DisplayName  string
	ProductState uint32
}

type mpStatus struct {
	AMRunningMode                 string
	AntivirusEnabled              bool
	RealTimeProtectionEnabled     bool
	AntivirusSignatureAge         uint32
	AntivirusSignatureLastUpdated time.Time
}

type physicalDisk struct {
	ObjectId     string
	FriendlyName string
	HealthStatus uint16
	MediaType    uint16
	BusType      uint16
}

type reliabilityCounter struct {
	Temperature    uint8
	TemperatureMax uint8
	PowerOnHours   uint32
}

func healthStages() []healthStage {
	return []healthStage{noCtx(winPower), noCtx(winSecurity), winDisks, noCtx(winBattery), noCtx(winTemps)}
}

// MSAcpi_ThermalZoneTemperature is absent or a static ACPI value on the
// machines measured, CPU sensors need a kernel driver: disks carry the temps
func winTemps(h *Health) {
	h.Temps = make([]HTemp, 0)
}

func winPower(h *Health) {
	var caps [76]byte // SYSTEM_POWER_CAPABILITIES
	if r, _, err := windows.NewLazySystemDLL("powrprof.dll").NewProc("GetPwrCapabilities").Call(uintptr(unsafe.Pointer(&caps[0]))); r == 0 {
		h.errf("GetPwrCapabilities: %v", err)
		return
	}
	h.Power.S3 = ptr(caps[5] != 0)             // SystemS3
	h.Power.ModernStandby = ptr(caps[20] != 0) // AoAc
}

func winSecurity(h *Health) {
	h.AV = make([]HAV, 0)
	// Security Center first: third-party AV (ESET) turns Defender off.
	// Server SKUs have no SecurityCenter2, then only Defender is known. On a
	// workstation (VER_NT_WORKSTATION) a failed query makes the server's check incomplete.
	var av []wscProduct
	if windows.RtlGetVersion().ProductType == 1 {
		var err error
		if av, err = wmiNS[wscProduct]("SELECT displayName, productState FROM AntiVirusProduct", `root\SecurityCenter2`); err != nil {
			h.errf("security center: %v", err)
		}
	}
	for _, p := range av {
		on, fresh := wscState(p.ProductState)
		if len(h.AV) < healthMaxList {
			h.AV = append(h.AV, HAV{Name: clip(p.DisplayName, 128), Enabled: on, UpToDate: ptr(fresh), Src: "wsc"})
		}
	}

	if mp, err := wmiNS[mpStatus]("SELECT AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge, AntivirusSignatureLastUpdated FROM MSFT_MpComputerStatus", `root\Microsoft\Windows\Defender`); err == nil && len(mp) > 0 {
		m := mp[0]
		d := &HDefender{Mode: clip(m.AMRunningMode, 32), AV: m.AntivirusEnabled, RTP: m.RealTimeProtectionEnabled}
		// 65535 = never updated / not running
		if m.AntivirusSignatureAge < 65535 {
			d.SigAgeDays = ptr(int(m.AntivirusSignatureAge))
		}
		if !m.AntivirusSignatureLastUpdated.IsZero() {
			d.SigUpdated = m.AntivirusSignatureLastUpdated.UTC().Format(time.RFC3339)
		}
		h.Defender = d
	}

	fw := &HFirewall{Products: make([]HFwProduct, 0)}
	if fwp, err := wmiNS[wscProduct]("SELECT displayName, productState FROM FirewallProduct", `root\SecurityCenter2`); err == nil {
		for _, p := range fwp {
			on, _ := wscState(p.ProductState)
			if len(fw.Products) < healthMaxList {
				fw.Products = append(fw.Products, HFwProduct{Name: clip(p.DisplayName, 128), Enabled: on})
			}
		}
	}
	profiles, current, err := fwPolicy()
	if err != nil {
		h.errf("FwPolicy2: %v", err)
	} else {
		fw.Profiles = profiles
	}
	// on = a third-party firewall is enabled, or every active profile is
	on := false
	for _, p := range fw.Products {
		on = on || p.Enabled
	}
	if err == nil && len(current) > 0 {
		all := true
		for _, c := range current {
			all = all && profiles[c]
		}
		on = on || all
		fw.Enabled = ptr(on)
	} else if on {
		fw.Enabled = ptr(true)
	}
	h.Firewall = fw
}

// HNetCfg.FwPolicy2: effective state including GPO, and the active profiles
func fwPolicy() (map[string]bool, []string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		if e, ok := err.(*ole.OleError); !ok || (e.Code() != S_OK && e.Code() != S_FALSE) {
			return nil, nil, err
		}
	}
	defer ole.CoUninitialize()

	fw, err := NewCOMObject("HNetCfg.FwPolicy2")
	if err != nil {
		return nil, nil, err
	}
	defer fw.Release()

	cur, err := oleutil.GetProperty(fw, "CurrentProfileTypes")
	if err != nil {
		return nil, nil, err
	}
	mask, _ := cur.Value().(int32)
	cur.Clear()

	profiles := make(map[string]bool)
	current := make([]string, 0)
	for _, p := range []struct {
		bit  int32
		name string
	}{{1, "domain"}, {2, "private"}, {4, "public"}} {
		v, err := oleutil.GetProperty(fw, "FirewallEnabled", p.bit)
		if err != nil {
			return nil, nil, err
		}
		on, ok := v.Value().(bool)
		v.Clear()
		if !ok {
			return nil, nil, fmt.Errorf("FirewallEnabled(%d): not a bool", p.bit)
		}
		profiles[p.name] = on
		if mask&p.bit != 0 {
			current = append(current, p.name)
		}
	}
	return profiles, current, nil
}

func winDisks(ctx context.Context, h *Health) {
	h.Disks = make([]HDisk, 0)
	pds, err := wmiNS[physicalDisk]("SELECT ObjectId, FriendlyName, HealthStatus, MediaType, BusType FROM MSFT_PhysicalDisk", nsStorage)
	if err != nil {
		h.errf("MSFT_PhysicalDisk: %v", err)
		return
	}
	for _, pd := range pds {
		if ctx.Err() != nil {
			return
		}
		d := HDisk{Name: clip(pd.FriendlyName, 64), Bus: winBus(pd.BusType), Media: winMedia(pd.MediaType), Smart: "unknown"}
		switch pd.HealthStatus {
		case 0:
			d.Health = "ok"
		case 1:
			d.Health = "warning"
		case 2:
			d.Health = "failing"
		default:
			d.Health = "unknown"
		}
		// Temperature 0 = not reported (usb bridges), Wear is 0 even on old ssds
		q := fmt.Sprintf(`ASSOCIATORS OF {MSFT_PhysicalDisk.ObjectId="%s"} WHERE AssocClass = MSFT_PhysicalDiskToStorageReliabilityCounter`, wqlEscape(pd.ObjectId))
		if rc, err := wmiNS[reliabilityCounter](q, nsStorage); err == nil && len(rc) > 0 {
			if rc[0].Temperature > 0 {
				d.TempC = saneC(float64(rc[0].Temperature), false)
			}
			if rc[0].TemperatureMax > 0 {
				d.TempWarnC = saneC(float64(rc[0].TemperatureMax), true)
			}
			if rc[0].PowerOnHours > 0 {
				d.POH = ptr(int64(rc[0].PowerOnHours))
			}
		}
		h.addDisk(d)
	}
}

func winBus(b uint16) string {
	switch b {
	case 7:
		return "usb"
	case 3, 11:
		return "sata"
	case 17:
		return "nvme"
	case 10:
		return "sas"
	case 8:
		return "raid"
	}
	return "other"
}

func winMedia(m uint16) string {
	switch m {
	case 3:
		return "hdd"
	case 4:
		return "ssd"
	}
	return "unknown"
}

// not verified on hardware: no Windows laptop in the fleet
func winBattery(h *Health) {
	if bats, err := wmiNS[struct{ Availability uint16 }]("SELECT Availability FROM Win32_Battery", `root\cimv2`); err != nil || len(bats) == 0 {
		return
	}
	bat := &HBattery{}
	design, e1 := wmiNS[struct{ DesignedCapacity uint32 }]("SELECT DesignedCapacity FROM BatteryStaticData", `root\wmi`)
	full, e2 := wmiNS[struct{ FullChargedCapacity uint32 }]("SELECT FullChargedCapacity FROM BatteryFullChargedCapacity", `root\wmi`)
	if e1 == nil && e2 == nil && len(design) > 0 && len(full) > 0 && design[0].DesignedCapacity > 0 {
		bat.MaxCapacityPct = ptr(int(uint64(full[0].FullChargedCapacity) * 100 / uint64(design[0].DesignedCapacity)))
	} else {
		h.errf("battery capacity not available")
	}
	if cycles, err := wmiNS[struct{ CycleCount uint32 }]("SELECT CycleCount FROM BatteryCycleCount", `root\wmi`); err == nil && len(cycles) > 0 && cycles[0].CycleCount > 0 {
		bat.Cycles = ptr(int(cycles[0].CycleCount))
	}
	h.Battery = bat
}
