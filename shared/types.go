// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package shared holds what the agent and the server exchange. NATS carries
// msgpack and HTTP carries JSON; both encoders take their keys from the json
// tags, so a tag is a wire name and stays as it is when a Go name changes.
package shared

import "time"

// LocalConfig is read at start from the registry (Windows) or the config
// file and is never sent anywhere. Its tags are the old Go names, so a JSON
// dump of it reads as before.
type LocalConfig struct {
	ServerBase    string `json:"BaseURL"`
	ID            string `json:"AgentID"`
	APIHost       string `json:"APIURL"`
	AuthToken     string `json:"Token"`
	PKText        string `json:"AgentPK"`
	PKNum         int    `json:"PK"`
	CACert        string `json:"Cert"`
	ProxyURL      string `json:"Proxy"`
	MeshDir       string `json:"CustomMeshDir"`
	WinTemp       string `json:"WinTmpDir"`
	UnixTemp      string `json:"UnixTmpDir"`
	WinUserTemp   string `json:"WinRunAsUserTmpDir"`
	NATSProxyPath string `json:"NatsProxyPath"`
	NATSProxyPort string `json:"NatsProxyPort"`
	NATSPort      string `json:"NatsStandardPort"`
	NATSPing      int    `json:"NatsPingInterval"`
	TLSCert       string `json:"ClientCert"` // mTLS client certificate, PEM
	TLSKey        string `json:"ClientKey"`  // its private key, PEM
	PinsJSON      string `json:"Pins"`       // certificate pins as stored
}

// From the server: the due checks and the automated tasks.

// CheckSet answers GET checkrunner/runchecks. List keeps the key "Checks"
// it always encoded with; decoding matches the server's "checks" since
// encoding/json compares keys case-insensitively.
type CheckSet struct {
	List []CheckDef `json:"Checks"`
}

// CheckDef is one check. Which fields matter depends on Kind; the rest come
// over as zero values.
type CheckDef struct {
	Script        ScriptBody `json:"script"`
	CheckID       int        `json:"id"`
	Kind          string     `json:"check_type"`
	Limit         int        `json:"threshold"`
	Drive         string     `json:"disk"`
	Target        string     `json:"ip"`
	Args          []string   `json:"script_args"`
	Env           []string   `json:"env_vars"`
	NuConfig      bool       `json:"nushell_enable_config"`
	DenoPerms     string     `json:"deno_default_permissions"`
	TimeoutSec    int        `json:"timeout"`
	Svc           string     `json:"svc_name"`
	OKIfStarting  bool       `json:"pass_if_start_pending"`
	OKIfMissing   bool       `json:"pass_if_svc_not_exist"`
	Restart       bool       `json:"restart_if_stopped"`
	Log           string     `json:"log_name"`
	EventCode     int        `json:"event_id"`
	AnyEvent      bool       `json:"event_id_is_wildcard"`
	EventKind     string     `json:"event_type"`
	EventSrc      string     `json:"event_source"`
	EventText     string     `json:"event_message"`
	Days          int        `json:"search_last_days"`
	Container     string     `json:"container"`
	ContainerKind string     `json:"container_kind"`
}

type ScriptBody struct {
	Interp string   `json:"shell"`
	Source string   `json:"code"`
	AsUser bool     `json:"run_as_user"`
	Env    []string `json:"env_vars"`
}

type TaskDef struct {
	Steps     []TaskStep `json:"task_actions"`
	KeepGoing bool       `json:"continue_on_error"`
}

// TaskStep is a command (Cmd, Interp) or a script (the other fields),
// told apart by Kind.
type TaskStep struct {
	Kind        string   `json:"type"`
	Cmd         string   `json:"command"`
	Interp      string   `json:"shell"`
	ScriptTitle string   `json:"script_name"`
	Source      string   `json:"code"`
	Params      []string `json:"script_args"`
	TimeoutSec  int      `json:"timeout"`
	AsUser      bool     `json:"run_as_user"`
	Env         []string `json:"env_vars"`
	NuConfig    bool     `json:"nushell_enable_config"`
	DenoPerms   string   `json:"deno_default_permissions"`
}

// Check-in reports, published with the agent id as subject and the message
// name (agent-hello, agent-agentinfo, ...) as reply subject.

type HelloReport struct {
	AgentID      string `json:"agent_id"`
	AgentVersion string `json:"version"`
}

// PowerReport (agent-power) is sent before the machine goes away. Kind is
// shutdown, restart, shutdown_or_restart, sleep or cancel; Source is rmm (a
// server command) or os. The server stamps the time.
type PowerReport struct {
	AgentID   string `json:"agent_id"`
	Kind      string `json:"kind"`
	Source    string `json:"source"`
	Initiator string `json:"initiator"`
}

type InfoReport struct {
	AgentID       string  `json:"agent_id"`
	LoggedInUser  string  `json:"logged_in_username"`
	HostName      string  `json:"hostname"`
	OSName        string  `json:"operating_system"`
	Plat          string  `json:"plat"`
	RAMTotal      float64 `json:"total_ram"`
	Booted        int64   `json:"boot_time"`
	PendingReboot bool    `json:"needs_reboot"`
	Arch          string  `json:"goarch"`
}

type PublicIPReport struct {
	AgentID string `json:"agent_id"`
	Addr    string `json:"public_ip"`
}

type DisksReport struct {
	AgentID string      `json:"agent_id"`
	Disks   []DiskUsage `json:"disks"`
}

// DiskUsage sizes are display text; UsedPct is the number.
type DiskUsage struct {
	Dev       string `json:"device"`
	FSType    string `json:"fstype"`
	TotalText string `json:"total"`
	UsedText  string `json:"used"`
	FreeText  string `json:"free"`
	UsedPct   int    `json:"percent"`
}

type ServicesReport struct {
	AgentID  string       `json:"agent_id"`
	Services []WinService `json:"services"`
}

type WinService struct {
	SvcName   string `json:"name"`
	State     string `json:"status"`
	Display   string `json:"display_name"`
	ExePath   string `json:"binpath"`
	Desc      string `json:"description"`
	Account   string `json:"username"`
	ProcID    uint32 `json:"pid"`
	Start     string `json:"start_type"`
	AutoDelay bool   `json:"autodelay"`
}

type WMIReport struct {
	AgentID string      `json:"agent_id"`
	Data    interface{} `json:"wmi"`
}

type MeshNode struct {
	Op      string `json:"func"`
	AgentID string `json:"agent_id"`
	Node    string `json:"nodeid"`
	SyncNow bool   `json:"run_sync_task"`
}

// Replies to server requests.

type ProcInfo struct {
	ProcName string `json:"name"`
	PID      int    `json:"pid"`
	RSSBytes uint64 `json:"membytes"`
	Owner    string `json:"username"`
	RowID    int    `json:"id"`
	CPUPct   string `json:"cpu_percent"`
}

type ScriptRunResult struct {
	Out      string  `json:"stdout"`
	ErrOut   string  `json:"stderr"`
	ExitCode int     `json:"retcode"`
	Seconds  float64 `json:"execution_time"`
	RunID    int     `json:"id"`
}

type CmdOutput struct {
	Text string `json:"results"`
}

type SvcActionResult struct {
	OK     bool   `json:"success"`
	Reason string `json:"errormsg"`
}

type EventEntry struct {
	Src   string `json:"source"`
	Kind  string `json:"eventType"`
	Code  uint32 `json:"eventID"`
	Text  string `json:"message"`
	When  string `json:"time"`
	RowID int    `json:"uid"`
}

type InstalledApp struct {
	Title        string `json:"name"`
	Ver          string `json:"version"`
	Vendor       string `json:"publisher"`
	Installed    string `json:"install_date"`
	SizeText     string `json:"size"`
	Origin       string `json:"source"`
	Path         string `json:"location"`
	UninstallCmd string `json:"uninstall"`
}

// UnixService leaves OnBoot and MainPID nil (msgpack nil) when unknown.
type UnixService struct {
	Unit    string `json:"name"`
	Desc    string `json:"description"`
	State   string `json:"status"`
	OnBoot  *bool  `json:"enabled"`
	MainPID *int   `json:"pid"`
	Init    string `json:"manager"`
}

type PosixLogs struct {
	Lines     []PosixLogLine `json:"lines"`
	Truncated bool           `json:"truncated"`
}

type PosixLogLine struct {
	TS       string `json:"ts"`
	Unit     string `json:"unit"`
	Priority *int   `json:"priority"`
	Text     string `json:"message"`
}

// Windows Update and Chocolatey.

type UpdateScan struct {
	AgentID  string          `json:"agent_id"`
	Packages []UpdatePackage `json:"wua_updates"`
}

// UpdatePackage keeps empty lists nil, sent as null; the server takes that.
type UpdatePackage struct {
	Caption  string   `json:"title"`
	Details  string   `json:"description"`
	CatNames []string `json:"categories"`
	CatIDs   []string `json:"category_ids"`
	KBs      []string `json:"kb_article_ids"`
	InfoURLs []string `json:"more_info_urls"`
	HelpURL  string   `json:"support_url"`
	GUID     string   `json:"guid"`
	Revision int32    `json:"revision_number"`
	MSRC     string   `json:"severity"`
	Present  bool     `json:"installed"`
	Cached   bool     `json:"downloaded"`
	Kind     string   `json:"type"` // software or driver
}

type UpdateInstallResult struct {
	AgentID string `json:"agent_id"`
	GUID    string `json:"guid"`
	OK      bool   `json:"success"`
}

type UpdateSuperseded struct {
	AgentID string `json:"agent_id"`
	GUID    string `json:"guid"`
}

type RebootState struct {
	AgentID string `json:"agent_id"`
	Pending bool   `json:"needs_reboot"`
}

type ChocoState struct {
	AgentID string `json:"agent_id"`
	Present bool   `json:"installed"`
}

// WMI classes for agent-wmi, one struct per class. The struct is the class
// name and each field a property: the library builds the query from both and
// fills fields by name. The tags spell the same names, they are the keys in
// wmi_detail. An EX struct is the newer property set, read first; its base
// struct is the fallback for Windows versions that lack a property.

// Win32_BaseBoard feeds wmi_detail["base_board"].
type Win32_BaseBoard struct {
	Caption                 string    `json:"Caption"`
	ConfigOptions           []string  `json:"ConfigOptions"`
	CreationClassName       string    `json:"CreationClassName"`
	Depth                   float32   `json:"Depth"`
	Description             string    `json:"Description"`
	Height                  float32   `json:"Height"`
	HostingBoard            bool      `json:"HostingBoard"`
	HotSwappable            bool      `json:"HotSwappable"`
	InstallDate             time.Time `json:"InstallDate"`
	Manufacturer            string    `json:"Manufacturer"`
	Model                   string    `json:"Model"`
	Name                    string    `json:"Name"`
	OtherIdentifyingInfo    string    `json:"OtherIdentifyingInfo"`
	PartNumber              string    `json:"PartNumber"`
	PoweredOn               bool      `json:"PoweredOn"`
	Product                 string    `json:"Product"`
	Removable               bool      `json:"Removable"`
	Replaceable             bool      `json:"Replaceable"`
	RequirementsDescription string    `json:"RequirementsDescription"`
	RequiresDaughterBoard   bool      `json:"RequiresDaughterBoard"`
	SerialNumber            string    `json:"SerialNumber"`
	SKU                     string    `json:"SKU"`
	SlotLayout              string    `json:"SlotLayout"`
	SpecialRequirements     bool      `json:"SpecialRequirements"`
	Status                  string    `json:"Status"`
	Tag                     string    `json:"Tag"`
	Version                 string    `json:"Version"`
	Weight                  int32     `json:"Weight"`
	Width                   int32     `json:"Width"`
}

// Win32_BIOS feeds wmi_detail["bios"].
type Win32_BIOS struct {
	BIOSVersion           []string  `json:"BIOSVersion"`
	BuildNumber           string    `json:"BuildNumber"`
	Caption               string    `json:"Caption"`
	CodeSet               string    `json:"CodeSet"`
	CurrentLanguage       string    `json:"CurrentLanguage"`
	Description           string    `json:"Description"`
	IdentificationCode    string    `json:"IdentificationCode"`
	InstallableLanguages  uint16    `json:"InstallableLanguages"`
	InstallDate           time.Time `json:"InstallDate"`
	LanguageEdition       string    `json:"LanguageEdition"`
	ListOfLanguages       []string  `json:"ListOfLanguages"`
	Manufacturer          string    `json:"Manufacturer"`
	Name                  string    `json:"Name"`
	OtherTargetOS         string    `json:"OtherTargetOS"`
	PrimaryBIOS           bool      `json:"PrimaryBIOS"`
	ReleaseDate           time.Time `json:"ReleaseDate"`
	SerialNumber          string    `json:"SerialNumber"`
	SMBIOSBIOSVersion     string    `json:"SMBIOSBIOSVersion"`
	SMBIOSMajorVersion    uint16    `json:"SMBIOSMajorVersion"`
	SMBIOSMinorVersion    uint16    `json:"SMBIOSMinorVersion"`
	SMBIOSPresent         bool      `json:"SMBIOSPresent"`
	SoftwareElementID     string    `json:"SoftwareElementID"`
	SoftwareElementState  uint16    `json:"SoftwareElementState"`
	Status                string    `json:"Status"`
	TargetOperatingSystem uint16    `json:"TargetOperatingSystem"`
	Version               string    `json:"Version"`
}

// Win32_BIOSEX is the full property set of Win32_BIOS.
type Win32_BIOSEX struct {
	BIOSVersion                    []string  `json:"BIOSVersion"`
	BuildNumber                    string    `json:"BuildNumber"`
	Caption                        string    `json:"Caption"`
	CodeSet                        string    `json:"CodeSet"`
	CurrentLanguage                string    `json:"CurrentLanguage"`
	Description                    string    `json:"Description"`
	EmbeddedControllerMajorVersion uint8     `json:"EmbeddedControllerMajorVersion"`
	EmbeddedControllerMinorVersion uint8     `json:"EmbeddedControllerMinorVersion"`
	IdentificationCode             string    `json:"IdentificationCode"`
	InstallableLanguages           uint16    `json:"InstallableLanguages"`
	InstallDate                    time.Time `json:"InstallDate"`
	LanguageEdition                string    `json:"LanguageEdition"`
	ListOfLanguages                []string  `json:"ListOfLanguages"`
	Manufacturer                   string    `json:"Manufacturer"`
	Name                           string    `json:"Name"`
	OtherTargetOS                  string    `json:"OtherTargetOS"`
	PrimaryBIOS                    bool      `json:"PrimaryBIOS"`
	ReleaseDate                    time.Time `json:"ReleaseDate"`
	SerialNumber                   string    `json:"SerialNumber"`
	SMBIOSBIOSVersion              string    `json:"SMBIOSBIOSVersion"`
	SMBIOSMajorVersion             uint16    `json:"SMBIOSMajorVersion"`
	SMBIOSMinorVersion             uint16    `json:"SMBIOSMinorVersion"`
	SMBIOSPresent                  bool      `json:"SMBIOSPresent"`
	SoftwareElementID              string    `json:"SoftwareElementID"`
	SoftwareElementState           uint16    `json:"SoftwareElementState"`
	Status                         string    `json:"Status"`
	SystemBiosMajorVersion         uint8     `json:"SystemBiosMajorVersion"`
	SystemBiosMinorVersion         uint8     `json:"SystemBiosMinorVersion"`
	TargetOperatingSystem          uint16    `json:"TargetOperatingSystem"`
	Version                        string    `json:"Version"`
}

// Win32_ComputerSystem feeds wmi_detail["comp_sys"].
type Win32_ComputerSystem struct {
	AdminPasswordStatus       uint16    `json:"AdminPasswordStatus"`
	AutomaticManagedPagefile  bool      `json:"AutomaticManagedPagefile"`
	AutomaticResetBootOption  bool      `json:"AutomaticResetBootOption"`
	AutomaticResetCapability  bool      `json:"AutomaticResetCapability"`
	BootOptionOnLimit         uint16    `json:"BootOptionOnLimit"`
	BootOptionOnWatchDog      uint16    `json:"BootOptionOnWatchDog"`
	BootROMSupported          bool      `json:"BootROMSupported"`
	BootupState               string    `json:"BootupState"`
	Caption                   string    `json:"Caption"`
	ChassisBootupState        uint16    `json:"ChassisBootupState"`
	CreationClassName         string    `json:"CreationClassName"`
	CurrentTimeZone           int16     `json:"CurrentTimeZone"`
	DaylightInEffect          bool      `json:"DaylightInEffect"`
	Description               string    `json:"Description"`
	DNSHostName               string    `json:"DNSHostName"`
	Domain                    string    `json:"Domain"`
	DomainRole                uint16    `json:"DomainRole"`
	EnableDaylightSavingsTime bool      `json:"EnableDaylightSavingsTime"`
	FrontPanelResetStatus     uint16    `json:"FrontPanelResetStatus"`
	InfraredSupported         bool      `json:"InfraredSupported"`
	InstallDate               time.Time `json:"InstallDate"`
	KeyboardPasswordStatus    uint16    `json:"KeyboardPasswordStatus"`
	Manufacturer              string    `json:"Manufacturer"`
	Model                     string    `json:"Model"`
	Name                      string    `json:"Name"`
	NameFormat                string    `json:"NameFormat"`
	NetworkServerModeEnabled  bool      `json:"NetworkServerModeEnabled"`
	NumberOfLogicalProcessors uint32    `json:"NumberOfLogicalProcessors"`
	NumberOfProcessors        uint32    `json:"NumberOfProcessors"`
	OEMStringArray            []string  `json:"OEMStringArray"`
	PartOfDomain              bool      `json:"PartOfDomain"`
	PauseAfterReset           int64     `json:"PauseAfterReset"`
	PCSystemType              uint16    `json:"PCSystemType"`
	PowerManagementSupported  bool      `json:"PowerManagementSupported"`
	PowerOnPasswordStatus     uint16    `json:"PowerOnPasswordStatus"`
	PowerState                uint16    `json:"PowerState"`
	PowerSupplyState          uint16    `json:"PowerSupplyState"`
	PrimaryOwnerContact       string    `json:"PrimaryOwnerContact"`
	PrimaryOwnerName          string    `json:"PrimaryOwnerName"`
	ResetCapability           uint16    `json:"ResetCapability"`
	ResetCount                int16     `json:"ResetCount"`
	ResetLimit                int16     `json:"ResetLimit"`
	Roles                     []string  `json:"Roles"`
	Status                    string    `json:"Status"`
	SupportContactDescription []string  `json:"SupportContactDescription"`
	SystemType                string    `json:"SystemType"`
	ThermalState              uint16    `json:"ThermalState"`
	TotalPhysicalMemory       uint64    `json:"TotalPhysicalMemory"`
	UserName                  string    `json:"UserName"`
	WakeUpType                uint16    `json:"WakeUpType"`
	Workgroup                 string    `json:"Workgroup"`
}

// Win32_ComputerSystemEX is the full property set of Win32_ComputerSystem.
type Win32_ComputerSystemEX struct {
	AdminPasswordStatus       uint16    `json:"AdminPasswordStatus"`
	AutomaticManagedPagefile  bool      `json:"AutomaticManagedPagefile"`
	AutomaticResetBootOption  bool      `json:"AutomaticResetBootOption"`
	AutomaticResetCapability  bool      `json:"AutomaticResetCapability"`
	BootOptionOnLimit         uint16    `json:"BootOptionOnLimit"`
	BootOptionOnWatchDog      uint16    `json:"BootOptionOnWatchDog"`
	BootROMSupported          bool      `json:"BootROMSupported"`
	BootupState               string    `json:"BootupState"`
	Caption                   string    `json:"Caption"`
	ChassisBootupState        uint16    `json:"ChassisBootupState"`
	ChassisSKUNumber          string    `json:"ChassisSKUNumber"`
	CreationClassName         string    `json:"CreationClassName"`
	CurrentTimeZone           int16     `json:"CurrentTimeZone"`
	DaylightInEffect          bool      `json:"DaylightInEffect"`
	Description               string    `json:"Description"`
	DNSHostName               string    `json:"DNSHostName"`
	Domain                    string    `json:"Domain"`
	DomainRole                uint16    `json:"DomainRole"`
	EnableDaylightSavingsTime bool      `json:"EnableDaylightSavingsTime"`
	FrontPanelResetStatus     uint16    `json:"FrontPanelResetStatus"`
	HypervisorPresent         bool      `json:"HypervisorPresent"`
	InfraredSupported         bool      `json:"InfraredSupported"`
	InstallDate               time.Time `json:"InstallDate"`
	KeyboardPasswordStatus    uint16    `json:"KeyboardPasswordStatus"`
	Manufacturer              string    `json:"Manufacturer"`
	Model                     string    `json:"Model"`
	Name                      string    `json:"Name"`
	NameFormat                string    `json:"NameFormat"`
	NetworkServerModeEnabled  bool      `json:"NetworkServerModeEnabled"`
	NumberOfLogicalProcessors uint32    `json:"NumberOfLogicalProcessors"`
	NumberOfProcessors        uint32    `json:"NumberOfProcessors"`
	OEMStringArray            []string  `json:"OEMStringArray"`
	PartOfDomain              bool      `json:"PartOfDomain"`
	PauseAfterReset           int64     `json:"PauseAfterReset"`
	PCSystemType              uint16    `json:"PCSystemType"`
	PCSystemTypeEx            uint16    `json:"PCSystemTypeEx"`
	PowerManagementSupported  bool      `json:"PowerManagementSupported"`
	PowerOnPasswordStatus     uint16    `json:"PowerOnPasswordStatus"`
	PowerState                uint16    `json:"PowerState"`
	PowerSupplyState          uint16    `json:"PowerSupplyState"`
	PrimaryOwnerContact       string    `json:"PrimaryOwnerContact"`
	PrimaryOwnerName          string    `json:"PrimaryOwnerName"`
	ResetCapability           uint16    `json:"ResetCapability"`
	ResetCount                int16     `json:"ResetCount"`
	ResetLimit                int16     `json:"ResetLimit"`
	Roles                     []string  `json:"Roles"`
	Status                    string    `json:"Status"`
	SupportContactDescription []string  `json:"SupportContactDescription"`
	SystemFamily              string    `json:"SystemFamily"`
	SystemSKUNumber           string    `json:"SystemSKUNumber"`
	SystemType                string    `json:"SystemType"`
	ThermalState              uint16    `json:"ThermalState"`
	TotalPhysicalMemory       uint64    `json:"TotalPhysicalMemory"`
	UserName                  string    `json:"UserName"`
	WakeUpType                uint16    `json:"WakeUpType"`
	Workgroup                 string    `json:"Workgroup"`
}

// Win32_ComputerSystemProduct feeds wmi_detail["comp_sys_prod"].
type Win32_ComputerSystemProduct struct {
	Caption           string `json:"Caption"`
	Description       string `json:"Description"`
	IdentifyingNumber string `json:"IdentifyingNumber"`
	Name              string `json:"Name"`
	SKUNumber         string `json:"SKUNumber"`
	Vendor            string `json:"Vendor"`
	Version           string `json:"Version"`
	UUID              string `json:"UUID"`
}

// Win32_DesktopMonitor feeds wmi_detail["desktop_monitor"].
type Win32_DesktopMonitor struct {
	Availability             uint16    `json:"Availability"`
	Bandwidth                uint32    `json:"Bandwidth"`
	Caption                  string    `json:"Caption"`
	ConfigManagerErrorCode   uint32    `json:"ConfigManagerErrorCode"`
	ConfigManagerUserConfig  bool      `json:"ConfigManagerUserConfig"`
	CreationClassName        string    `json:"CreationClassName"`
	Description              string    `json:"Description"`
	DeviceID                 string    `json:"DeviceID"`
	DisplayType              uint16    `json:"DisplayType"`
	ErrorCleared             bool      `json:"ErrorCleared"`
	ErrorDescription         string    `json:"ErrorDescription"`
	InstallDate              time.Time `json:"InstallDate"`
	IsLocked                 bool      `json:"IsLocked"`
	LastErrorCode            uint32    `json:"LastErrorCode"`
	MonitorManufacturer      string    `json:"MonitorManufacturer"`
	MonitorType              string    `json:"MonitorType"`
	Name                     string    `json:"Name"`
	PixelsPerXLogicalInch    uint32    `json:"PixelsPerXLogicalInch"`
	PixelsPerYLogicalInch    uint32    `json:"PixelsPerYLogicalInch"`
	PNPDeviceID              string    `json:"PNPDeviceID"`
	PowerManagementSupported bool      `json:"PowerManagementSupported"`
	ScreenHeight             uint32    `json:"ScreenHeight"`
	ScreenWidth              uint32    `json:"ScreenWidth"`
	Status                   string    `json:"Status"`
	StatusInfo               uint16    `json:"StatusInfo"`
	SystemCreationClassName  string    `json:"SystemCreationClassName"`
	SystemName               string    `json:"SystemName"`
}

// Win32_DiskDrive feeds wmi_detail["disk"].
type Win32_DiskDrive struct {
	Availability             uint16    `json:"Availability"`
	BytesPerSector           uint32    `json:"BytesPerSector"`
	CapabilityDescriptions   []string  `json:"CapabilityDescriptions"`
	Caption                  string    `json:"Caption"`
	CompressionMethod        string    `json:"CompressionMethod"`
	ConfigManagerErrorCode   uint32    `json:"ConfigManagerErrorCode"`
	ConfigManagerUserConfig  bool      `json:"ConfigManagerUserConfig"`
	CreationClassName        string    `json:"CreationClassName"`
	DefaultBlockSize         uint64    `json:"DefaultBlockSize"`
	Description              string    `json:"Description"`
	DeviceID                 string    `json:"DeviceID"`
	ErrorCleared             bool      `json:"ErrorCleared"`
	ErrorDescription         string    `json:"ErrorDescription"`
	ErrorMethodology         string    `json:"ErrorMethodology"`
	FirmwareRevision         string    `json:"FirmwareRevision"`
	Index                    uint32    `json:"Index"`
	InstallDate              time.Time `json:"InstallDate"`
	InterfaceType            string    `json:"InterfaceType"`
	LastErrorCode            uint32    `json:"LastErrorCode"`
	Manufacturer             string    `json:"Manufacturer"`
	MaxBlockSize             uint64    `json:"MaxBlockSize"`
	MaxMediaSize             uint64    `json:"MaxMediaSize"`
	MediaLoaded              bool      `json:"MediaLoaded"`
	MediaType                string    `json:"MediaType"`
	MinBlockSize             uint64    `json:"MinBlockSize"`
	Model                    string    `json:"Model"`
	Name                     string    `json:"Name"`
	NeedsCleaning            bool      `json:"NeedsCleaning"`
	NumberOfMediaSupported   uint32    `json:"NumberOfMediaSupported"`
	Partitions               uint32    `json:"Partitions"`
	PNPDeviceID              string    `json:"PNPDeviceID"`
	PowerManagementSupported bool      `json:"PowerManagementSupported"`
	SCSIBus                  uint32    `json:"SCSIBus"`
	SCSILogicalUnit          uint16    `json:"SCSILogicalUnit"`
	SCSIPort                 uint16    `json:"SCSIPort"`
	SCSITargetId             uint16    `json:"SCSITargetId"`
	SectorsPerTrack          uint32    `json:"SectorsPerTrack"`
	SerialNumber             string    `json:"SerialNumber"`
	Signature                uint32    `json:"Signature"`
	Size                     uint64    `json:"Size"`
	Status                   string    `json:"Status"`
	StatusInfo               uint16    `json:"StatusInfo"`
	SystemCreationClassName  string    `json:"SystemCreationClassName"`
	SystemName               string    `json:"SystemName"`
	TotalCylinders           uint64    `json:"TotalCylinders"`
	TotalHeads               uint32    `json:"TotalHeads"`
	TotalSectors             uint64    `json:"TotalSectors"`
	TotalTracks              uint64    `json:"TotalTracks"`
	TracksPerCylinder        uint32    `json:"TracksPerCylinder"`
}

// Win32_NetworkAdapter feeds wmi_detail["network_adapter"].
type Win32_NetworkAdapter struct {
	AdapterType              string    `json:"AdapterType"`
	AdapterTypeID            uint16    `json:"AdapterTypeID"`
	AutoSense                bool      `json:"AutoSense"`
	Availability             uint16    `json:"Availability"`
	Caption                  string    `json:"Caption"`
	ConfigManagerErrorCode   uint32    `json:"ConfigManagerErrorCode"`
	ConfigManagerUserConfig  bool      `json:"ConfigManagerUserConfig"`
	CreationClassName        string    `json:"CreationClassName"`
	Description              string    `json:"Description"`
	DeviceID                 string    `json:"DeviceID"`
	ErrorCleared             bool      `json:"ErrorCleared"`
	ErrorDescription         string    `json:"ErrorDescription"`
	GUID                     string    `json:"GUID"`
	Index                    uint32    `json:"Index"`
	InstallDate              time.Time `json:"InstallDate"`
	InterfaceIndex           uint32    `json:"InterfaceIndex"`
	LastErrorCode            uint32    `json:"LastErrorCode"`
	MACAddress               string    `json:"MACAddress"`
	Manufacturer             string    `json:"Manufacturer"`
	MaxNumberControlled      uint32    `json:"MaxNumberControlled"`
	MaxSpeed                 uint64    `json:"MaxSpeed"`
	Name                     string    `json:"Name"`
	NetConnectionID          string    `json:"NetConnectionID"`
	NetConnectionStatus      uint16    `json:"NetConnectionStatus"`
	NetEnabled               bool      `json:"NetEnabled"`
	NetworkAddresses         []string  `json:"NetworkAddresses"`
	PermanentAddress         string    `json:"PermanentAddress"`
	PhysicalAdapter          bool      `json:"PhysicalAdapter"`
	PNPDeviceID              string    `json:"PNPDeviceID"`
	PowerManagementSupported bool      `json:"PowerManagementSupported"`
	ProductName              string    `json:"ProductName"`
	ServiceName              string    `json:"ServiceName"`
	Speed                    uint64    `json:"Speed"`
	Status                   string    `json:"Status"`
	StatusInfo               uint16    `json:"StatusInfo"`
	SystemCreationClassName  string    `json:"SystemCreationClassName"`
	SystemName               string    `json:"SystemName"`
	TimeOfLastReset          time.Time `json:"TimeOfLastReset"`
}

// Win32_NetworkAdapterConfiguration feeds wmi_detail["network_config"].
type Win32_NetworkAdapterConfiguration struct {
	Caption                      string    `json:"Caption"`
	Description                  string    `json:"Description"`
	SettingID                    string    `json:"SettingID"`
	ArpAlwaysSourceRoute         bool      `json:"ArpAlwaysSourceRoute"`
	ArpUseEtherSNAP              bool      `json:"ArpUseEtherSNAP"`
	DatabasePath                 string    `json:"DatabasePath"`
	DeadGWDetectEnabled          bool      `json:"DeadGWDetectEnabled"`
	DefaultIPGateway             []string  `json:"DefaultIPGateway"`
	DefaultTOS                   uint8     `json:"DefaultTOS"`
	DefaultTTL                   uint8     `json:"DefaultTTL"`
	DHCPEnabled                  bool      `json:"DHCPEnabled"`
	DHCPLeaseExpires             time.Time `json:"DHCPLeaseExpires"`
	DHCPLeaseObtained            time.Time `json:"DHCPLeaseObtained"`
	DHCPServer                   string    `json:"DHCPServer"`
	DNSDomain                    string    `json:"DNSDomain"`
	DNSDomainSuffixSearchOrder   []string  `json:"DNSDomainSuffixSearchOrder"`
	DNSEnabledForWINSResolution  bool      `json:"DNSEnabledForWINSResolution"`
	DNSHostName                  string    `json:"DNSHostName"`
	DNSServerSearchOrder         []string  `json:"DNSServerSearchOrder"`
	DomainDNSRegistrationEnabled bool      `json:"DomainDNSRegistrationEnabled"`
	ForwardBufferMemory          uint32    `json:"ForwardBufferMemory"`
	FullDNSRegistrationEnabled   bool      `json:"FullDNSRegistrationEnabled"`
	IGMPLevel                    uint8     `json:"IGMPLevel"`
	Index                        uint32    `json:"Index"`
	InterfaceIndex               uint32    `json:"InterfaceIndex"`
	IPAddress                    []string  `json:"IPAddress"`
	IPConnectionMetric           uint32    `json:"IPConnectionMetric"`
	IPEnabled                    bool      `json:"IPEnabled"`
	IPFilterSecurityEnabled      bool      `json:"IPFilterSecurityEnabled"`
	IPSecPermitIPProtocols       []string  `json:"IPSecPermitIPProtocols"`
	IPSecPermitTCPPorts          []string  `json:"IPSecPermitTCPPorts"`
	IPSecPermitUDPPorts          []string  `json:"IPSecPermitUDPPorts"`
	IPSubnet                     []string  `json:"IPSubnet"`
	IPUseZeroBroadcast           bool      `json:"IPUseZeroBroadcast"`
	KeepAliveInterval            uint32    `json:"KeepAliveInterval"`
	KeepAliveTime                uint32    `json:"KeepAliveTime"`
	MACAddress                   string    `json:"MACAddress"`
	MTU                          uint32    `json:"MTU"`
	NumForwardPackets            uint32    `json:"NumForwardPackets"`
	PMTUBHDetectEnabled          bool      `json:"PMTUBHDetectEnabled"`
	PMTUDiscoveryEnabled         bool      `json:"PMTUDiscoveryEnabled"`
	ServiceName                  string    `json:"ServiceName"`
	TcpipNetbiosOptions          uint32    `json:"TcpipNetbiosOptions"`
	TcpMaxConnectRetransmissions uint32    `json:"TcpMaxConnectRetransmissions"`
	TcpMaxDataRetransmissions    uint32    `json:"TcpMaxDataRetransmissions"`
	TcpNumConnections            uint32    `json:"TcpNumConnections"`
	TcpUseRFC1122UrgentPointer   bool      `json:"TcpUseRFC1122UrgentPointer"`
	TcpWindowSize                uint16    `json:"TcpWindowSize"`
	WINSEnableLMHostsLookup      bool      `json:"WINSEnableLMHostsLookup"`
	WINSHostLookupFile           string    `json:"WINSHostLookupFile"`
	WINSPrimaryServer            string    `json:"WINSPrimaryServer"`
	WINSScopeID                  string    `json:"WINSScopeID"`
	WINSSecondaryServer          string    `json:"WINSSecondaryServer"`
}

// Win32_OperatingSystem feeds wmi_detail["os"].
type Win32_OperatingSystem struct {
	BootDevice                 string    `json:"BootDevice"`
	BuildNumber                string    `json:"BuildNumber"`
	BuildType                  string    `json:"BuildType"`
	Caption                    string    `json:"Caption"`
	CodeSet                    string    `json:"CodeSet"`
	CountryCode                string    `json:"CountryCode"`
	CreationClassName          string    `json:"CreationClassName"`
	CSCreationClassName        string    `json:"CSCreationClassName"`
	CSDVersion                 string    `json:"CSDVersion"`
	CSName                     string    `json:"CSName"`
	CurrentTimeZone            int16     `json:"CurrentTimeZone"`
	Debug                      bool      `json:"Debug"`
	Description                string    `json:"Description"`
	Distributed                bool      `json:"Distributed"`
	EncryptionLevel            uint32    `json:"EncryptionLevel"`
	ForegroundApplicationBoost uint8     `json:"ForegroundApplicationBoost"`
	FreePhysicalMemory         uint64    `json:"FreePhysicalMemory"`
	FreeSpaceInPagingFiles     uint64    `json:"FreeSpaceInPagingFiles"`
	FreeVirtualMemory          uint64    `json:"FreeVirtualMemory"`
	InstallDate                time.Time `json:"InstallDate"`
	LastBootUpTime             time.Time `json:"LastBootUpTime"`
	LocalDateTime              time.Time `json:"LocalDateTime"`
	Locale                     string    `json:"Locale"`
	Manufacturer               string    `json:"Manufacturer"`
	MaxNumberOfProcesses       uint32    `json:"MaxNumberOfProcesses"`
	MaxProcessMemorySize       uint64    `json:"MaxProcessMemorySize"`
	MUILanguages               []string  `json:"MUILanguages"`
	Name                       string    `json:"Name"`
	NumberOfLicensedUsers      uint32    `json:"NumberOfLicensedUsers"`
	NumberOfProcesses          uint32    `json:"NumberOfProcesses"`
	NumberOfUsers              uint32    `json:"NumberOfUsers"`
	OperatingSystemSKU         uint32    `json:"OperatingSystemSKU"`
	Organization               string    `json:"Organization"`
	OSArchitecture             string    `json:"OSArchitecture"`
	OSLanguage                 uint32    `json:"OSLanguage"`
	OSProductSuite             uint32    `json:"OSProductSuite"`
	OSType                     uint16    `json:"OSType"`
	OtherTypeDescription       string    `json:"OtherTypeDescription"`
	PAEEnabled                 bool      `json:"PAEEnabled"`
	PlusProductID              string    `json:"PlusProductID"`
	PlusVersionNumber          string    `json:"PlusVersionNumber"`
	Primary                    bool      `json:"Primary"`
	ProductType                uint32    `json:"ProductType"`
	RegisteredUser             string    `json:"RegisteredUser"`
	SerialNumber               string    `json:"SerialNumber"`
	ServicePackMajorVersion    uint16    `json:"ServicePackMajorVersion"`
	ServicePackMinorVersion    uint16    `json:"ServicePackMinorVersion"`
	SizeStoredInPagingFiles    uint64    `json:"SizeStoredInPagingFiles"`
	Status                     string    `json:"Status"`
	SuiteMask                  uint32    `json:"SuiteMask"`
	SystemDevice               string    `json:"SystemDevice"`
	SystemDirectory            string    `json:"SystemDirectory"`
	SystemDrive                string    `json:"SystemDrive"`
	TotalSwapSpaceSize         uint64    `json:"TotalSwapSpaceSize"`
	TotalVirtualMemorySize     uint64    `json:"TotalVirtualMemorySize"`
	TotalVisibleMemorySize     uint64    `json:"TotalVisibleMemorySize"`
	Version                    string    `json:"Version"`
	WindowsDirectory           string    `json:"WindowsDirectory"`
}

// Win32_PhysicalMemory feeds wmi_detail["mem"].
type Win32_PhysicalMemory struct {
	BankLabel            string    `json:"BankLabel"`
	Capacity             uint64    `json:"Capacity"`
	Caption              string    `json:"Caption"`
	CreationClassName    string    `json:"CreationClassName"`
	DataWidth            uint16    `json:"DataWidth"`
	Description          string    `json:"Description"`
	DeviceLocator        string    `json:"DeviceLocator"`
	FormFactor           uint16    `json:"FormFactor"`
	HotSwappable         bool      `json:"HotSwappable"`
	InstallDate          time.Time `json:"InstallDate"`
	InterleaveDataDepth  uint16    `json:"InterleaveDataDepth"`
	InterleavePosition   uint32    `json:"InterleavePosition"`
	Manufacturer         string    `json:"Manufacturer"`
	MemoryType           uint16    `json:"MemoryType"`
	Model                string    `json:"Model"`
	Name                 string    `json:"Name"`
	OtherIdentifyingInfo string    `json:"OtherIdentifyingInfo"`
	PartNumber           string    `json:"PartNumber"`
	PositionInRow        uint32    `json:"PositionInRow"`
	PoweredOn            bool      `json:"PoweredOn"`
	Removable            bool      `json:"Removable"`
	Replaceable          bool      `json:"Replaceable"`
	SerialNumber         string    `json:"SerialNumber"`
	SKU                  string    `json:"SKU"`
	Speed                uint32    `json:"Speed"`
	Status               string    `json:"Status"`
	Tag                  string    `json:"Tag"`
	TotalWidth           uint16    `json:"TotalWidth"`
	TypeDetail           uint16    `json:"TypeDetail"`
	Version              string    `json:"Version"`
}

// Win32_PhysicalMemoryEX is the full property set of Win32_PhysicalMemory.
type Win32_PhysicalMemoryEX struct {
	Attributes           uint32    `json:"Attributes"`
	BankLabel            string    `json:"BankLabel"`
	Capacity             uint64    `json:"Capacity"`
	Caption              string    `json:"Caption"`
	ConfiguredClockSpeed uint32    `json:"ConfiguredClockSpeed"`
	ConfiguredVoltage    uint32    `json:"ConfiguredVoltage"`
	CreationClassName    string    `json:"CreationClassName"`
	DataWidth            uint16    `json:"DataWidth"`
	Description          string    `json:"Description"`
	DeviceLocator        string    `json:"DeviceLocator"`
	FormFactor           uint16    `json:"FormFactor"`
	HotSwappable         bool      `json:"HotSwappable"`
	InstallDate          time.Time `json:"InstallDate"`
	InterleaveDataDepth  uint16    `json:"InterleaveDataDepth"`
	InterleavePosition   uint32    `json:"InterleavePosition"`
	Manufacturer         string    `json:"Manufacturer"`
	MaxVoltage           uint32    `json:"MaxVoltage"`
	MemoryType           uint16    `json:"MemoryType"`
	MinVoltage           uint32    `json:"MinVoltage"`
	Model                string    `json:"Model"`
	Name                 string    `json:"Name"`
	OtherIdentifyingInfo string    `json:"OtherIdentifyingInfo"`
	PartNumber           string    `json:"PartNumber"`
	PositionInRow        uint32    `json:"PositionInRow"`
	PoweredOn            bool      `json:"PoweredOn"`
	Removable            bool      `json:"Removable"`
	Replaceable          bool      `json:"Replaceable"`
	SerialNumber         string    `json:"SerialNumber"`
	SKU                  string    `json:"SKU"`
	SMBIOSMemoryType     uint32    `json:"SMBIOSMemoryType"`
	Speed                uint32    `json:"Speed"`
	Status               string    `json:"Status"`
	Tag                  string    `json:"Tag"`
	TotalWidth           uint16    `json:"TotalWidth"`
	TypeDetail           uint16    `json:"TypeDetail"`
	Version              string    `json:"Version"`
}

// Win32_Processor feeds wmi_detail["cpu"].
type Win32_Processor struct {
	AddressWidth              uint16    `json:"AddressWidth"`
	Architecture              uint16    `json:"Architecture"`
	Availability              uint16    `json:"Availability"`
	Caption                   string    `json:"Caption"`
	ConfigManagerErrorCode    uint32    `json:"ConfigManagerErrorCode"`
	ConfigManagerUserConfig   bool      `json:"ConfigManagerUserConfig"`
	CpuStatus                 uint16    `json:"CpuStatus"`
	CreationClassName         string    `json:"CreationClassName"`
	CurrentClockSpeed         uint32    `json:"CurrentClockSpeed"`
	CurrentVoltage            uint16    `json:"CurrentVoltage"`
	DataWidth                 uint16    `json:"DataWidth"`
	Description               string    `json:"Description"`
	DeviceID                  string    `json:"DeviceID"`
	ErrorCleared              bool      `json:"ErrorCleared"`
	ErrorDescription          string    `json:"ErrorDescription"`
	ExtClock                  uint32    `json:"ExtClock"`
	Family                    uint16    `json:"Family"`
	InstallDate               time.Time `json:"InstallDate"`
	L2CacheSize               uint32    `json:"L2CacheSize"`
	L2CacheSpeed              uint32    `json:"L2CacheSpeed"`
	L3CacheSize               uint32    `json:"L3CacheSize"`
	L3CacheSpeed              uint32    `json:"L3CacheSpeed"`
	LastErrorCode             uint32    `json:"LastErrorCode"`
	Level                     uint16    `json:"Level"`
	LoadPercentage            uint16    `json:"LoadPercentage"`
	Manufacturer              string    `json:"Manufacturer"`
	MaxClockSpeed             uint32    `json:"MaxClockSpeed"`
	Name                      string    `json:"Name"`
	NumberOfCores             uint32    `json:"NumberOfCores"`
	NumberOfLogicalProcessors uint32    `json:"NumberOfLogicalProcessors"`
	OtherFamilyDescription    string    `json:"OtherFamilyDescription"`
	PNPDeviceID               string    `json:"PNPDeviceID"`
	PowerManagementSupported  bool      `json:"PowerManagementSupported"`
	ProcessorId               string    `json:"ProcessorId"`
	ProcessorType             uint16    `json:"ProcessorType"`
	Revision                  uint16    `json:"Revision"`
	Role                      string    `json:"Role"`
	SocketDesignation         string    `json:"SocketDesignation"`
	Status                    string    `json:"Status"`
	StatusInfo                uint16    `json:"StatusInfo"`
	Stepping                  string    `json:"Stepping"`
	SystemCreationClassName   string    `json:"SystemCreationClassName"`
	SystemName                string    `json:"SystemName"`
	UniqueId                  string    `json:"UniqueId"`
	UpgradeMethod             uint16    `json:"UpgradeMethod"`
	Version                   string    `json:"Version"`
	VoltageCaps               uint32    `json:"VoltageCaps"`
}

// Win32_ProcessorEX is the full property set of Win32_Processor.
type Win32_ProcessorEX struct {
	AddressWidth                            uint16    `json:"AddressWidth"`
	Architecture                            uint16    `json:"Architecture"`
	AssetTag                                string    `json:"AssetTag"`
	Availability                            uint16    `json:"Availability"`
	Caption                                 string    `json:"Caption"`
	Characteristics                         uint32    `json:"Characteristics"`
	ConfigManagerErrorCode                  uint32    `json:"ConfigManagerErrorCode"`
	ConfigManagerUserConfig                 bool      `json:"ConfigManagerUserConfig"`
	CpuStatus                               uint16    `json:"CpuStatus"`
	CreationClassName                       string    `json:"CreationClassName"`
	CurrentClockSpeed                       uint32    `json:"CurrentClockSpeed"`
	CurrentVoltage                          uint16    `json:"CurrentVoltage"`
	DataWidth                               uint16    `json:"DataWidth"`
	Description                             string    `json:"Description"`
	DeviceID                                string    `json:"DeviceID"`
	ErrorCleared                            bool      `json:"ErrorCleared"`
	ErrorDescription                        string    `json:"ErrorDescription"`
	ExtClock                                uint32    `json:"ExtClock"`
	Family                                  uint16    `json:"Family"`
	InstallDate                             time.Time `json:"InstallDate"`
	L2CacheSize                             uint32    `json:"L2CacheSize"`
	L2CacheSpeed                            uint32    `json:"L2CacheSpeed"`
	L3CacheSize                             uint32    `json:"L3CacheSize"`
	L3CacheSpeed                            uint32    `json:"L3CacheSpeed"`
	LastErrorCode                           uint32    `json:"LastErrorCode"`
	Level                                   uint16    `json:"Level"`
	LoadPercentage                          uint16    `json:"LoadPercentage"`
	Manufacturer                            string    `json:"Manufacturer"`
	MaxClockSpeed                           uint32    `json:"MaxClockSpeed"`
	Name                                    string    `json:"Name"`
	NumberOfCores                           uint32    `json:"NumberOfCores"`
	NumberOfEnabledCore                     uint32    `json:"NumberOfEnabledCore"`
	NumberOfLogicalProcessors               uint32    `json:"NumberOfLogicalProcessors"`
	OtherFamilyDescription                  string    `json:"OtherFamilyDescription"`
	PartNumber                              string    `json:"PartNumber"`
	PNPDeviceID                             string    `json:"PNPDeviceID"`
	PowerManagementSupported                bool      `json:"PowerManagementSupported"`
	ProcessorId                             string    `json:"ProcessorId"`
	ProcessorType                           uint16    `json:"ProcessorType"`
	Revision                                uint16    `json:"Revision"`
	Role                                    string    `json:"Role"`
	SecondLevelAddressTranslationExtensions bool      `json:"SecondLevelAddressTranslationExtensions"`
	SerialNumber                            string    `json:"SerialNumber"`
	SocketDesignation                       string    `json:"SocketDesignation"`
	Status                                  string    `json:"Status"`
	StatusInfo                              uint16    `json:"StatusInfo"`
	Stepping                                string    `json:"Stepping"`
	SystemCreationClassName                 string    `json:"SystemCreationClassName"`
	SystemName                              string    `json:"SystemName"`
	ThreadCount                             uint32    `json:"ThreadCount"`
	UniqueId                                string    `json:"UniqueId"`
	UpgradeMethod                           uint16    `json:"UpgradeMethod"`
	Version                                 string    `json:"Version"`
	VirtualizationFirmwareEnabled           bool      `json:"VirtualizationFirmwareEnabled"`
	VMMonitorModeExtensions                 bool      `json:"VMMonitorModeExtensions"`
	VoltageCaps                             uint32    `json:"VoltageCaps"`
}

// Win32_USBController feeds wmi_detail["usb"].
type Win32_USBController struct {
	Availability             uint16    `json:"Availability"`
	Caption                  string    `json:"Caption"`
	ConfigManagerErrorCode   uint32    `json:"ConfigManagerErrorCode"`
	ConfigManagerUserConfig  bool      `json:"ConfigManagerUserConfig"`
	CreationClassName        string    `json:"CreationClassName"`
	Description              string    `json:"Description"`
	DeviceID                 string    `json:"DeviceID"`
	ErrorCleared             bool      `json:"ErrorCleared"`
	ErrorDescription         string    `json:"ErrorDescription"`
	InstallDate              time.Time `json:"InstallDate"`
	LastErrorCode            uint32    `json:"LastErrorCode"`
	Manufacturer             string    `json:"Manufacturer"`
	MaxNumberControlled      uint32    `json:"MaxNumberControlled"`
	Name                     string    `json:"Name"`
	PNPDeviceID              string    `json:"PNPDeviceID"`
	PowerManagementSupported bool      `json:"PowerManagementSupported"`
	ProtocolSupported        uint16    `json:"ProtocolSupported"`
	Status                   string    `json:"Status"`
	StatusInfo               uint16    `json:"StatusInfo"`
	SystemCreationClassName  string    `json:"SystemCreationClassName"`
	SystemName               string    `json:"SystemName"`
	TimeOfLastReset          time.Time `json:"TimeOfLastReset"`
}

// Win32_VideoController feeds wmi_detail["graphics"].
type Win32_VideoController struct {
	AcceleratorCapabilities   []string  `json:"AcceleratorCapabilities"`
	AdapterCompatibility      string    `json:"AdapterCompatibility"`
	AdapterDACType            string    `json:"AdapterDACType"`
	AdapterRAM                uint32    `json:"AdapterRAM"`
	Availability              uint16    `json:"Availability"`
	CapabilityDescriptions    []string  `json:"CapabilityDescriptions"`
	Caption                   string    `json:"Caption"`
	CurrentRefreshRate        uint32    `json:"CurrentRefreshRate"`
	CurrentVerticalResolution uint32    `json:"CurrentVerticalResolution"`
	Description               string    `json:"Description"`
	DeviceID                  string    `json:"DeviceID"`
	DriverDate                time.Time `json:"DriverDate"`
	DriverVersion             string    `json:"DriverVersion"`
	InstallDate               time.Time `json:"InstallDate"`
	InstalledDisplayDrivers   string    `json:"InstalledDisplayDrivers"`
	MaxMemorySupported        uint32    `json:"MaxMemorySupported"`
	MaxRefreshRate            uint32    `json:"MaxRefreshRate"`
	MinRefreshRate            uint32    `json:"MinRefreshRate"`
	Name                      string    `json:"Name"`
	Status                    string    `json:"Status"`
	SystemCreationClassName   string    `json:"SystemCreationClassName"`
	SystemName                string    `json:"SystemName"`
	TimeOfLastReset           time.Time `json:"TimeOfLastReset"`
	VideoModeDescription      string    `json:"VideoModeDescription"`
	VideoProcessor            string    `json:"VideoProcessor"`
}
