package models

type UpdatePcrEvent struct {
	//OperationType string `json:"Operation_type"`
	VmId      string `json:"ID_vm"`
	NumberPCR string `json:"Number_PCR"`
	Hash      string `json:"Hash"`
}

type SnapshotEvent struct {
	VmId	  string `json:"ID_vm"`
	PCRS    []string `json:"PCRS"`
}

type MigrationEvent struct {
	VmId	  string `json:"ID_vm"`
	TargetIp  string `json:"target_ip"`
}

type ReceiveVmEvent struct {
	VmId	string `json:"vm_id"`
	Pcrs    string `json:"pcrs"`
}

type PermanentStateEvent struct {
	VmId      string `json:"ID_vm"`
	Hash      string `json:"Hash"`
}

type DeleteVm struct {
	VmId      string `json:"ID_vm"`
}
