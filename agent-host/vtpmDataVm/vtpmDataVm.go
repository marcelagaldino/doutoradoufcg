package vtpmDataVm

import (
	"encoding/json"
	"fmt"
	"net"
	"swtpm-integrity-monitoring/socketVm"
)

type VTPMData struct {
	State_list      []string `json:"State_list"`
}

func convertToVTPM(d socketVm.Data, vtpm_data *VTPMData) error {
	a, err := json.Marshal(d.Content)
	if err != nil {
		return err
	}

	json.Unmarshal(a, vtpm_data)

	return nil
}

func convertToStateList(d socketVm.Data, vtpm_state_list *[]string) error {
	a, err := json.Marshal(d.Content)
	if err != nil {
		return err
	}

	json.Unmarshal(a, vtpm_state_list)

	return nil
}

func ReceiveStateList(conn net.Conn) ([]string, error) {
	var vtpm_state_list []string

	d, err := socketVm.ReceiveAndConfirm(conn)
	if err != nil {
		return vtpm_state_list, fmt.Errorf("error: Failed to receive bytes in socket: %v", err)
	}

	if err := socketVm.CheckContentType(d.ContentType, socketVm.VTPM_STATE_LIST); err != nil {
		return vtpm_state_list, fmt.Errorf("error: Failed to verify content type: %v", err)
	}

	if err = convertToStateList(*d, &vtpm_state_list); err != nil {
		return vtpm_state_list, fmt.Errorf("error: Failed to unmarshal vTPM State List: %v", err)
	}

	return vtpm_state_list, nil
}

func Receive(conn net.Conn) (VTPMData, error) {
	var vtpm_data VTPMData

	d, err := socketVm.ReceiveAndConfirm(conn)
	if err != nil {
		return vtpm_data, fmt.Errorf("error: Failed to receive bytes in socket: %v", err)
	}

	if err := socketVm.CheckContentType(d.ContentType, socketVm.VTPM_DATA); err != nil {
		return vtpm_data, fmt.Errorf("error: Failed to verify content type: %v", err)
	}

	if err = convertToVTPM(*d, &vtpm_data); err != nil {
		return vtpm_data, fmt.Errorf("error: Failed to unmarshal vTPM State List: %v", err)
	}

	return vtpm_data, nil
}
