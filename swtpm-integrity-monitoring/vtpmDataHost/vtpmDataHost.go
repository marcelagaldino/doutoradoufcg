package vtpmDataHost

import (
	"encoding/json"
	"fmt"
	"net"
	"swtpm-integrity-monitoring/socketHost"
)

type VTPMData struct {
	State_hash      string `json:"State_hash"`
}


func convertToVTPM(d socketHost.Data, vtpm_data *VTPMData) error {
	a, err := json.Marshal(d.Content)
	if err != nil {
		return err
	}

	json.Unmarshal(a, vtpm_data)

	return nil
}

func convertToStateList(d socketHost.Data, vtpm_state_list *[]string) error {
	a, err := json.Marshal(d.Content)
	if err != nil {
		return err
	}

	json.Unmarshal(a, vtpm_state_list)

	return nil
}

/*func ReceiveStateList(conn net.Conn) ([]string, error) {
	var state_hash string

	d, err := socket.ReceiveAndConfirm(conn)
	if err != nil {
		return state_hash, fmt.Errorf("error: Failed to receive bytes in socket: %v", err)
	}

	if err := socket.CheckContentType(d.ContentType, socket.VTPM_STATE_LIST); err != nil {
		return state_hash, fmt.Errorf("error: Failed to verify content type: %v", err)
	}

	if err = convertToStateList(*d, &vtpm_state_list); err != nil {
		return state_hash, fmt.Errorf("error: Failed to unmarshal vTPM State List: %v", err)
	}

	return state_hash, nil
}*/

func Receive(conn net.Conn) (string, error) {

	d, err := socketHost.ReceiveAndConfirm(conn)
	if err != nil {
		return "", fmt.Errorf("error: Failed to receive bytes in socket: %v", err)
	}

	return d, nil
}
