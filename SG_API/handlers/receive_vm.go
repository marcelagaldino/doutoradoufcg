package handlers

import (
	"api_vms/models"
	"encoding/json"
	"log"
	"net/http"
	"io"
	"fmt"
	"api_vms/netlink"
)

func ReceiveVm(w http.ResponseWriter, r *http.Request) {
	var info models.ReceiveVmEvent

	bodyBytes, err := io.ReadAll(r.Body)
	json.Unmarshal(bodyBytes, &info)
	log.Printf("Content: %+v", info)
	if err != nil {
		log.Printf("Error decoding JSON file: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if validateReceiveVmEvent(info) {
		sendInfoToModuleReceiveVmEvent(info)
	}
}

func sendInfoToModuleReceiveVmEvent(info models.ReceiveVmEvent) {
	formatedInfo := fmt.Sprintf("MIGRATE/%s/%s", info.VmId, info.Pcrs)
	fmt.Println(formatedInfo)
	netlink.Send_message_netlink(formatedInfo,21)
}

func validateReceiveVmEvent(op models.ReceiveVmEvent) (result bool) {
	if op.VmId == "" || op.Pcrs == "" {
		return false
	}
	return true
}
