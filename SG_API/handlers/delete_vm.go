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

func DeleteVm(w http.ResponseWriter, r *http.Request) {
	var info models.DeleteVm

	bodyBytes, err := io.ReadAll(r.Body)
	json.Unmarshal(bodyBytes, &info)
	log.Printf("Content: %+v", info)
	if err != nil {
		log.Printf("Error decoding JSON file: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if validateDeleteVm(info) {
		sendInfoToModuleDeleteVm(info)
	}
}

func sendInfoToModuleDeleteVm(info models.DeleteVm) {
	formatedInfo := fmt.Sprintf("DEL/%s", info.VmId)
	fmt.Println(formatedInfo)
	netlink.Send_message_netlink(formatedInfo,21)
}

func validateDeleteVm(op models.DeleteVm) (result bool) {
	if op.VmId == "" {
		return false
	}
	return true
}
