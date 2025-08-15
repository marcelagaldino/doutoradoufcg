package handlers

import (
	"api_vms/models"
	"encoding/json"
	"log"
	"net/http"
	"io"
	"api_vms/netlink"
	"fmt"
)

func UpdatePcrVmg(w http.ResponseWriter, r *http.Request) {
	var info models.UpdatePcrEvent

	bodyBytes, err := io.ReadAll(r.Body)
	json.Unmarshal(bodyBytes, &info)
	log.Printf("Content: %+v", info)
	if err != nil {
		log.Printf("Error decoding JSON file: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if validateUpdatePcrEvent(info) {
		sendInfoToModuleUpdatePcrEventVmg(info)
	}
}

func sendInfoToModuleUpdatePcrEventVmg(info models.UpdatePcrEvent) {
	formatedInfo := fmt.Sprintf("ADD-VMG/%s/%s/%s", info.VmId, info.NumberPCR, info.Hash)
	fmt.Print(formatedInfo + "\n")
	netlink.Send_message_netlink(formatedInfo,21)
}
