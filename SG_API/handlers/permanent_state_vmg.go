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

func PermanentStateVmg(w http.ResponseWriter, r *http.Request) {
	var info models.PermanentStateEvent

	bodyBytes, err := io.ReadAll(r.Body)
	json.Unmarshal(bodyBytes, &info)
	log.Printf("Content: %+v", info)
	if err != nil {
		log.Printf("Error decoding JSON file: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if validatePermanentStateEvent(info) {
		sendInfoToModulePermanentStateEventVmg(info)
	}
}

func sendInfoToModulePermanentStateEventVmg(info models.PermanentStateEvent) {
	formatedInfo := fmt.Sprintf("PERMANENT-STATE/%s/%s", info.VmId, info.Hash)
	fmt.Println(formatedInfo)
	netlink.Send_message_netlink(formatedInfo,21)
}
