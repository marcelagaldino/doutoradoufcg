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

func Snapshot(w http.ResponseWriter, r *http.Request) {
	var info models.SnapshotEvent

	bodyBytes, err := io.ReadAll(r.Body)
	json.Unmarshal(bodyBytes, &info)
	log.Printf("Content: %+v", info)
	if err != nil {
		log.Printf("Error decoding JSON file: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if validateSnapshotEvent(info) {
		sendInfoToModuleSnapshotEvent(info)
	}
}

func sendInfoToModuleSnapshotEvent(info models.SnapshotEvent) {
	
	allPCRS := ""

	for _, e := range info.PCRS{
		allPCRS += e + "\n"
	}


	formatedInfo := fmt.Sprintf("SNAPSHOT/%s/%s", info.VmId, allPCRS)
	fmt.Println(formatedInfo)
	netlink.Send_message_netlink(formatedInfo,21)
}

func validateSnapshotEvent(op models.SnapshotEvent) (result bool) {
	if op.VmId == "" || len(op.PCRS) != 24 {
		return false
	}

	for _, e := range op.PCRS{
		if e == ""{
			return false
		}
	}
	return true
}
