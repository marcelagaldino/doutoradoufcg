package handlers

import (
	"api_vms/configs"
	"api_vms/models"
	"api_vms/netlink"
//	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

func Migration(w http.ResponseWriter, r *http.Request) {
	var info models.MigrationEvent
	log.Printf("Chamou migração")

	bodyBytes, err := io.ReadAll(r.Body)
	json.Unmarshal(bodyBytes, &info)
	log.Printf("Content: %+v", info)
	if err != nil {
		log.Printf("Error decoding JSON file: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	//if !validateMigrationEvent(info) {
	//	return
	//}

	file, err := ioutil.ReadFile(configs.GetModulePath() + info.VmId)
	if err != nil {
		log.Println(err)
		return
	}
	text := strings.Trim(string(file), "\n")
	fmt.Println(text)

/*	var send models.ReceiveVmEvent
	send.VmId = info.VmId
	send.Pcrs = text

	postBody, _ := json.Marshal(send)
	responseBody := bytes.NewBuffer(postBody)
	resp, err := http.Post("http://"+info.TargetIp+":8080/receive-vm", "application/json", responseBody)
	if err != nil {
		fmt.Printf("An Error Occured %v\n", err)
		return
	}
	defer resp.Body.Close()

	sendInfoToModuleMigrationEvent(info)*/
}

func sendInfoToModuleMigrationEvent(info models.MigrationEvent) {
	formatedInfo := fmt.Sprintf("DEL/%s", info.VmId)
	fmt.Println(formatedInfo)
	netlink.Send_message_netlink(formatedInfo,21)
}

func validateMigrationEvent(op models.MigrationEvent) (result bool) {
	if op.VmId == "" || op.TargetIp == "" {
		return false
	}
	return true
}
