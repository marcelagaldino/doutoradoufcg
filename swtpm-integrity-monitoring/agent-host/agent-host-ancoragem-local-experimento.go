package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/mdlayher/netlink"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"swtpm-integrity-monitoring/socketHost"
	"swtpm-integrity-monitoring/socketVm"
	"swtpm-integrity-monitoring/vtpmDataHost"
	"swtpm-integrity-monitoring/vtpmDataVm"
	"sync"
	"time"
)

type PCR struct {
	ID_vm      string
	Number_PCR string
	Hash       string
}

type permanentState struct {
	ID_vm string
	Hash  string
}

type managementVM struct {
	Address string `yaml:"address"`
	Uuid    string `yaml:"uuid"`
	Port    string `yaml:"port"`
}

type removalEvent struct {
	ID_vm string
}

type migrationEvent struct {
	ID_vm     string
	Target_IP string
}

type snapshotPCRS struct {
	ID_vm string
	PCRS  []string
}

type runningMigrationStructure struct {
	id_vm     string
	removed   bool
	target_IP string
}

var buffer_list_hash []string
var management_vm managementVM
var uuid_map = make(map[string]string)
var runningMigration = make(map[string]runningMigrationStructure)

var info snapshotPCRS

func main() {
	management_vm.getConf()

	var wg sync.WaitGroup
	wg.Add(5)
	go server(&wg)
	go client(&wg)
	go volatile(&wg)
	go snapshot(&wg)
	go eventCapture(&wg)
	wg.Wait()

}

func (c *managementVM) getConf() *managementVM {

	yamlFile, err := ioutil.ReadFile("conf.yaml")
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	return c
}

func SendMessageNetlinkExperimento(msg string) {
    const rtnetlink = 2
    const rtmGroupLink = 21
    conn, _ := netlink.Dial(rtnetlink, nil)
    defer conn.Close()

    _ = conn.JoinGroup(rtmGroupLink)

    m := netlink.Message{
        Header: netlink.Header{},
        Data:   []byte(msg),
    }

    // Registrar o horário de envio
    sendTime := time.Now().Format("2006-01-02 15:04:05.000")

    conn.Send(m)

    // URL do host2
//    url := "http://192.168.0.7:8087/notify"
    url := "http://localhost:8087/notify"

    // Estrutura do corpo da requisição em JSON
    requestBody := map[string]string{
        "message":   msg,
        "timestamp": sendTime,
    }
    jsonData, err := json.Marshal(requestBody)
    if err != nil {
        fmt.Println("Erro ao criar o JSON:", err)
        return
    }

    // Criar a requisição POST
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
    if err != nil {
        fmt.Println("Erro ao criar a requisição:", err)
        return
    }

    // Definir o tipo de conteúdo como application/json
    req.Header.Set("Content-Type", "application/json")

    // Enviar a requisição
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        fmt.Println("Erro ao enviar a notificação:", err)
        return
    }
    defer resp.Body.Close()

    // Verificar a resposta
    if resp.StatusCode == http.StatusOK {
        fmt.Println("Notificação enviada com sucesso!")
    } else {
        fmt.Printf("Erro ao enviar a notificação: Status %d\n", resp.StatusCode)
    }
}




func SendMessageNetlink(msg string) {
	const rtnetlink = 2
	const rtmGroupLink = 21
	conn, _ := netlink.Dial(rtnetlink, nil)
	defer conn.Close()

	_ = conn.JoinGroup(rtmGroupLink)

	m := netlink.Message{
		Header: netlink.Header{},
		Data:   []byte(msg),
	}

	conn.Send(m)
}

/*func SendMessageNetlink(msg string) {
	const rtnetlink = 2
	const rtmGroupLink = 21
	conn, _ := netlink.Dial(rtnetlink, nil)
	defer conn.Close()

	_ = conn.JoinGroup(rtmGroupLink)

	m := netlink.Message{
		Header: netlink.Header{},
		Data:   []byte(msg),
	}

	conn.Send(m)

//adicionado para experimentação

 // URL do host2
    url := "http://150.165.75.50:8080/notify"

    // Corpo da requisição - por exemplo, uma mensagem simples ou dados estruturados em JSON
    jsonData := []byte(fmt.Sprintf(`{"message":  %s"}`, msg))
    // Criar a requisição POST
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
    if err != nil {
        fmt.Println("Erro ao criar a requisição:", err)
        return
    }

    // Definir o tipo de conteúdo como application/json
    req.Header.Set("Content-Type", "application/json")

    // Enviar a requisição
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        fmt.Println("Erro ao enviar a notificação:", err)
        return
    }
    defer resp.Body.Close()

    // Verificar a resposta
    if resp.StatusCode == http.StatusOK {
        fmt.Println("Notificação enviada com sucesso!")
    } else {
        fmt.Printf("Erro ao enviar a notificação: Status %d\n", resp.StatusCode)
    }

}*/

func eventCapture(wg *sync.WaitGroup) error {
	// Listen to rtnetlink for modification of network interfaces
	defer wg.Done()
	for {
		const rtnetlink = 2
		const rtmGroupLink = 21
		conn, _ := netlink.Dial(rtnetlink, nil)
		defer conn.Close()

		// Join multicast group: Receive will block until messages arrive.
		_ = conn.JoinGroup(rtmGroupLink)
		log.Printf("Starting Netlink Server")
		msgs, err := conn.Receive()
		if err != nil {
			return err
		}

		Event := strings.Split(string(msgs[0].Data), ",")
		fmt.Println(string(msgs[0].Data))
		if Event[0] == "migrate-init" {
			// migrate-init,<VMID>,<destinationIP>,<PID>
			target_IP := strings.Split(Event[2], "/")[2]
			if strings.Contains(target_IP, "@") {
				target_IP = strings.Split(target_IP, "@")[1]
			}
			runningMigration[Event[3]] = runningMigrationStructure{id_vm: getUuid(Event[1]), target_IP: target_IP, removed: false}

		} else if Event[0] == "migrate-end" {
			// migrate-end,<PID>,<return code>

			element, present := runningMigration[Event[1]]
			if present {

				if Event[2] == "0" {
					info := migrationEvent{ID_vm: element.id_vm, Target_IP: element.target_IP}

					jsonInfo, err := json.MarshalIndent(info, "", "\t")
					if err != nil {
						fmt.Println(err)
					}
					fmt.Println(string(jsonInfo))
					postBody, _ := json.Marshal(info)
					requestBody := bytes.NewBuffer(postBody)
					_, err = http.Post("http://"+management_vm.Address+":"+management_vm.Port+"/migration", "application/json", requestBody)
					if err != nil {
						fmt.Printf("An Error Occured %v\n", err)
					}
				} else if element.removed {
					info := removalEvent{ID_vm: element.id_vm}

					jsonInfo, err := json.MarshalIndent(info, "", "\t")
					if err != nil {
						fmt.Println(err)
					}
					fmt.Println(string(jsonInfo))
					postBody, _ := json.Marshal(info)
					requestBody := bytes.NewBuffer(postBody)
					_, err = http.Post("http://"+management_vm.Address+":"+management_vm.Port+"/delete-vm", "application/json", requestBody)
					if err != nil {
						fmt.Printf("An Error Occured %v\n", err)
					}
				}
				delete(runningMigration, Event[1])
			}
		} else if Event[0] == "removal" {
			///etc/apparmor.d/libvirt/libvirt-567ba625-4a74-4181-8198-621fe3db770c
			uuid := strings.Split(Event[1], "/")
			uuid = strings.Split(uuid[4], "libvirt-")
			migrated := false
			for key, element := range runningMigration {
				if element.id_vm == uuid[1] {
					entry := runningMigration[key]
					entry.removed = true

					runningMigration[key] = entry

					migrated = true
					fmt.Printf("Migration in progress, not removed\n")
				}
			}

			if !migrated {
				info := removalEvent{ID_vm: uuid[1]}

				jsonInfo, err := json.MarshalIndent(info, "", "\t")
				if err != nil {
					fmt.Println(err)
				}
				fmt.Println(string(jsonInfo))
				postBody, _ := json.Marshal(info)
				requestBody := bytes.NewBuffer(postBody)
				_, err = http.Post("http://"+management_vm.Address+":"+management_vm.Port+"/delete-vm", "application/json", requestBody)
				if err != nil {
					fmt.Printf("An Error Occured %v\n", err)
				}
			}
		}

	}
}

func server(wg *sync.WaitGroup) {
	defer wg.Done()
	log.Printf("Starting SWTPM Host Agent - %v://%v:%v\n", socketHost.CONN_TYPE, socketHost.VM_AGENT_BIND_ADRESS, socketHost.VM_AGENT_PORT)

	vm_agent, err := socketHost.CreateListener(socketHost.VM_AGENT_BIND_ADRESS, socketHost.VM_AGENT_PORT)
	if err != nil {
		log.Fatalf("error: Failed to create SWTPM VM Listener: %v", err)
	}

	defer vm_agent.Close()
	for {
		state_hash, err := getMeasurement(vm_agent)
		if err != nil {
			continue
		}

		data := strings.Split(state_hash, ",")
		ID := strings.Split(data[1], "/")
		uuid := ID[len(ID)-2]

		if management_vm.Uuid == "" {

			if findManagementVm(uuid) {

				management_vm.Uuid = uuid

			}

		}

		if management_vm.Uuid != uuid && uuid != "tmp" {

			info := permanentState{ID_vm: uuid, Hash: data[0]}

			jsonInfo, err := json.MarshalIndent(info, "", "\t")
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(string(jsonInfo))
			postBody, _ := json.Marshal(info)
			requestBody := bytes.NewBuffer(postBody)
			_, err = http.Post("http://"+management_vm.Address+":"+management_vm.Port+"/permanent-state", "application/json", requestBody)
			if err != nil {
				fmt.Printf("An Error Occured %v\n", err)
			}

		} else if management_vm.Uuid == uuid {
			formatedInfo := fmt.Sprintf("PERMANENT-STATE/management/%s", uuid, data[0])
			fmt.Printf("%s\n", formatedInfo)
			SendMessageNetlink(formatedInfo)
		}

	}
}

func client(wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		if len(buffer_list_hash) != 0 {

			VM_AGENT_IP := os.Args[1]
			VM_AGENT_PORT := os.Args[2]
			vm_conn, err := socketVm.Connect(VM_AGENT_IP, VM_AGENT_PORT)
			if err == nil {
				fmt.Println("---------------------------------------------------------------------")
				fmt.Printf("----------- Connecting to SWTPM Integrity VM Agent on %v:%v ----------\n", VM_AGENT_IP, VM_AGENT_PORT)
				fmt.Println("Sending the following measurements:")

				for _, value := range buffer_list_hash {
					fmt.Printf("- %v", value)
				}

				err = sendVTPMData(buffer_list_hash, vm_conn)
				if err == nil {
					fmt.Println("Measurements sent successfully!!!")
					buffer_list_hash = nil
				}
				if err != nil {
					log.Fatalf("error: Unable to send vTPM State List to VM Agent: %s: %v", VM_AGENT_IP, err)
				}

			} else {
				continue
			}

			vm_conn.Close()

			time.Sleep(30 * time.Second)

		} else {
			continue
		}
	}
}

func volatile(wg *sync.WaitGroup) {
	defer wg.Done()
	log.Printf("Starting SWTPM Host Agent - %v://%v:%v\n", socketHost.CONN_TYPE, socketHost.VM_AGENT_BIND_ADRESS, socketHost.VM_AGENT_PORT_VOLATILE)
	vm_agent, err := socketHost.CreateListener(socketHost.VM_AGENT_BIND_ADRESS, socketHost.VM_AGENT_PORT_VOLATILE)
	if err != nil {
		log.Fatalf("error: Failed to create SWTPM VM Listener: %v", err)
	}

	defer vm_agent.Close()

	for {
		state_hash, err := getMeasurement(vm_agent)
		if err != nil {
			continue
		}

		data := strings.Split(state_hash, ",")
		ID := strings.Split(data[1], "/")
		uuid := ID[len(ID)-2]

		Number_PCR := strings.TrimSuffix(data[2], "\n")

		if management_vm.Uuid == "" {

			if findManagementVm(uuid) {

				management_vm.Uuid = uuid

			}

		}

		if management_vm.Uuid != uuid && uuid != "tmp" {
			info := PCR{ID_vm: uuid, Number_PCR: Number_PCR, Hash: data[0]}

			jsonInfo, err := json.MarshalIndent(info, "", "\t")
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(string(jsonInfo))
			postBody, _ := json.Marshal(info)
			requestBody := bytes.NewBuffer(postBody)
			_, err = http.Post("http://"+management_vm.Address+":"+management_vm.Port+"/update-pcr", "application/json", requestBody)
			if err != nil {
				fmt.Printf("An Error Occured %v\n", err)
			}

		} else if management_vm.Uuid == uuid {

			formatedInfo := fmt.Sprintf("ADD/management/%s/%s", Number_PCR, data[0])
			fmt.Printf("%s\n", formatedInfo)

			//SendMessageNetlink(formatedInfo)

			if(Number_PCR == "11"){
				SendMessageNetlinkExperimento(formatedInfo)
                        } else{

				SendMessageNetlink(formatedInfo)

			}
		}
	}
}

func snapshot(wg *sync.WaitGroup) {
	defer wg.Done()
	log.Printf("Starting SWTPM Host Agent - %v://%v:%v\n", socketHost.CONN_TYPE, socketHost.VM_AGENT_BIND_ADRESS, socketHost.VM_AGENT_PORT_SNAPSHOT_PCRS)
	vm_agent, err := socketHost.CreateListener(socketHost.VM_AGENT_BIND_ADRESS, socketHost.VM_AGENT_PORT_SNAPSHOT_PCRS)
	if err != nil {
		log.Fatalf("error: Failed to create SWTPM VM Listener: %v", err)
	}

	defer vm_agent.Close()

	for {
		var PCRS_list []string
		state_hash, err := getMeasurement(vm_agent)
		if err != nil {
			continue
		}

		data := strings.Split(state_hash, ",")
		ID := strings.Split(data[24], "/")
		uuid := ID[len(ID)-2]
		for i := 0; i < 24; i++ {
			PCRS_list = append(PCRS_list, data[i])
		}
		if info.ID_vm == uuid && reflect.DeepEqual(info.PCRS, PCRS_list) {
			info = snapshotPCRS{ID_vm: "", PCRS: make([]string, 0)}
			continue
		} else {
			info = snapshotPCRS{ID_vm: uuid, PCRS: PCRS_list}
		}
		if management_vm.Uuid == "" {

			if findManagementVm(uuid) {

				management_vm.Uuid = uuid

			}

		}

		if management_vm.Uuid != uuid && uuid != "tmp" {
			//info := snapshotPCRS{ID_vm: uuid, PCRS: PCRS_list}

			jsonInfo, err := json.MarshalIndent(info, "", "\t")
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(string(jsonInfo))
			postBody, _ := json.Marshal(info)
			requestBody := bytes.NewBuffer(postBody)
			_, err = http.Post("http://"+management_vm.Address+":"+management_vm.Port+"/snapshot", "application/json", requestBody)
			if err != nil {
				fmt.Printf("An Error Occured %v\n", err)
			}

		} else {
			continue
		}

	}
}

func sendVTPMData(state_list_parsed []string, conn net.Conn) error {

	vtpm_assets := vtpmDataVm.VTPMData{
		State_list: state_list_parsed,
	}

	vtpm_data := socketVm.Data{
		ContentType: socketVm.VTPM_DATA,
		Content:     vtpm_assets,
	}

	err := socketVm.Send(conn, vtpm_data)
	if err != nil {
		return err
	}

	return nil
}

func getMeasurement(vm_agent net.Listener) (string, error) {
	var state_hash string
	host_conn, err := socketHost.Accept(vm_agent)
	if err != nil {
		log.Printf("error: Error while accepting connection: %v", err)
		return state_hash, err
	}
	//host_agent_IP := socketHost.GetIP(host_conn)
	//log.Printf("Agent has connected via IP: %v", host_agent_IP)

	state_hash, err = vtpmDataHost.Receive(host_conn)
	if err != nil {
		log.Printf("Cannot receive vTPM Data: %v", err)
		return state_hash, err
	}

	return state_hash, err

}

func findManagementVm(uuid string) bool {

	cmd, _ := exec.Command("virsh", "domifaddr", uuid).Output()

	for i, e := range strings.Split(string(cmd), "\n") {
		if i > 1 && strings.TrimSpace(e) != "" {
			domain := strings.Fields(string(e))
			ip := strings.Split(domain[3], "/")[0]
			if management_vm.Address == ip {

				return true
			} else {
				return false
			}

		}
	}
	return false
}

func getUuid(vm_name string) string {

	if uuid, err := uuid_map[vm_name]; err {
		return (uuid)
	} else {
		cmd, _ := exec.Command("virsh", "domuuid", vm_name).Output()
		uuid := strings.Split(string(cmd), "\n")[0]
		uuid_map[vm_name] = uuid
		return uuid
	}

}
