package main

import (
        "crypto/sha256"
    "encoding/hex"
    "io/ioutil"
    "log"
        "strings"
        "github.com/sfreiberg/simplessh"
        "os/exec"
		"fmt"
)

func main() {


	
	fmt.Printf("Path of measurements file: ")

	var state_list_file string

	fmt.Scanln(&state_list_file)
   // content, err := ioutil.ReadFile("/var/lib/libvirt/swtpm/567ba625-4a74-4181-8198-621fe3db770c/tpm2/state_list")
	content, err := ioutil.ReadFile(state_list_file)

    if err != nil {
        log.Fatal(err)
    }

   //fmt.Println(string(content))
   state_list := strings.Split(string(content),"\n")
   final_extends_state_hash, last_state := extendStateListHashes(state_list)



    client, err := simplessh.ConnectWithPassword("192.168.122.145", "root", "password")
        if err != nil {
                log.Fatal(err)
        }



    // Now run the commands on the remote machine:
    output, err := client.Exec("tpm2_pcrread | grep 16: | cut -d ':' -f2 | cut -d ' ' -f2 | cut -c3- | tr -d '\n'")

        if err != nil {
                log.Fatal(err)
        }
        pcr16 := strings.ToLower(string(output))



        client.Close()

        log.Printf("The vTPM State List Hash Extends is: %s", final_extends_state_hash)
        log.Printf("The PCR 16 value is: %s", pcr16)


        if(final_extends_state_hash==pcr16){


                log.Printf("The state list is reliable\n")

				fmt.Printf("Path of permanent state: ")

				var permanent_state_file string

				fmt.Scanln(&permanent_state_file)
				cmd := exec.Command("sha256sum", permanent_state_file)
              //  cmd := exec.Command("sha256sum", "/var/lib/libvirt/swtpm/567ba625-4a74-4181-8198-621fe3db770c/tpm2/tpm2-00.permall")
//              cmd := exec.Command("sha256sum", "false.permall")
                stdout, _ := cmd.Output()


                digest_permall_file:=strings.Split(string(stdout)," ")[0]

                log.Printf("Digest permall file: %s",digest_permall_file)

                log.Printf("The Last State in the State List: %s", last_state)

                if(last_state==digest_permall_file){

                        log.Printf("The vTPM state validation result is: true")

                }else{
                        log.Printf("The vTPM state validation result is: false")
                }
        }else{
                log.Printf("The state list is unreliable\n")
        }
}

func extendStateListHashes(hashes []string) (string, string) {

        out := "0000000000000000000000000000000000000000000000000000000000000000"
        var last_state string
        for _, hash := range hashes {
                        if (hash==""){
                                continue
                        }
                        out = out + hash
                        out_bytes, _ := hex.DecodeString(out)
                        out_hash := sha256.Sum256(out_bytes)
                        out = hex.EncodeToString(out_hash[:])
                        last_state=hash
        }

        return out, strings.ToLower(string(last_state))
}
