package handlers

import (
        "api_vms/models"
        "encoding/json"
        "log"
        "net/http"
	"io/ioutil"
	"io"
        "fmt"
         "bytes"
	 clientv3 "go.etcd.io/etcd/client/v3"
	"time"
	"crypto/tls"
        "crypto/x509"
//      "api_vms/netlink"
)

func AncoragemVMgVolatileState(w http.ResponseWriter, r *http.Request) {

    	cli, err := clientv3.New(clientv3.Config{
	        Endpoints:   []string{"http://10.1.4.130:3079", "http://10.20.3.6:6069"}, // substitua pelos seus endpoints
//	        Endpoints:   []string{"http://192.168.0.7:6069", "http://192.168.0.102:3079", "http://192.168.0.100:7069"}, // substitua pelos seus endpoints
        	DialTimeout: 5 * time.Second,
   	 })

	if err != nil {
        	log.Fatalf("Erro ao conectar ao etcd: %v", err)
    	}
	defer cli.Close()

	clientCert := "/home/management/doutorado_ufcg/golang_API/ca_and_keys/ca_and_keys_remoto/client-cert.pem"
        clientKey := "/home/management/doutorado_ufcg/golang_API/ca_and_keys/ca_and_keys_remoto/client-key.pem"
        caCertPath := "/home/management/doutorado_ufcg/golang_API/ca_and_keys/ca_and_keys_remoto/ca-cert.pem"

       // Configurar o transporte mTLS
        tlsConfig, err := setupMTLS(clientCert, clientKey, caCertPath)
        if err != nil {
                panic(fmt.Sprintf("Falha ao configurar mTLS: %v", err))
        }

        client := &http.Client{
                Transport: &http.Transport{
                        TLSClientConfig: tlsConfig,
                },
        }



        var info models.UpdatePcrEvent

        bodyBytes, err := io.ReadAll(r.Body)
        json.Unmarshal(bodyBytes, &info)
        log.Printf("Content: %+v", info)
        if err != nil {
                log.Printf("Error decoding JSON file: %v", err)
                http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
                return
        }


        jsonInfo, err := json.MarshalIndent(info, "", "\t")
        if err != nil {
                fmt.Println(err)
        }
        fmt.Println(string(jsonInfo))
        postBody, _ := json.Marshal(info)
        requestBody := bytes.NewBuffer(postBody)

        remoteVMg, err := getRemoteVMgIP(cli,info.VmId)


        keyMetric:=""
        if remoteVMg == "" {
                _,remoteVMg, err = selectVMg(cli)
                keyMetric,remoteVMg, err = selectVMg(cli)
                if err != nil {
                log.Fatalf("Erro ao selecionar a VM: %v", err)
                }
                fmt.Printf("A chave com o menor valor é: %s\n", remoteVMg)
        }


	// Fazer a requisição POST
        url := "https://"+remoteVMg+"/update-pcr-vmg"
        resp, err := client.Post(url, "application/json", requestBody)
        if err != nil {
                panic(fmt.Sprintf("Falha na requisição: %v", err))
        }

	log.Printf(url)

        defer resp.Body.Close()


      //  _, err = http.Post("http://"+remoteVMg+"/update-pcr", "application/json", requestBody)

        log.Printf("Enviou requisição ao update-pcr state da outra VM")


        if err != nil {
                log.Printf("Error decoding JSON file: %v", err)
                http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
                return
        }

	err = setRemoteVMgIP(cli,info.VmId,remoteVMg)
        if err != nil {
	    log.Fatalf("Erro ao setar remoteVMgIP: %v", err)
        }

	if keyMetric != "" {
        	err = incrementKeyValue(cli, keyMetric)
	        if err != nil {
        	    log.Fatalf("Erro ao incrementar o valor da chave: %v", err)
	        }

        	fmt.Printf("Valor da chave %s foi incrementado com sucesso.\n", keyMetric)
	}

}


// setupMTLS configura o cliente mTLS
func setupMTLS(clientCertPath, clientKeyPath, caCertPath string) (*tls.Config, error) {
        // Carregar o certificado e a chave do cliente
        cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
        if err != nil {
                return nil, fmt.Errorf("falha ao carregar certificado do cliente: %v", err)
        }

        // Carregar o certificado do CA
        caCert, err := ioutil.ReadFile(caCertPath)
        if err != nil {
                return nil, fmt.Errorf("falha ao carregar CA: %v", err)
        }

        // Criar pool de CA confiáveis
        caCertPool := x509.NewCertPool()
        if !caCertPool.AppendCertsFromPEM(caCert) {
                return nil, fmt.Errorf("falha ao adicionar CA ao pool")
        }

        // Configurar TLS
        return &tls.Config{
                Certificates:       []tls.Certificate{cert}, // Certificado do cliente
                RootCAs:            caCertPool,             // CA para validar o servidor
                InsecureSkipVerify: false,                  // Validação rigorosa do certificado
        }, nil
}

/*func getRemoteVMgIP(key string) (string, error) {
    // Configuração do cliente etcd
    cli, err := clientv3.New(clientv3.Config{
        Endpoints:   []string{"http://150.165.75.50:6069", "http://150.165.75.51:3079"},
        DialTimeout: 5 * time.Second,
    })
    if err != nil {
        return "", err
    }
    defer cli.Close()

    // Contexto com timeout para as requisições
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    // Lendo o valor da chave fornecida
    resp, err := cli.Get(ctx, key)
    if err != nil {
        return "", err
    }

    // Verificando se a chave foi encontrada
    if len(resp.Kvs) == 0 {
        return "", fmt.Errorf("chave '%s' não encontrada", key)
    }

    // Retornando o valor associado à chave
    return string(resp.Kvs[0].Value), nil
}


func setRemoteVMgIP(key string, value string) (error) {
    // Configuração do cliente etcd
    cli, err := clientv3.New(clientv3.Config{
        Endpoints:   []string{"http://150.165.75.50:6069", "http://150.165.75.51:3079"},
        DialTimeout: 5 * time.Second,
    })
    if err != nil {
        return err
    }
    defer cli.Close()

    // Contexto com timeout para as requisições
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    _, err = cli.Put(ctx, key, value)
    if err != nil {
        return err
    }


    return nil
}


func selectVMg() (string, error) {
    // Configura o cliente etcd
    cli, err := clientv3.New(clientv3.Config{
        Endpoints:   []string{"http://150.165.75.50:6069", "http://150.165.75.51:3079"}, // substitua pelos seus endpoints
        DialTimeout: 5 * time.Second,
    })
    if err != nil {
        return "", err
    }
    defer cli.Close()

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    // Obter todas as chaves que começam com "metric"
    resp, err := cli.Get(ctx, "metric", clientv3.WithPrefix())
    if err != nil {
        return "", err
    }

    if len(resp.Kvs) == 0 {
        return "", fmt.Errorf("nenhuma chave encontrada com o prefixo 'metric'")
    }

    var minValue float64
    var minIP string

    // Iterar sobre as chaves e encontrar o menor valor
    for _, kv := range resp.Kvs {
        // O valor associado é no formato "valor,IP"
        valueParts := strings.SplitN(string(kv.Value), ",", 2)
        if len(valueParts) != 2 {
            log.Printf("Formato inválido para valor %s", kv.Value)
            continue
        }

        // Converter a parte antes da vírgula para float64
        value, err := strconv.ParseFloat(valueParts[0], 64)
        if err != nil {
            log.Printf("Erro ao converter o valor %s para float: %v", valueParts[0], err)
            continue
        }

        // Comparar e armazenar o menor valor e seu respectivo IP
        if minIP == "" || value < minValue {
            minValue = value
            minIP = valueParts[1] // Armazenar o IP correspondente
        }
    }

    if minIP == "" {
        return "", fmt.Errorf("não foi possível encontrar um valor válido")
    }

    return minIP, nil // Retornar o IP correspondente ao menor valor
}*/
