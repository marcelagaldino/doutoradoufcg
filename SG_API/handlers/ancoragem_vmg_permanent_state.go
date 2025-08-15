package handlers

import (
        "api_vms/models"
        "encoding/json"
        "log"
        "net/http"
        "io"
        "fmt"
         "bytes"
        "time"
	"strconv"
	"strings"
        "context"
         clientv3 "go.etcd.io/etcd/client/v3"
//      "api_vms/netlink"
)

func AncoragemVMgPermanentState(w http.ResponseWriter, r *http.Request) {

    cli, err := clientv3.New(clientv3.Config{
        Endpoints:   []string{"http://150.165.75.50:6069", "http://150.165.75.51:3079"}, // substitua pelos seus endpoints
        DialTimeout: 5 * time.Second,
    })
    if err != nil {
        log.Fatalf("Erro ao conectar ao etcd: %v", err)
    }
    defer cli.Close()


    var info models.PermanentStateEvent

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
    // Verificar se o valor retornado é vazio ao invés de nil
    if remoteVMg == "" {
        keyMetric, remoteVMg, err = selectVMg(cli)
        _, remoteVMg, err = selectVMg(cli)
        if err != nil {
            log.Fatalf("Erro ao selecionar a VM: %v", err)
        }
        fmt.Printf("A chave com o menor valor é: %s\n", remoteVMg)

    }

    _, err = http.Post("http://"+remoteVMg+"/permanent-state-vmg", "application/json", requestBody)

    log.Printf("Enviou requisição ao permanent state da outra VM: " + remoteVMg)

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
    	log.Printf("valor de keyMetric: ", keyMetric)
    	err = incrementKeyValue(cli, keyMetric)
    	if err != nil {
            log.Fatalf("Erro ao incrementar o valor da chave: %v", err)
    	}

	fmt.Printf("Valor da chave %s foi incrementado com sucesso.\n", keyMetric)

    }


}



func getRemoteVMgIP(cli *clientv3.Client, key string) (string, error) {
    // Configuração do cliente etcd
    /*cli, err := clientv3.New(clientv3.Config{
        Endpoints:   []string{"http://150.165.75.50:6069", "http://150.165.75.51:3079"},
        DialTimeout: 5 * time.Second,
    })
    if err != nil {
        return "", err
    }
    defer cli.Close()*/

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


func setRemoteVMgIP(cli *clientv3.Client, key string, value string) (error) {
    // Configuração do cliente etcd
    /*cli, err := clientv3.New(clientv3.Config{
        Endpoints:   []string{"http://150.165.75.50:6069", "http://150.165.75.51:3079"},
        DialTimeout: 5 * time.Second,
    })
    if err != nil {
        return err
    }
    defer cli.Close()*/

    // Contexto com timeout para as requisições
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    _, err := cli.Put(ctx, key, value)
    if err != nil {
        return err
    }


    return nil
}



func selectVMg(cli *clientv3.Client) (string, string, error) {
    // Configura o cliente etcd
    /*cli, err := clientv3.New(clientv3.Config{
        Endpoints:   []string{"http://150.165.75.50:6069", "http://150.165.75.51:3079"}, // substitua pelos seus endpoints
        DialTimeout: 5 * time.Second,
    })
    if err != nil {
        return "", "", err
    }
    defer cli.Close()*/

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    // Obter todas as chaves que começam com "metric"
    resp, err := cli.Get(ctx, "metric", clientv3.WithPrefix())
    if err != nil {
        return "", "", err
    }

    if len(resp.Kvs) == 0 {
        return "", "", fmt.Errorf("nenhuma chave encontrada com o prefixo 'metric'")
    }

    var minValue float64
    var minIP, minKey string

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

        // Comparar e armazenar o menor valor, seu respectivo IP e a chave correspondente
        if minIP == "" || value < minValue {
            minValue = value
            minIP = valueParts[1] // Armazenar o IP correspondente
            minKey = string(kv.Key) // Armazenar a chave correspondente
        }
    }

    if minIP == "" {
        return "", "", fmt.Errorf("não foi possível encontrar um valor válido")
    }

    return minKey, minIP, nil // Retornar a chave e o IP correspondentes ao menor valor
}


func incrementKeyValue(cli *clientv3.Client, minKey string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    // Obter o valor atual da chave
    resp, err := cli.Get(ctx, minKey)
    if err != nil {
        return fmt.Errorf("erro ao obter o valor da chave %s: %v", minKey, err)
    }
    if len(resp.Kvs) == 0 {
        return fmt.Errorf("chave %s não encontrada", minKey)
    }

    // Separar o valor no formato "valor,IP"
    currentVal := string(resp.Kvs[0].Value)
    valueParts := strings.SplitN(currentVal, ",", 2)
    if len(valueParts) != 2 {
        return fmt.Errorf("formato inválido para o valor da chave %s", minKey)
    }

    // Converter a parte numérica e incrementar
    value, err := strconv.Atoi(valueParts[0])
    if err != nil {
        return fmt.Errorf("erro ao converter o valor %s para inteiro: %v", valueParts[0], err)
    }
    incrementedValue := value + 1
    newValue := fmt.Sprintf("%d,%s", incrementedValue, valueParts[1])

    // Atualizar a chave com o valor incrementado
    _, err = cli.Put(ctx, minKey, newValue)
    if err != nil {
        return fmt.Errorf("erro ao atualizar o valor da chave %s: %v", minKey, err)
    }

    return nil
}


/*func selectVMg() (string, error) {
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
