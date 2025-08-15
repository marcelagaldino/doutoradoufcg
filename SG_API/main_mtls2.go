package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
	"api_vms/configs"
	"api_vms/handlers"

	"github.com/go-chi/chi/v5"
)

func main() {
	// Carregar as configurações
	err := configs.Load()
	if err != nil {
		panic(err)
	}

	r := chi.NewRouter()

	r.Post("/update-pcr", handlers.UpdatePcr)
	r.Post("/update-pcr-vmg", handlers.UpdatePcrVmg)
	r.Post("/migration", handlers.Migration)
	r.Post("/receive-vm", handlers.ReceiveVm)
	r.Post("/snapshot", handlers.Snapshot)
	r.Post("/permanent-state", handlers.PermanentState)
	r.Post("/permanent-state-vmg", handlers.PermanentStateVmg)
	r.Post("/delete-vm", handlers.DeleteVm)
        r.Post("/ancoragem-vmg-permanent-state", handlers.AncoragemVMgPermanentState)
        r.Post("/ancoragem-vmg-volatile-state", handlers.AncoragemVMgVolatileState)

	// Configurar mTLS
	mtlsServerTLSConfig, err := setupMTLS()
	if err != nil {
		panic(fmt.Sprintf("falha ao configurar mTLS: %v", err))
	}

	// Configurar transporte HTTP com reutilização de conexões
	http.DefaultTransport = &http.Transport{
		MaxIdleConns:        100,              
		MaxIdleConnsPerHost: 10,               
		MaxConnsPerHost:     20,               
		IdleConnTimeout:     90 * time.Second, 
	}

	// Servidor mTLS
	mtlsServer := &http.Server{
		Addr:         ":8080", // Porta para mTLS
		Handler:      r,
		TLSConfig:    mtlsServerTLSConfig,
		IdleTimeout:  60 * time.Second, // Tempo máximo para conexões ociosas
		ReadTimeout:  30 * time.Second, // Tempo máximo para leitura
		WriteTimeout: 30 * time.Second, // Tempo máximo para escrita
	}

	// Servidor sem TLS
	noTLSConfig := &http.Server{
		Addr:         ":8443", // Porta para conexões sem TLS
		Handler:      r,
		IdleTimeout:  60 * time.Second,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Iniciar servidores em goroutines
	go func() {
		fmt.Println("Servidor mTLS rodando na porta 8080")
		if err := mtlsServer.ListenAndServeTLS("", ""); err != nil {
			fmt.Printf("Erro no servidor mTLS: %v\n", err)
		}
	}()

	go func() {
		fmt.Println("Servidor sem TLS rodando na porta 8443")
		if err := noTLSConfig.ListenAndServe(); err != nil {
			fmt.Printf("Erro no servidor sem TLS: %v\n", err)
		}
	}()

	select {}
}

func setupMTLS() (*tls.Config, error) {
	// Caminhos para os arquivos de certificado e chave do servidor
	serverCert := "/home/management/doutorado_ufcg/golang_API/ca_and_keys/ca_and_keys_remoto/server-cert.pem"
	serverKey := "/home/management/doutorado_ufcg/golang_API/ca_and_keys/ca_and_keys_remoto/server-key.pem"

	// Caminho para o certificado do CA (para validar o cliente)
	caCertPath := "/home/management/doutorado_ufcg/golang_API/ca_and_keys/ca_and_keys_remoto/ca-cert.pem"

	// Carregar certificado e chave do servidor
	cert, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		return nil, fmt.Errorf("falha ao carregar certificado/privkey: %v", err)
	}

	// Carregar o certificado do CA
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("falha ao ler certificado CA: %v", err)
	}

	// Criar pool de certificados confiáveis
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("falha ao adicionar CA ao pool")
	}

	// Configurar TLS
	return &tls.Config{
		Certificates: []tls.Certificate{cert}, // Certificado do servidor
		ClientCAs:    caCertPool,              // CA para validar os clientes
		ClientAuth:   tls.RequireAndVerifyClientCert, // Exige autenticação mTLS
		MinVersion:   tls.VersionTLS13,              // Versão mínima do TLS
	}, nil
}
