package socketHost

import (
        "bufio"
        "encoding/json"
        "fmt"
        "net"
        "strings"
)

const (
        VM_AGENT_BIND_ADRESS = "0.0.0.0"
        VM_AGENT_PORT        = "65534"
        VM_AGENT_PORT_SNAPSHOT_PCRS = "65533"
	VM_AGENT_PORT_VOLATILE = "65532"
        CONN_TYPE            = "tcp"

        VTPM_STATE_LIST = "vtpm_state_list"
        VTPM_DATA       = "vtpm_data"
)

type Data struct {
        ContentType string      `json:"content_type"`
        Content     interface{} `json:"content"`
}

func Connect(host, port string) (net.Conn, error) {
        conn, err := net.Dial(CONN_TYPE, host+":"+port)
        if err != nil {
                return nil, err
        }

        return conn, nil
}

func Receive(c net.Conn) (string, error) {

        buffer, err := bufio.NewReader(c).ReadBytes('\n')


        if err != nil {
                return "", err
        }


        return string(buffer), nil
}

func Send(c net.Conn, d Data) error {
       b, err := json.Marshal(d)
    	if err != nil {
                return err
        }

        b = append(b, []byte("\n")...)

		

        if _, err := c.Write(b); err != nil {
                return err
        }

        return nil
}

func Accept(l net.Listener) (net.Conn, error) {
        c, err := l.Accept()
        if err != nil {
                return nil, err
        }

        return c, nil
}

func CreateListener(bind_adresss, port string) (net.Listener, error) {
        l, err := net.Listen(CONN_TYPE, bind_adresss+":"+port)
        if err != nil {
                return nil, err
        }

        return l, nil
}

func ReceiveAndConfirm(c net.Conn) (string, error) {
        d, err := Receive(c)
        if err != nil {
                return "", err
        }


        Send(c, Data{})

        return d, nil
}

func CheckContentType(want, got string) error {
        if want != got {
                return fmt.Errorf("wrong content type. Wanted: %v, but got: %v", want, got)
        }

        return nil
}

func GetIP(c net.Conn) string {
        return strings.Split(c.RemoteAddr().String(), ":")[0]
}
