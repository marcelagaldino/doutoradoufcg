package netlink

import (
	"github.com/mdlayher/netlink"
)

func Send_message_netlink(msg string, rtmGroupLink uint32) {
	const rtnetlink = 2
	//const rtmGroupLink = 21
	conn, _ := netlink.Dial(rtnetlink, nil)
	defer conn.Close()

	_ = conn.JoinGroup(rtmGroupLink)

	m := netlink.Message{
		Header: netlink.Header{},
		Data:   []byte(msg),
	}

	conn.Send(m)
}
