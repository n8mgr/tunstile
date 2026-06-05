package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func main() {
	tun := tuntest.NewChannelTUN()
	log := device.NewLogger(device.LogLevelVerbose, "")
	bind := conn.NewDefaultBind()
	defer bind.Close()

	dvc := device.NewDevice(tun.TUN(), bind, log)
	defer dvc.Close()

	privateKeyBytes, _ := hex.DecodeString("67e112e97e07c8241a8f470a2dafb5d7b7eeceaaa8f58acbb009c884f85840c4")

	publicKey, _ := curve25519.X25519(privateKeyBytes, curve25519.Basepoint)
	fmt.Printf("public key %x", publicKey)

	err := dvc.IpcSet(`private_key=67e112e97e07c8241a8f470a2dafb5d7b7eeceaaa8f58acbb009c884f85840c4
listen_port=51821
public_key=4bf5f044dd434343b4349f047f74e438850ab6383a277ff7d3b497f6c61a210c
allowed_ip=0.0.0.0/0`)
	if err != nil {
		panic(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return
		case buf := <-tun.Inbound:
			fmt.Println("recv", string(buf))
		case buf := <-tun.Outbound:
			fmt.Println("send", string(buf))
		}
	}
}
