package main

import (
	"fmt"
	"log"
	"os"

	"github.com/go-meta/rpc"
)

func main() {

	// Add host/pass as environment variables, do not hardcode this!
	host := os.Getenv("ADD an ENV variable")
	pass := os.Getenv("ADD an ENV variable")
	user := "msf"

	if host == "" || pass == "" {
		log.Println("Missing required environment variables")
	}
	msf, err := rpc.New(host, user, pass)
	if err != nil {
		log.Println(err)
	}
	defer msf.Logout()

	sess, err := msf.SessionList()
	if err != nil {
		log.Println(err)
	}
	fmt.Println("Sessions: ")
	for _, session := range sess {
		fmt.Printf("%5d %s\n", session.ID, session.Info)
	}
}
