package main

import (
	"bytes"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
)

/*
Function gets private key file as an argument
Returns parsed private key
*/
func PublicKeyFile(file string) ssh.AuthMethod {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println("Could not read private key file provided", file)
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		fmt.Println("Could not parse private key file", file)
		return nil
	}
	return ssh.PublicKeys(key)
}
func main() {

	sshConfig := &ssh.ClientConfig{
		User: "skovalenko",
		Auth: []ssh.AuthMethod{
			PublicKeyFile("/Users/skoval200/.ssh/id_rsa"),
		},
	}

	connection, err := ssh.Dial("tcp", "hydra:22", sshConfig)
	if err != nil {
		fmt.Errorf("Failed to dial:  %s", err)
		return
	}

	session, err := connection.NewSession()
	if err != nil {
		fmt.Errorf("failed to establish session: %s", err)
		return
	}
	defer session.Close()

	cmdPtr := flag.String("cmd", "uptime", "Provide command to execute on all servers")
	flag.Parse()
	fmt.Println("command to run is: ", *cmdPtr)

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Run(*cmdPtr)
	output := stdoutBuf.String()

	fmt.Print(output)

}
