package main

import (
	"bufio"
	"fmt"
	"gopkg.in/hypersleep/easyssh.v0"
	"os"
	"time"
)

func main() {
	fmt.Println("hello ssh")
	fmt.Println(os.Getenv("LOGNAME"))

	src, err := os.Open("initial.txt")
	if err != nil {
		fmt.Println("error opening source file: %v", err)
	}
	defer src.Close()

	scanner := bufio.NewScanner(src)
	result := make(chan string)
	done := make(chan bool)
	count := 0
	timeout := time.After(3 * time.Second)

	for scanner.Scan() {
		hostname := scanner.Text()
		fmt.Println(">>>", hostname)
		go func(hostname string) {
			ssh := &easyssh.MakeConfig{
				User:   "skovalenko",
				Server: hostname,
				Key:    "/.ssh/id_rsa",
				Port:   "22",
			}
			response, err := ssh.Run("uptime")
			// Handle errors
			if err != nil {
				//panic("Can't run remote command: " + err.Error())
				fmt.Println("Cannot get to the host===> ", hostname)

			} else {

				result <- hostname + ": " + response
			}

			done <- true
		}(hostname)
		count++
	}
	go func() {
		for i := 0; i < count; i++ {
			<-done
		}
		close(result)
	}()

	for i := 0; i < count; i++ {
		select {
		case res := <-result:
			fmt.Println(res)
		case <-timeout:
			fmt.Println("something went wrong timeout")
			return
		}
	}
	//for h := range result {
	//	select {
	//	case h:
	//		fmt.Println(h)
	//	case <- timeout:
	//		fmt.Println("timeout")
	//	}
	//}

	/*	ssh := &easyssh.MakeConfig{
		User:   "skoval200",
		Server: "odol-splix-sfb-03.santaclara.ca.sfba.comcast.net",
		// Optional key or Password without either we try to contact your agent SOCKET
		Key:  "/.ssh/id_rsa",
		Port: "22",
	}*/

	// Call Run method with command you want to run on remote server.
	/*	response, err := ssh.Run("hostname -f")
		// Handle errors
		if err != nil {
			panic("Can't run remote command: " + err.Error())
		} else {
			fmt.Println(response)
		}*/

}
