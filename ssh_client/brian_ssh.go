package brian_ssh

// program that will run a supplied command against multiple nodes concurrently

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	traffic_ops "github.com/Comcast/traffic_control/traffic_ops/client"
	"github.com/MakeNowJust/heredoc"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

type trafficOpsCredentials struct {
	username string
	password string
}

type sshResponse struct {
	resp     string
	hostname string
	failed   bool
}

func usage() {
	usage := heredoc.Doc(`
        USAGE:

        This program, hopefully, should allow you to run concurrently across many nodes a command specified on the command line.

        It makes a ssh connection over to the node and runs the command specified with the command flag. You must have preconfigured SSH RSA public key authentication.

        Should you choose to fetch the list of nodes from Traffic Ops, you must specify the username and password in two environment variables: TO_USERNAME and TO_PASSWORD,
        or you can supply the path to a YAML formatted file with the Traffic Ops credentials in it.


        OPTIONS:
        -source <filename>|trafficops : tells the program where the list of hosts we'll be working against is at. Not specifying this assumes /etc/hosts for your sourcefile.
        -TOconfig <file> : you can use this option to specify the Traffic Ops credentials in a yaml formatted file as opposed to setting environment variables
        -regex <regular expression> : you can use this to specify a subset of the nodes listed in the source which match the regular expression. Default is to match everything.
        -command "command that you want to run" : you need to enclose this in " " if there is whitespace. This option is REQUIRED.
        -timeout <n> : length of time that we will wait for a response. Default is 20 seconds.

        EXAMPLES:

        1. run_concurrently -source trafficops -regex odol-atsec -command uptime -timeout 20s
        Run the uptime command on all Edge Caches that Traffic Ops knows about. Remember you must set the credentials for Traffic Ops either in environment variables or in a YAML file.

        2. run_concurrently -source  /tmp/list_of_hosts -regex . -command "ls -al /etc/passwd" -timeout 5s
        Run ls -al /etc/passwd on all nodes in /tmp/list_of_hosts. You actually could have left off the -regex option here and it would have done the same thing.

        3. sudo TO_USERNAME=xxxxxxxxxx TO_PASSWORD=yyyyyyyyy ./run_concurrently -source trafficops -regex 18901 -command whoami -timeout 45s
        Run the whoami command as root on all nodes which have 18901 in their hostname per the nodes Traffic Ops knows about

        4. sudo ./run_concurrently -source trafficops -toconfig traffic_ops.yaml -regex 18901 -command whoami -timeout 1m
        Run the whoami command as root on all nodes which have 18901 in their hostname per the nodes Traffic Ops knows about

        Polling too many nodes at the same time will result in file handle exhaustion and you will get invalid results.

        `)
	fmt.Println(usage)
	os.Exit(1)
}

func fetchServerListTrafficOps(credentials trafficOpsCredentials, regex string, verbose bool) []string {
	// read our Traffic Ops credentials from a YAML file as opposed to env variables

	toSession, err := traffic_ops.Login("https://tm.comcast.net", credentials.username, credentials.password, true)
	if err != nil {
		log.Fatalln("Failed to login to Traffic Ops: ", err)
	}

	servers, err := toSession.Servers()
	if err != nil {
		log.Fatalln("Failed to fetch from Traffic Ops a list of the servers:", err)
	}

	var matchingHostnames []string

	re := regexp.MustCompile(regex)

	for _, node := range servers {
		nodeFQDN := node.HostName + "." + node.DomainName
		if re.MatchString(nodeFQDN) {
			matchingHostnames = append(matchingHostnames, nodeFQDN)
		}
	}

	if verbose {
		fmt.Printf("We matched %d nodes from Traffic Ops: \n", len(matchingHostnames))
		fmt.Println()
		for _, value := range matchingHostnames {
			fmt.Printf("\tMatched node: %s\n", value)
		}
	}

	return matchingHostnames
}

func returnMatchedNodesFromFile(sourcefile string, regex string, verbose bool) []string {

	f, err := os.Open(sourcefile)
	if err != nil {
		log.Fatalf("Failed to open %s.\n", sourcefile)
	}
	defer f.Close()

	re := regexp.MustCompile(regex)

	var matchingHostnames []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "#") {
			continue
		}
		if re.MatchString(scanner.Text()) {
			if sourcefile == "/etc/hosts" {
				sl := strings.Fields(scanner.Text())
				matchingHostnames = append(matchingHostnames, sl[1])
			} else {
				matchingHostnames = append(matchingHostnames, scanner.Text())
			}
		}
	}

	if verbose {
		fmt.Printf("We matched %d nodes from %s:\n", len(matchingHostnames), sourcefile)
		fmt.Println()
		for _, value := range matchingHostnames {
			fmt.Printf("\tMatched node: %s\n", value)
		}
	}

	return matchingHostnames

}

func validateEnvVars() trafficOpsCredentials {

	var credentials trafficOpsCredentials
	credentials.username = os.Getenv("TO_USERNAME")
	credentials.password = os.Getenv("TO_PASSWORD")

	if len(credentials.username) == 0 || len(credentials.password) == 0 {
		log.Fatal("You did not specify either the YAML credential file for Traffic Ops, and you did not set both the TO_USERNAME and TO_PASSWORD env variable.")
	}
	return credentials
}

func validateTOyaml(file string) trafficOpsCredentials {

	var credentials trafficOpsCredentials

	yamlconfig, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatalln("Failed to read from YAML file: ", file)
	}

	err = yaml.Unmarshal(yamlconfig, &credentials)
	if err != nil {
		log.Fatalln("Failed to unmarshal YAML file: ", file)
	}

	if len(credentials.username) == 0 {
		log.Fatalln("Failed to get username from YAML file.")
	}

	if len(credentials.password) == 0 {
		log.Fatalln("Failed to get password from YAML file.")
	}

	return credentials

}

// validateMatched will loop through the list of matchedNodes ensuring that either the node is in DNS, or that there is an entry in /etc/hosts
func validateMatched(matchedNodes []string, verbose bool) []string {

	var validatedNodes []string
	var unknownNodes []string

	for _, node := range matchedNodes {
		aRecord, err := net.LookupIP(node)
		if err != nil {
			unknownNodes = append(unknownNodes, node)
			if verbose {
				fmt.Printf("\tDNS Lookup for %s had error: %v\n", node, err)
				continue
			} else {
				continue
			}
		}

		if len(aRecord) == 0 {
			unknownNodes = append(unknownNodes, node)
			if verbose {
				fmt.Printf("\tDNS Lookup for %s did not return any results.\n", node)
			}
		} else {
			validatedNodes = append(validatedNodes, node)
			if verbose {
				fmt.Printf("\tDNS Lookup for %s succeeded.\n", node)
			}
		}
	}

	f, err := os.Open("/etc/hosts")
	if err != nil {
		log.Fatalln("Failed to open /etc/hosts for reading")
	}
	defer f.Close()

	for _, node := range unknownNodes {
		nodeRegex := fmt.Sprintf("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\s*.*\\b%s\\b", node)
		nodeRE := regexp.MustCompile(nodeRegex)
		if searchHosts(f, nodeRE, node, verbose) {
			validatedNodes = append(validatedNodes, node)
		}
	}

	return validatedNodes

}

//searchHosts will examine /etc/hosts to try and find the given string is present or not
func searchHosts(f *os.File, re *regexp.Regexp, s string, verbose bool) bool {

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "#") {
			continue
		}
		if re.MatchString(scanner.Text()) {
			if verbose {
				fmt.Printf("\tFound %s in /etc/hosts.\n", s)
			}
			return true
		}
	}

	if verbose {
		fmt.Printf("\tFailed to find %s in /etc/hosts.\n", s)
	}
	return false
}

func executeCmd(sshResults chan sshResponse, command, hostname, port string, config *ssh.ClientConfig) {

	var r sshResponse

	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", hostname, port), config)
	if err != nil {
		t := time.Now()
		timestr := fmt.Sprintf(t.Format("2006/01/02 15:04:05.000"))

		r.failed = true
		r.hostname = hostname
		r.resp = fmt.Sprintf("%s %-70s -> Failed to connect.\n", timestr, hostname)
		sshResults <- r
		return
	}

	session, err := conn.NewSession()
	if err != nil {
		t := time.Now()
		timestr := fmt.Sprintf(t.Format("2006/01/02 15:04:05.000"))

		r.failed = true
		r.hostname = hostname
		r.resp = fmt.Sprintf("%s %-70s -> Failed to establish SSH session.\n", timestr, hostname)
		sshResults <- r
		return
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Run(command)
	output := stdoutBuf.String()

	if len(output) == 0 {
		t := time.Now()
		timestr := fmt.Sprintf(t.Format("2006/01/02 15:04:05.000"))

		r.hostname = hostname
		r.resp = fmt.Sprintf("%s %-70s -> (Empty stdout buffer)\n", timestr, hostname)
		sshResults <- r
		return
	}

	t := time.Now()
	timestr := fmt.Sprintf(t.Format("2006/01/02 15:04:05.000"))

	r.hostname = hostname
	r.resp = fmt.Sprintf("%s %-70s -> %s", timestr, hostname, output)
	sshResults <- r
	return
}

func main() {
	source := flag.String("source", "/etc/hosts", "Source from which we should generate our list of hosts. Valid choices are: <filename> or trafficops.")
	TOconfig := flag.String("toconfig", "null", "Use this option to specify a yaml formatted file which contains our Traffic Ops credentials.")
	command := flag.String("command", "null", "This is the command that we will be running against multiple hosts that match our regexp.")
	regex := flag.String("regex", "null", "Regexp which we use to select which hosts to run our command against.")
	timeout := flag.Duration("timeout", 20*time.Second, "The maximum amount of time we will wait for a response to our ssh command")
	verbose := flag.Bool("verbose", false, "Specify -verbose if you want additional feedback in the output")
	flag.Parse()

	user := os.Getenv("USER")
	if len(user) == 0 {
		log.Fatalln("Failed to determine our current username, exiting.")
	}

	//check for existence of user private key
	privateKey := fmt.Sprintf(os.Getenv("HOME") + "/.ssh/id_rsa")
	_, err := os.Stat(privateKey)
	if err != nil {
		log.Println("Failed to open private key - you must have preconfigured SSH RSA public key authentication:", privateKey)
		time.Sleep(2 * time.Second)
		usage()
	}

	if *command == "null" {
		fmt.Println()
		fmt.Println("You did not specify a command to run !!")
		fmt.Println()
		time.Sleep(2 * time.Second)
		usage()
	}

	if *regex == "null" {
		*regex = "."
	}

	var matchedNodes []string

	switch *source {
	case "trafficops":
		var credentials trafficOpsCredentials

		if *TOconfig == "null" {
			credentials = validateEnvVars()
		}
		if *TOconfig != "null" {
			credentials = validateTOyaml(*TOconfig)
		}
		matchedNodes = fetchServerListTrafficOps(credentials, *regex, *verbose)
	case "/etc/hosts":
		matchedNodes = returnMatchedNodesFromFile("/etc/hosts", *regex, *verbose)
	default:
		matchedNodes = returnMatchedNodesFromFile(*source, *regex, *verbose)
	}

	fmt.Println()

	validatedNodes := validateMatched(matchedNodes, *verbose)
	fmt.Printf("%d validated nodes, %d matched nodes\n", len(validatedNodes), len(matchedNodes))

	fmt.Println("********************************************************")
	fmt.Println()
	t := time.Now()
	timestr := fmt.Sprintf(t.Format("2006/01/02 15:04:05.000"))

	fmt.Printf("%s We will be running: %s as: %s\n", timestr, *command, user)
	fmt.Printf("%s There will be a %v timeout timer.\n", timestr, *timeout)
	time.Sleep(3 * time.Second)
	fmt.Println()

	pkey, err := ioutil.ReadFile(os.Getenv("HOME") + "/.ssh/id_rsa")
	if err != nil {
		log.Fatalf("unable to read private key: %v", err)
	}

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(pkey)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
	}

	config := &ssh.ClientConfig{
		User:    user,
		Timeout: *timeout,
		Auth: []ssh.AuthMethod{
			// Use the PublicKeys method for remote authentication.
			ssh.PublicKeys(signer),
		},
	}

	sshResults := make(chan sshResponse, 10)
	hostMap := make(map[string]struct{})
	failedMap := make(map[string]struct{})

	for _, hostname := range validatedNodes {
		go func(hostname string) {
			executeCmd(sshResults, *command, hostname, "22", config)
		}(hostname)
	}

	//create a timer so that if we don't get a response back, we give up
	timer := time.NewTimer(*timeout)
	for i := 0; i < len(validatedNodes); i++ {
		select {
		case res := <-sshResults:
			fmt.Print(res.resp)
			hostMap[res.hostname] = struct{}{}
			if res.failed {
				failedMap[res.hostname] = struct{}{}
			}
		case <-timer.C:
			fmt.Println()
			t := time.Now()
			timestr := fmt.Sprintf(t.Format("2006/01/02 15:04:05.000"))
			fmt.Printf("%s Timeout %v reached, no longer waiting for SSH command output.\n", timestr, *timeout)
			break
		}
	}

	fmt.Println()

	for _, i := range validatedNodes {
		_, ok := hostMap[i]
		if !ok {
			t := time.Now()
			timestr := fmt.Sprintf(t.Format("2006/01/02 15:04:05.000"))
			fmt.Printf("%s Failed to get response from: %s\n", timestr, i)
		}
	}

	for _, i := range validatedNodes {
		_, ok := failedMap[i]
		if ok {
			t := time.Now()
			timestr := fmt.Sprintf(t.Format("2006/01/02 15:04:05.000"))
			fmt.Printf("%s Possible problems from: %s\n", timestr, i)
		}
	}

}
