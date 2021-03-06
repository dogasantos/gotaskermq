package main

import (
	"github.com/streadway/amqp"
	"log"
	"os"
	"io/ioutil"
	"strings"

	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"

)

func handleError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func runTcpScan(targetip string) {
	var options runner.Options
	options.Silent = true
	options.Verbose = false  // mudar
	options.Debug = false // mudar
	options.Ping = false
	options.EnableProgressBar = false
	options.ScanType = "s"
	options.ExcludeCDN = true
	options.Rate = 400
	options.Timeout = 8
	options.Retries = 3
	options.WarmUpTime = 5
	options.Host = targetip
	options.Interface = "enp1s0"
	options.InterfacesList = false
	options.TopPorts = "100"
	options.Threads = 6
	options.Nmap = false
	options.Output = "/tmp/naabu-output.txt"
	//options.NmapCLI = "nmap -sV -oX /tmp/nmap-results.xml --script=http-title,http-server-header,http-open-proxy,http-methods,http-headers,ssl-cert"

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	err = naabuRunner.RunEnumeration()
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
}

func parseOutput(conteudo []byte) (string, []string) {
	var results []string
	var ipaddr string 

	linhas := strings.Split(string(conteudo), "\n")
	for _,item := range linhas {
		ipport := strings.Split(item, ":")
		if len(ipport) > 1 {
			ipaddr = ipport[0]
			//log.Printf("Porta encontrada: %s",port[1])
			results = append(results, ipport[1])
		}
	}

	return ipaddr,results
}

func checkScanResults() (string, []string) {
	noutput := "/tmp/naabu-output.txt"

	fc, err := ioutil.ReadFile(noutput)
	handleError(err,"Can't read /tmp/naabu-output.txt")

	return parseOutput(fc)
}


func main() {
	conn, err := amqp.Dial("amqp://rabbitmq:rabbitmq@localhost:5672/")
	handleError(err, "Can't connect to AMQP")
	defer conn.Close()

	// cria channel
	amqpChannel, err := conn.Channel()
	handleError(err, "Can't create a amqpChannel")

	exchangeName 	:= "ip"
	bindingKey   	:= "tcp.scan.*"
	queueName 		:= "iptarget"

	// Create the exchange if it doesn't already exist.
	err = amqpChannel.ExchangeDeclare(
		exchangeName, 	// name
		"topic",  		// type
		true,         	// durable
		false,
		false,
		false,
		nil,
	)

	defer amqpChannel.Close()
	
	// cria Queue
	queue, err := amqpChannel.QueueDeclare(queueName, true, false, false, false, nil)
	handleError(err, "Could not declare queue")

	// Bind the queue to the exchange based on a string pattern (binding key).
	err = amqpChannel.QueueBind(
		queue.Name,			// queue name
		bindingKey,		// binding key
		exchangeName,	// exchange
		false,
		nil,
	)


	err = amqpChannel.Qos(1, 0, false)
	handleError(err, "Could not configure QoS")

	// consome queue
	messageChannel, err := amqpChannel.Consume(
		queue.Name,
		"",
		false,
		false,
		false,
		false,
		nil,
	)
	handleError(err, "Could not register consumer")

	stopChan := make(chan bool)

	go func() {
		log.Printf("Consumer ready, PID: %d", os.Getpid())
		for d := range messageChannel {
			log.Printf("New ipaddr to work with: %s", d.Body)

			runTcpScan(string(d.Body))
			ipaddr,portas := checkScanResults()
			

			if err := d.Ack(false); err != nil {
				log.Printf("Error acknowledging message : %s", err)
			} else {
				log.Printf("Acknowledged message!")
				ip_portas := ipaddr + ":"+strings.Join(portas, ",")
				log.Printf("Portas abertas: %s",ip_portas)
			}

		}
	}()

	// Stop for program termination
	<-stopChan
}
