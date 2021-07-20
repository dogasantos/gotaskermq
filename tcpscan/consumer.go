package main

import (
	"github.com/streadway/amqp"
	"log"
	"os"
	"io/ioutil"

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

	// Parse the command line flags and read config files
	//options := runner.ParseOptions()
	var options runner.Options
	options.Silent = true
	//options.Debug = true
	options.Ping = false
	options.ExcludeCDN = true
	//options.Rate = 200
	options.Timeout = 6
	options.Retries = 2
	options.WarmUpTime = 4
	options.Host = targetip
	options.Interface = "enp1s0"
	options.InterfacesList = false
	options.Ports = "21-100,106,110-199,389,427,443,444,445,465,513,514,515,543-548,554,587,631,646,873,990-995,1025-1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051-5090,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080-8090,8440-8450,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157"
	//options.TopPorts = "100"
	options.Threads = 10
	options.Nmap = true
	options.NmapCLI = "nmap -sV -oX /tmp/nmap-output.xml --script=http-title,http-server-header,http-open-proxy,http-methods,http-headers,ssl-cert"

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	err = naabuRunner.RunEnumeration()
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
}


func checkNmapResults(){
	nmapxml := "/tmp/nmap-results.xml"

	_, err := os.Lstat(nmapxml)
	handleError(err,"Can't stat /tmp/nmap-results.xml")
	
	filecontent, err := ioutil.ReadFile(nmapxml)
	handleError(err,"Can't read /tmp/nmap-results.xml")
	
	_ = os.Remove(nmapxml) //toctou
	//handleError(err,"Can't remove /tmp/nmap-results.xml")
	
	log.Printf("==========================================================")
	log.Printf("==========================================================")

	log.Printf("%s",filecontent)

	log.Printf("==========================================================")
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
			 checkNmapResults()

			if err := d.Ack(false); err != nil {
				log.Printf("Error acknowledging message : %s", err)
			} else {
				log.Printf("Acknowledged message!")
				log.Printf("Found: ")

			}

		}
	}()

	// Stop for program termination
	<-stopChan
}
