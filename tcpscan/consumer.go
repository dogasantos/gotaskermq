package main

import (
	"github.com/streadway/amqp"
	"log"
	"os"

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
	options.Ping = false
	options.ExcludeCDN = true
	options.Rate = 2000
	options.Timeout = 4
	options.Retries = 2
	options.Host = targetip        
	//Ports
	options.TopPorts = "100"
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
