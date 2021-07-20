package main

import (
	"github.com/streadway/amqp"
	"log"
	"os"
	"fmt"

	
	"bytes"
	"context"
	"io"
	"io/ioutil"
	
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"

)

func handleError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}


func runSubFinder(targetdomain string) []string {
	var list_of_subs []string

	config := runner.ConfigFile{
		// Use the default list of resolvers by marshaling it to the config
		Resolvers: resolve.DefaultResolvers,
		// Use the default list of passive sources
		Sources: passive.DefaultSources,
		// Use the default list of all passive sources
		AllSources: passive.DefaultAllSources,
		// Use the default list of recursive sources
		Recursive: passive.DefaultRecursiveSources,
	}
	runnerInstance, err := runner.NewRunner(&runner.Options{
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		YAMLConfig:         config,
	})

	buf := bytes.Buffer{}
	err = runnerInstance.EnumerateSingleDomain(context.Background(), targetdomain, []io.Writer{&buf})
	if err != nil {
		log.Fatal(err)
	}

	data, err := ioutil.ReadAll(&buf)
	if err != nil {
		log.Fatal(err)
	}
	
	for _, item := range data {
		fmt.Printf("%s", string(item))
		list_of_subs = append(list_of_subs, string(item))
	}

		
	return list_of_subs
}




func main() {
	conn, err := amqp.Dial("amqp://rabbitmq:rabbitmq@localhost:5672/")
	handleError(err, "Can't connect to AMQP")
	defer conn.Close()

	// cria channel
	amqpChannel, err := conn.Channel()
	handleError(err, "Can't create a amqpChannel")

	exchangeName 	:= "domain"
	bindingKey   	:= "search.subfinder.*"
	queueName 		:= "domains"

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
			log.Printf("New domain to work with: %s", d.Body)

			found := runSubFinder(string(d.Body))

			if err := d.Ack(false); err != nil {
				log.Printf("Error acknowledging message : %s", err)
			} else {
				log.Printf("Acknowledged message!")
				log.Printf("Found: ")
				log.Printf("%s",found)

			}

		}
	}()

	// Stop for program termination
	<-stopChan
}
