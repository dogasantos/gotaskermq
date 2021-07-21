package main

import (
	"github.com/streadway/amqp"
	"log"
	"math/rand"
	"time"
	"flag"
	"os"
	"fmt"
)

type Options struct {
	ipaddr string
}

func handleError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}

}

func main() {
	options := Options{}
	flag.StringVar(&options.ipaddr, 		"d", "", "target ip")
	flag.Parse()
	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	conn, err := amqp.Dial("amqp://rabbitmq:rabbitmq@localhost:5672/")
	handleError(err, "Can't connect to AMQP")
	defer conn.Close()

	// cria channel
	amqpChannel, err := conn.Channel()
	handleError(err, "Can't create a amqpChannel")
	defer amqpChannel.Close()

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

	rand.Seed(time.Now().UnixNano())

	err = amqpChannel.Publish("", queue.Name, false, false, amqp.Publishing{
		DeliveryMode: amqp.Persistent,
		ContentType:  "text/plain",
		Body:         []byte(options.ipaddr),
	})

	if err != nil {
		log.Fatalf("Error publishing message: %s", err)
	}

}