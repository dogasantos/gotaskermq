package main

import (
	"github.com/streadway/amqp"
    "context"
    "fmt"
    "log"
    "time"
	"strings"
	"os"

	"github.com/Ullaakut/nmap/v2"
)

func handleError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func runNmapFingerprint(target string, ports string) string {
	
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()

	fmt.Printf("Prepare target scan on %s at ports %s\n", target,ports)
	// CONFIGURE SCAN
    scanner, err := nmap.NewScanner(
        nmap.WithTargets(target),
        nmap.WithSkipHostDiscovery(),
        nmap.WithServiceInfo(),
		nmap.WithVersionIntensity(6),
		nmap.WithScripts("http-title,http-server-header,http-open-proxy,http-methods,http-headers,ssl-cert"),
		nmap.WithTimingTemplate(4),
		nmap.WithPorts(ports),
        nmap.WithContext(ctx),
    )
    if err != nil {
        log.Fatalf("unable to create nmap scanner: %v", err)
    }

	// RUN NMAP SCAN
    result, warnings, err := scanner.Run()
    if err != nil {
        log.Fatalf("unable to run nmap scan: %v", err)
    }

    if warnings != nil {
        log.Printf("Warnings: \n %v", warnings)
    }


    // Use the results to print an example output
    for _, host := range result.Hosts {
        if len(host.Ports) == 0 || len(host.Addresses) == 0 {
            continue
        }


        for _, port := range host.Ports {
            //fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
			fmt.Printf("\t%s:%d %s %s %s \n\t\t%s\n",host.Addresses[0], port.ID, port.Service.Tunnel, port.Service.Product, port.Service.Version, port.Service.CPEs )

        }
    }

    fmt.Printf("Nmap done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)


	rawXML := new(strings.Builder)
	_, err := io.Copy(rawXML, result.ToReader())
	
	fmt.Printf("======XML:========================\n")
	fmt.Printf("%s",rawXML.String())

	fmt.Printf("==================================\n")
	return string( rawXML.String() )
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


func main() {
	conn, err := amqp.Dial("amqp://rabbitmq:rabbitmq@localhost:5672/")
	handleError(err, "Can't connect to AMQP")
	defer conn.Close()

	// cria channel
	amqpChannel, err := conn.Channel()
	handleError(err, "Can't create a amqpChannel")

	exchangeName 	:= "ip"
	bindingKey   	:= "tcp.nmap.*"
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

			dados := strings.Split(string(d.Body),":")
			resultado := runNmapFingerprint(dados[0],dados[1])
			//ipaddr,portas := parseOutput()
			log.Printf("%s",len(string(resultado)))

			if err := d.Ack(false); err != nil {
				log.Printf("Error acknowledging message : %s", err)
			} else {
				log.Printf("Acknowledged message!")
				//log.Printf("Portas abertas no ip %s: %s", ipaddr, portas)
			}

		}
	}()

	// Stop for program termination
	<-stopChan
}
