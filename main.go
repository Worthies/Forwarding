package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	portMappings arrayFlags
	detectIPAddr string
	listenAddr   string
	bufferSize   = 32 * 1024 // 32KB buffer for high performance
	bufferPool   = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, bufferSize)
			return &buf
		},
	}
)

type arrayFlags []string

func (a *arrayFlags) String() string {
	return strings.Join(*a, ",")
}

func (a *arrayFlags) Set(value string) error {
	*a = append(*a, value)
	return nil
}

type PortMapping struct {
	PublicPort  string
	PrivatePort string
}

func main() {
	flag.Var(&portMappings, "p", "Port mapping in format 'public:private' (can be specified multiple times or comma-separated)")
	flag.StringVar(&detectIPAddr, "d", "", "Optional local IP address to use for outbound detection (default: auto-detect via Google DNS addresses: 8.8.8.8, 8.8.4.4, 2001:4860:4860::8888, 2001:4860:4860::8844)")
	flag.StringVar(&listenAddr, "l", "", "Optional listen address (default: auto-detected public IP, use 0.0.0.0 for all interfaces)")
	flag.Parse()

	if len(portMappings) == 0 {
		fmt.Fprintf(os.Stderr, "Error: at least one port mapping is required\n")
		fmt.Fprintf(os.Stderr, "Usage: %s -p <public_port:private_port> [-d <detect_ip>] [-l <listen_addr>]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s -p 8080:80 -p 8443:443\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s -p 8080:80,8443:443\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s -p 8080:80 -l 0.0.0.0\n", os.Args[0])
		os.Exit(1)
	}

	// Determine the listen address
	var publicIP string
	if listenAddr != "" {
		publicIP = listenAddr
		log.Printf("Using specified listen address: %s", publicIP)
	} else {
		// Detect public IP
		ip, err := detectPublicIP(detectIPAddr)
		if err != nil {
			log.Printf("Warning: Failed to detect public IP: %v", err)
			log.Printf("Falling back to listening on all interfaces (0.0.0.0)")
			publicIP = "0.0.0.0"
		} else {
			publicIP = ip
			log.Printf("Detected public IP: %s", publicIP)
		}
	}

	// Parse port mappings
	mappings := parsePortMappings(portMappings)
	if len(mappings) == 0 {
		log.Fatal("No valid port mappings provided")
	}

	// Start forwarding for each mapping
	var wg sync.WaitGroup
	for _, mapping := range mappings {
		wg.Add(1)
		go func(m PortMapping) {
			defer wg.Done()
			if err := startForwarding(publicIP, m); err != nil {
				log.Printf("Error forwarding %s:%s -> 127.0.0.1:%s: %v",
					publicIP, m.PublicPort, m.PrivatePort, err)
			}
		}(mapping)
	}

	wg.Wait()
}

func parsePortMappings(flags []string) []PortMapping {
	var mappings []PortMapping
	for _, flag := range flags {
		// Split by comma for comma-separated mappings
		parts := strings.Split(flag, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			// Split by colon for port pair
			portPair := strings.Split(part, ":")
			if len(portPair) != 2 {
				log.Printf("Warning: invalid port mapping format '%s', skipping", part)
				continue
			}
			publicPort := strings.TrimSpace(portPair[0])
			privatePort := strings.TrimSpace(portPair[1])

			// Validate port numbers
			if !isValidPort(publicPort) {
				log.Printf("Warning: invalid public port '%s', skipping", publicPort)
				continue
			}
			if !isValidPort(privatePort) {
				log.Printf("Warning: invalid private port '%s', skipping", privatePort)
				continue
			}

			mappings = append(mappings, PortMapping{
				PublicPort:  publicPort,
				PrivatePort: privatePort,
			})
		}
	}
	return mappings
}

func isValidPort(port string) bool {
	// Parse port number
	var portNum int
	_, err := fmt.Sscanf(port, "%d", &portNum)
	if err != nil {
		return false
	}
	return portNum >= 1 && portNum <= 65535
}

func detectPublicIP(sourceIP string) (string, error) {
	// If sourceIP isn't provided, attempt to auto-detect the outbound local
	// IP by making a short UDP/TCP connection to a set of known public DNS
	// endpoints (Google DNS). This heuristic helps select the correct
	// outbound interface on multi-homed systems so that subsequent HTTP
	// requests use the same routing path.
	if sourceIP == "" {
		// Try Google public DNS endpoints (IPv4 and IPv6) as defaults.
		defaultTargets := []string{
			"8.8.8.8",
			"8.8.4.4",
			"2001:4860:4860::8888",
			"2001:4860:4860::8844",
		}
		if detected, err := detectOutboundLocalIP(defaultTargets, 2*time.Second); err == nil && detected != "" {
			sourceIP = detected
			log.Printf("Auto-detected outbound local IP: %s (using %v)", sourceIP, defaultTargets)
		} else {
			// Not fatal: continue with sourceIP empty and let the HTTP client
			// pick the default source address.
			if err != nil {
				log.Printf("Warning: failed to auto-detect outbound local IP: %v", err)
			}
		}
	}
	// Create HTTP client with custom transport
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
	}

	// If a specific source IP is provided, use it
	if sourceIP != "" {
		localAddr, err := net.ResolveTCPAddr("tcp", sourceIP+":0")
		if err != nil {
			return "", fmt.Errorf("invalid source IP: %v", err)
		}
		transport.DialContext = (&net.Dialer{
			LocalAddr: localAddr,
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	// Try multiple public IP detection services
	services := []string{
		"https://api.ipify.org",
		"https://icanhazip.com",
		"https://ifconfig.me",
	}

	var lastErr error
	for _, service := range services {
		resp, err := client.Get(service)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("service %s returned status %d", service, resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip, nil
		}
		lastErr = fmt.Errorf("invalid IP received from %s: %s", service, ip)
	}

	return "", fmt.Errorf("failed to detect public IP: %v", lastErr)
}

// detectOutboundLocalIP tries to determine the local outbound IP used to
// reach remote targets by opening a short UDP or TCP connection and returning
// the local address portion. It returns the first successful local IP.
func detectOutboundLocalIP(targets []string, timeout time.Duration) (string, error) {
	var lastErr error
	for _, target := range targets {
		// First try UDP (DNS); many networks allow outbound UDP for DNS.
		addr := net.JoinHostPort(target, "53")
		conn, err := net.DialTimeout("udp", addr, timeout)
		if err == nil {
			local := conn.LocalAddr()
			conn.Close()
			if udpAddr, ok := local.(*net.UDPAddr); ok && !udpAddr.IP.IsUnspecified() {
				return udpAddr.IP.String(), nil
			}
		} else {
			lastErr = err
		}

		// Try TCP (HTTPS) as a fallback.
		addr = net.JoinHostPort(target, "443")
		conn2, err2 := net.DialTimeout("tcp", addr, timeout)
		if err2 == nil {
			local := conn2.LocalAddr()
			conn2.Close()
			if tcpAddr, ok := local.(*net.TCPAddr); ok && !tcpAddr.IP.IsUnspecified() {
				return tcpAddr.IP.String(), nil
			}
		} else {
			lastErr = err2
		}
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("no valid target responded")
}

func startForwarding(publicIP string, mapping PortMapping) error {
	listenAddr := fmt.Sprintf("%s:%s", publicIP, mapping.PublicPort)
	forwardAddr := fmt.Sprintf("127.0.0.1:%s", mapping.PrivatePort)

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", listenAddr, err)
	}
	defer listener.Close()

	log.Printf("Forwarding %s -> %s", listenAddr, forwardAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection on %s: %v", listenAddr, err)
			continue
		}

		go handleConnection(conn, forwardAddr)
	}
}

func handleConnection(clientConn net.Conn, forwardAddr string) {
	defer clientConn.Close()

	// Connect to the local service
	serverConn, err := net.DialTimeout("tcp", forwardAddr, 10*time.Second)
	if err != nil {
		log.Printf("Error connecting to %s: %v", forwardAddr, err)
		return
	}
	defer serverConn.Close()

	// Enable TCP keepalive for better connection management
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true) // Disable Nagle's algorithm for lower latency
	}
	if tcpConn, ok := serverConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true)
	}

	// Use a WaitGroup to ensure both goroutines complete
	var wg sync.WaitGroup
	wg.Add(2)

	// Forward client -> server
	go func() {
		defer wg.Done()
		copyWithBuffer(serverConn, clientConn)
		// Close the write side to signal EOF
		if tcpConn, ok := serverConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// Forward server -> client
	go func() {
		defer wg.Done()
		copyWithBuffer(clientConn, serverConn)
		// Close the write side to signal EOF
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
}

func copyWithBuffer(dst io.Writer, src io.Reader) {
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	io.CopyBuffer(dst, src, *bufPtr)
}
