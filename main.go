package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	flag.StringVar(&listenAddr, "l", "", "Optional listen address (default: auto-detected local outbound interface IP; use 0.0.0.0 for all interfaces)")
	flag.Parse()

	if len(portMappings) == 0 {
		fmt.Fprintf(os.Stderr, "Error: at least one port mapping is required\n")
		fmt.Fprintf(os.Stderr, "Usage: %s -p <public_port:private_port> [-d <detect_ip>] [-l <listen_addr>]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s -p 8080:80 -p 8443:443\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s -p 8080:80,8443:443\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s -p 8080:80 -l 0.0.0.0\n", os.Args[0])
		os.Exit(1)
	}

	// Determine the bind/listen address
	var bindIP string
	if listenAddr != "" {
		// If user explicitly specified a listen address (not 0.0.0.0), ensure
		// it is a local interface address; otherwise fail early.
		if listenAddr != "0.0.0.0" && !isLocalIP(listenAddr) {
			log.Fatalf("Specified listen address '%s' is not a local interface address", listenAddr)
		}
		bindIP = listenAddr
		log.Printf("Using specified listen address: %s", bindIP)
	} else {
		// Detect the best local interface to use for public network outbound
		// communication, and bind the listeners to that local interface.
		// We still attempt to detect the external public IP for logging, but
		// we should not bind to the external public IP (it might be a LB or NAT).
		outboundIP, _ := detectOutboundLocalIP([]string{"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"}, 2*time.Second)
		if outboundIP != "" {
			bindIP = outboundIP
			log.Printf("Using outbound local interface IP as listen address: %s", bindIP)
		} else {
			// Fallback to wildcard listen address if we can't determine the
			// outbound interface; this is uncommon but acceptable if the host
			// needs to listen on all interfaces.
			bindIP = "0.0.0.0"
			log.Printf("Could not detect outbound local interface; falling back to all interfaces (0.0.0.0)")
		}

		// Try to detect the external public IP for reporting purposes. We
		// pass the outbound local IP (if available) as the source so the
		// detection uses the same outbound interface.
		ip, err := detectPublicIP(outboundIP)
		if err != nil {
			log.Printf("Warning: Failed to detect public IP: %v", err)
		} else {
			// Log the detected public IP, but still bind to the local interface
			// IP to which we'll attach listeners.
			log.Printf("Detected public IP: %s", ip)
		}
	}

	// Parse port mappings
	mappings := parsePortMappings(portMappings)
	if len(mappings) == 0 {
		log.Fatal("No valid port mappings provided")
	}

	// Start forwarding for each mapping
	var wg sync.WaitGroup
	// Create a cancellable context that will be canceled on SIGINT or SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for _, mapping := range mappings {
		wg.Add(1)
		go func(m PortMapping) {
			defer wg.Done()
			if err := startForwarding(ctx, bindIP, m); err != nil {
				log.Printf("Error forwarding %s:%s -> 127.0.0.1:%s: %v",
					bindIP, m.PublicPort, m.PrivatePort, err)
			}
		}(mapping)
	}

	// Wait for cancel signal (SIGINT/SIGTERM)
	<-ctx.Done()
	log.Printf("Shutdown signal received, closing listeners and waiting for active connections to finish")

	// Give forwarders some time to shut down gracefully
	shutdownTimeout := 10 * time.Second
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		log.Printf("All forwarders shut down")
	case <-time.After(shutdownTimeout):
		log.Printf("Timeout waiting for forwarders to exit; forcing exit")
	}
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
	portNum, err := strconv.Atoi(port)
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

	var client *http.Client
	if sourceIP != "" {
		// Create custom transport with source IP binding
		localAddr, err := net.ResolveTCPAddr("tcp", sourceIP+":0")
		if err != nil {
			return "", fmt.Errorf("invalid source IP: %v", err)
		}
		transport := &http.Transport{
			DialContext: (&net.Dialer{
				LocalAddr: localAddr,
				Timeout:   10 * time.Second,
				KeepAlive: 10 * time.Second,
			}).DialContext,
		}
		client = &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		}
	} else {
		// Use default client for standard case
		client = http.DefaultClient
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

// isLocalIP checks whether the provided ipStr matches any local interface address
// on the host. It returns true if a matching address exists.
func isLocalIP(ipStr string) bool {
	if ipStr == "" {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Warning: failed to enumerate network interfaces: %v", err)
		return false
	}
	for _, iface := range ifaces {
		// Skip down interfaces
		if (iface.Flags & net.FlagUp) == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.IP.Equal(ip) {
					return true
				}
			case *net.IPAddr:
				if v.IP.Equal(ip) {
					return true
				}
			}
		}
	}
	return false
}

func startForwarding(ctx context.Context, bindIP string, mapping PortMapping) error {
	listenAddr := fmt.Sprintf("%s:%s", bindIP, mapping.PublicPort)
	forwardAddr := fmt.Sprintf("127.0.0.1:%s", mapping.PrivatePort)

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", listenAddr, err)
	}
	// Ensure the listener is closed when the function returns
	closed := make(chan struct{})
	defer func() {
		listener.Close()
		close(closed)
	}()

	log.Printf("Forwarding %s -> %s", listenAddr, forwardAddr)

	// If the context is canceled, close the listener to interrupt Accept()
	go func() {
		select {
		case <-ctx.Done():
			// Close the listener; Accept() will return an error and the loop will exit.
			listener.Close()
		case <-closed:
			// Normal shutdown of this function
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// If listener was closed due to context cancel, exit gracefully
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			// If it's a temporary error, retry a few times
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				log.Printf("Temporary accept error on %s: %v", listenAddr, err)
				time.Sleep(50 * time.Millisecond)
				continue
			}
			// Unrecoverable error
			return fmt.Errorf("error accepting connection on %s: %v", listenAddr, err)
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
		if err := tcpConn.SetKeepAlive(true); err != nil {
			log.Printf("Warning: failed to set keepalive on clientConn: %v", err)
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			log.Printf("Warning: failed to set keepalive period on clientConn: %v", err)
		}
		if err := tcpConn.SetNoDelay(true); err != nil { // Disable Nagle's algorithm for lower latency
			log.Printf("Warning: failed to set no delay on clientConn: %v", err)
		}
	}

	if tcpConn, ok := serverConn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			log.Printf("Warning: failed to set keepalive on serverConn: %v", err)
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			log.Printf("Warning: failed to set keepalive period on serverConn: %v", err)
		}
		if err := tcpConn.SetNoDelay(true); err != nil {
			log.Printf("Warning: failed to set no delay on serverConn: %v", err)
		}
	}

	// Use a WaitGroup to ensure both goroutines complete
	var wg sync.WaitGroup
	wg.Add(2)

	// Forward client -> server
	go func() {
		defer wg.Done()
		err := copyWithBuffer(serverConn, clientConn)
		// Only signal EOF if copy completed successfully
		if tcpConn, ok := serverConn.(*net.TCPConn); ok {
			if err == nil {
				tcpConn.CloseWrite()
			} else {
				tcpConn.Close()
			}
		}
	}()

	// Forward server -> client
	go func() {
		defer wg.Done()
		err := copyWithBuffer(clientConn, serverConn)
		// Only signal EOF if copy completed successfully
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			if err == nil {
				tcpConn.CloseWrite()
			} else {
				tcpConn.Close()
			}
		}
	}()

	wg.Wait()
}

func copyWithBuffer(dst io.Writer, src io.Reader) error {
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	_, err := io.CopyBuffer(dst, src, *bufPtr)
	return err
}
