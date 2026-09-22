package waf

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	defaultCoordinatorMaxEntries  = 10000
	defaultCoordinatorEntryTTL    = 10 * time.Minute
	defaultCoordinatorRPCTimeout  = 2 * time.Second
	defaultCoordinatorIdleTimeout = 30 * time.Second
	maxCoordinatorKeyBytes        = 512
	maxCoordinatorConnections     = 256
)

type coordinatorLimiter struct {
	limiter  *rate.Limiter
	limit    float64
	burst    int
	lastSeen time.Time
}

type idleDeadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleDeadlineConn) Read(p []byte) (int, error) {
	if err := c.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c *idleDeadlineConn) Write(p []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

// Coordinator handles cluster-wide rate-limit state synchronization using authenticated net/rpc.
type Coordinator struct {
	mu              sync.Mutex
	limiters        map[string]*coordinatorLimiter
	role            string
	address         string
	secret          string
	listener        net.Listener
	connections     map[net.Conn]struct{}
	connectionSlots chan struct{}
	maxEntries      int
	entryTTL        time.Duration
	rpcTimeout      time.Duration
	serverTLS       *tls.Config
	clientTLS       *tls.Config
	tlsFingerprint  [sha256.Size]byte
	now             func() time.Time
	nextCleanup     time.Time
	clientMu        sync.Mutex
	client          *rpc.Client
	clientConn      net.Conn
	clientLastUsed  time.Time
	clientClosed    bool
	serverClosed    bool
}

// ConfigureTLS loads the coordinator's server or client TLS material.
func (c *Coordinator) ConfigureTLS(caFile, certFile, keyFile, serverName string) error {
	switch c.role {
	case "leader":
		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			return fmt.Errorf("read server certificate: %w", err)
		}
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("read server key: %w", err)
		}
		certificate, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return fmt.Errorf("load server certificate: %w", err)
		}
		serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
		fingerprintInput := append(append([]byte("leader\x00"), certPEM...), keyPEM...)
		if caFile != "" {
			caPEM, err := os.ReadFile(caFile)
			if err != nil {
				return fmt.Errorf("read client CA file: %w", err)
			}
			clientCAs := x509.NewCertPool()
			if !clientCAs.AppendCertsFromPEM(caPEM) {
				return fmt.Errorf("client CA file contains no certificates")
			}
			serverTLS.ClientCAs = clientCAs
			serverTLS.ClientAuth = tls.RequireAndVerifyClientCert
			fingerprintInput = append(fingerprintInput, caPEM...)
		}
		c.serverTLS = serverTLS
		c.tlsFingerprint = sha256.Sum256(fingerprintInput)
	case "follower":
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return fmt.Errorf("read CA file: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("CA file contains no certificates")
		}
		clientTLS := &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS13}
		fingerprintInput := append([]byte("follower\x00"+serverName+"\x00"), caPEM...)
		if (certFile == "") != (keyFile == "") {
			return fmt.Errorf("client certificate and key must be configured together")
		}
		if certFile != "" {
			certPEM, err := os.ReadFile(certFile)
			if err != nil {
				return fmt.Errorf("read client certificate: %w", err)
			}
			keyPEM, err := os.ReadFile(keyFile)
			if err != nil {
				return fmt.Errorf("read client key: %w", err)
			}
			certificate, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				return fmt.Errorf("load client certificate: %w", err)
			}
			clientTLS.Certificates = []tls.Certificate{certificate}
			fingerprintInput = append(append(fingerprintInput, certPEM...), keyPEM...)
		}
		c.clientTLS = clientTLS
		c.tlsFingerprint = sha256.Sum256(fingerprintInput)
	default:
		return fmt.Errorf("unsupported coordinator role %q", c.role)
	}
	return nil
}

func (c *Coordinator) sameConfiguration(other *Coordinator) bool {
	return c != nil && other != nil &&
		c.role == other.role &&
		c.address == other.address &&
		c.secret == other.secret &&
		c.tlsFingerprint == other.tlsFingerprint
}

// CheckLimitArgs is the argument for the RPC CheckLimit method.
type CheckLimitArgs struct {
	Key    string
	Limit  float64
	Burst  int
	Secret string
}

// CheckLimitReply is the response from the RPC CheckLimit method.
type CheckLimitReply struct {
	Allowed bool
}

// NewCoordinator creates a new RPC coordinator.
func NewCoordinator(role, address, secret string) *Coordinator {
	return &Coordinator{
		limiters:        make(map[string]*coordinatorLimiter),
		role:            role,
		address:         address,
		secret:          secret,
		connections:     make(map[net.Conn]struct{}),
		connectionSlots: make(chan struct{}, maxCoordinatorConnections),
		maxEntries:      defaultCoordinatorMaxEntries,
		entryTTL:        defaultCoordinatorEntryTTL,
		rpcTimeout:      defaultCoordinatorRPCTimeout,
		now:             time.Now,
	}
}

// Start initializes the coordinator based on its role.
func (c *Coordinator) Start() error {
	if c.secret == "" {
		return fmt.Errorf("coordinator secret is required")
	}
	switch c.role {
	case "leader":
		if c.serverTLS == nil {
			return fmt.Errorf("coordinator TLS is not configured")
		}
		return c.startServer()
	case "follower":
		if c.clientTLS == nil {
			return fmt.Errorf("coordinator TLS is not configured")
		}
		return nil
	default:
		return fmt.Errorf("unsupported coordinator role %q", c.role)
	}
}

func (c *Coordinator) startServer() error {
	rpcServer := rpc.NewServer()
	if err := rpcServer.Register(c); err != nil {
		return fmt.Errorf("register coordinator RPC: %w", err)
	}

	tcpListener, err := net.Listen("tcp", c.address)
	if err != nil {
		return err
	}
	listener := tls.NewListener(tcpListener, c.serverTLS)
	c.mu.Lock()
	c.listener = listener
	c.mu.Unlock()

	ErrorLog.Infof("Coordinator leader listening on %s", listener.Addr())
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				ErrorLog.Errorf("Coordinator accept error: %v", err)
				continue
			}
			select {
			case c.connectionSlots <- struct{}{}:
			default:
				_ = conn.Close()
				continue
			}
			conn = &idleDeadlineConn{Conn: conn, timeout: defaultCoordinatorIdleTimeout}
			c.mu.Lock()
			if c.serverClosed {
				c.mu.Unlock()
				<-c.connectionSlots
				_ = conn.Close()
				return
			}
			c.connections[conn] = struct{}{}
			c.mu.Unlock()
			go func() {
				defer func() {
					c.mu.Lock()
					delete(c.connections, conn)
					c.mu.Unlock()
					<-c.connectionSlots
					_ = conn.Close()
				}()
				rpcServer.ServeConn(conn)
			}()
		}
	}()
	return nil
}

// CheckLimit is the authenticated RPC method called by followers.
func (c *Coordinator) CheckLimit(args *CheckLimitArgs, reply *CheckLimitReply) error {
	if args == nil || reply == nil {
		return fmt.Errorf("coordinator request and reply are required")
	}
	if subtle.ConstantTimeCompare([]byte(args.Secret), []byte(c.secret)) != 1 {
		return fmt.Errorf("unauthorized")
	}
	if args.Key == "" || len(args.Key) > maxCoordinatorKeyBytes {
		return fmt.Errorf("invalid rate-limit key")
	}
	if args.Limit <= 0 || args.Burst <= 0 {
		return fmt.Errorf("limit and burst must be positive")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.nextCleanup.IsZero() || !now.Before(c.nextCleanup) {
		for key, entry := range c.limiters {
			if now.Sub(entry.lastSeen) > c.entryTTL {
				delete(c.limiters, key)
			}
		}
		cleanupInterval := max(c.entryTTL/10, time.Second)
		c.nextCleanup = now.Add(cleanupInterval)
	}

	entry, ok := c.limiters[args.Key]
	if !ok || entry.limit != args.Limit || entry.burst != args.Burst {
		if !ok && len(c.limiters) >= c.maxEntries {
			oldestKey := ""
			var oldest time.Time
			for key, candidate := range c.limiters {
				if oldestKey == "" || candidate.lastSeen.Before(oldest) {
					oldestKey = key
					oldest = candidate.lastSeen
				}
			}
			delete(c.limiters, oldestKey)
		}
		entry = &coordinatorLimiter{
			limiter:  rate.NewLimiter(rate.Limit(args.Limit), args.Burst),
			limit:    args.Limit,
			burst:    args.Burst,
			lastSeen: now,
		}
		c.limiters[args.Key] = entry
	} else {
		entry.lastSeen = now
	}

	reply.Allowed = entry.limiter.Allow()
	return nil
}

// Allow checks if a request is allowed according to cluster-wide state.
func (c *Coordinator) Allow(key string, limit float64, burst int) (bool, error) {
	args := &CheckLimitArgs{Key: key, Limit: limit, Burst: burst, Secret: c.secret}
	var reply CheckLimitReply
	if c.role == "leader" {
		err := c.CheckLimit(args, &reply)
		return reply.Allowed, err
	}

	c.clientMu.Lock()
	defer c.clientMu.Unlock()
	if c.clientClosed {
		return false, net.ErrClosed
	}
	if c.client != nil && c.now().Sub(c.clientLastUsed) >= defaultCoordinatorIdleTimeout {
		c.closeFollowerClientLocked()
	}
	if c.client == nil {
		if err := c.dialFollowerLocked(); err != nil {
			return false, err
		}
	}
	if err := c.clientConn.SetDeadline(c.now().Add(c.rpcTimeout)); err != nil {
		c.closeFollowerClientLocked()
		return false, err
	}
	if err := c.client.Call("Coordinator.CheckLimit", args, &reply); err != nil {
		c.closeFollowerClientLocked()
		return false, err
	}
	c.clientLastUsed = c.now()
	if err := c.clientConn.SetDeadline(c.clientLastUsed.Add(defaultCoordinatorIdleTimeout)); err != nil {
		c.closeFollowerClientLocked()
		return false, err
	}
	return reply.Allowed, nil
}

func (c *Coordinator) dialFollowerLocked() error {
	dialer := net.Dialer{Timeout: c.rpcTimeout}
	conn, err := tls.DialWithDialer(&dialer, "tcp", c.address, c.clientTLS)
	if err != nil {
		return err
	}
	c.clientConn = conn
	c.client = rpc.NewClient(conn)
	c.clientLastUsed = c.now()
	return nil
}

func (c *Coordinator) closeFollowerClientLocked() {
	if c.client != nil {
		_ = c.client.Close()
	} else if c.clientConn != nil {
		_ = c.clientConn.Close()
	}
	c.client = nil
	c.clientConn = nil
	c.clientLastUsed = time.Time{}
}

// Close releases coordinator listeners and active connections.
func (c *Coordinator) Close() error {
	c.clientMu.Lock()
	c.clientClosed = true
	client := c.client
	clientConn := c.clientConn
	c.client = nil
	c.clientConn = nil
	c.clientLastUsed = time.Time{}
	c.clientMu.Unlock()

	c.mu.Lock()
	c.serverClosed = true
	listener := c.listener
	c.listener = nil
	connections := make([]net.Conn, 0, len(c.connections))
	for conn := range c.connections {
		connections = append(connections, conn)
	}
	c.mu.Unlock()

	var errs []error
	if client != nil {
		errs = append(errs, client.Close())
	} else if clientConn != nil {
		errs = append(errs, clientConn.Close())
	}
	if listener != nil {
		errs = append(errs, listener.Close())
	}
	for _, conn := range connections {
		errs = append(errs, conn.Close())
	}
	return errors.Join(errs...)
}
