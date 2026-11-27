package mapping

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/redis/go-redis/v9"
)

// Synthetic CPF (valid check digits, no real person).
const syntheticCPF = "12345678909"

// fakeRedis answers the few commands the mapping lookup sends (GET, LRANGE,
// HGET, SETEX) over RESP2, keeping the strings in memory.
type fakeRedis struct {
	mu      sync.Mutex
	strings map[string]string
	lists   map[string][]string
	hashes  map[string]map[string]string
}

func readCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("unexpected line %q", line)
	}
	n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		header, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		size, err := strconv.Atoi(strings.TrimSpace(header[1:]))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:size]))
	}
	return args, nil
}

func bulk(s string) string { return fmt.Sprintf("$%d\r\n%s\r\n", len(s), s) }

func (f *fakeRedis) reply(args []string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch strings.ToUpper(args[0]) {
	case "GET":
		if v, ok := f.strings[args[1]]; ok {
			return bulk(v)
		}
		return "$-1\r\n"
	case "SETEX":
		f.strings[args[1]] = args[3]
		return "+OK\r\n"
	case "LRANGE":
		list := f.lists[args[1]]
		out := fmt.Sprintf("*%d\r\n", len(list))
		for _, v := range list {
			out += bulk(v)
		}
		return out
	case "HGET":
		if v, ok := f.hashes[args[1]][args[2]]; ok {
			return bulk(v)
		}
		return "$-1\r\n"
	case "PING":
		return "+PONG\r\n"
	}
	return "-ERR unknown command\r\n"
}

func (f *fakeRedis) serve(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				r := bufio.NewReader(conn)
				for {
					args, err := readCommand(r)
					if err != nil || len(args) == 0 {
						return
					}
					if _, err := io.WriteString(conn, f.reply(args)); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestRedisLookupLogsMaskTheCPFInThePath(t *testing.T) {
	fake := &fakeRedis{
		strings: map[string]string{},
		lists:   map[string][]string{"heimdall:mappings:patterns:GET": {"7"}},
		hashes: map[string]map[string]string{"heimdall:mappings:all": {
			"7": `{"id":7,"method":"GET","path_pattern":"^/v1/citizen/[0-9]+/wallet$","action_id":3,"action_name":"citizen:read"}`,
		}},
	}
	rdb := redis.NewClient(&redis.Options{Addr: fake.serve(t), Protocol: 2, DisableIdentity: true})
	t.Cleanup(func() { _ = rdb.Close() })
	c := &client{config: &Config{}, redisClient: rdb}

	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	path := "/v1/citizen/" + syntheticCPF + "/wallet"
	for i := 0; i < 2; i++ { // the 1st call matches the pattern, the 2nd hits the lookup cache
		action, mapping, err := c.GetAction(context.Background(), path, "GET")
		if err != nil || action != "citizen:read" {
			t.Fatalf("GetAction #%d = %q, %v; want citizen:read", i+1, action, err)
		}
		if mapping.Path != path {
			t.Fatalf("the mapping must keep the real path, got %q", mapping.Path)
		}
	}
	// The lookup cache stays keyed by the real path, or the 2nd call would miss.
	fake.mu.Lock()
	_, cached := fake.strings["heimdall:mappings:lookup:GET:"+path]
	fake.mu.Unlock()
	if !cached {
		t.Fatal("the lookup cache must stay keyed by the real path")
	}
	_, _, err := c.GetAction(context.Background(), "/v1/other/"+syntheticCPF, "GET")
	if err == nil || strings.Contains(err.Error(), syntheticCPF) || !strings.Contains(err.Error(), "/v1/other/[CPF]") {
		t.Fatalf("no-mapping error must carry the masked path, got %v", err)
	}

	logs := buf.String()
	if strings.Contains(logs, syntheticCPF) {
		t.Fatalf("[MAPPING] logs leak the CPF in the path:\n%s", logs)
	}
	for _, want := range []string{
		"Cache MISS: GET /v1/citizen/[CPF]/wallet",
		"Testing '/v1/citizen/[CPF]/wallet' against '^/v1/citizen/[0-9]+/wallet$'",
		"Caching result: heimdall:mappings:lookup:GET:/v1/citizen/[CPF]/wallet",
		"Cache HIT: GET /v1/citizen/[CPF]/wallet",
		"Resolved: GET /v1/citizen/[CPF]/wallet -> citizen:read",
		"No pattern matches found for GET /v1/other/[CPF]",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lost %q:\n%s", want, logs)
		}
	}
}
