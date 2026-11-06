package cap

import (
	"reflect"
	"strings"
	"testing"
)

const validTCP = `
name = "mongo"
description = "MongoDB through a proxy on the Mac"
[tcp]
upstream = "127.0.0.1:27016"
port = 27017
[guest.env]
MONGODB_URI = "mongodb://127.0.0.1:27017/app"
`

func TestParseValidTCPCap(t *testing.T) {
	c, err := Parse(validTCP, "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Kind() != KindTCP {
		t.Fatalf("kind = %q, want %q", c.Kind(), KindTCP)
	}
	if c.TCP.Upstream != "127.0.0.1:27016" || c.TCP.Port != 27017 {
		t.Errorf("unexpected tcp section: %+v", c.TCP)
	}
}

func TestTCPDial(t *testing.T) {
	cases := map[string]struct {
		upstream         string
		network, address string
	}{
		"host and port": {"127.0.0.1:27016", "tcp", "127.0.0.1:27016"},
		"name and port": {"db.internal:5432", "tcp", "db.internal:5432"},
		"ipv6":          {"[::1]:6379", "tcp", "[::1]:6379"},
		"unix socket":   {"unix:/Users/me/.skiff/mongo.sock", "unix", "/Users/me/.skiff/mongo.sock"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			network, address := TCP{Upstream: tc.upstream}.Dial()
			if network != tc.network || address != tc.address {
				t.Errorf("Dial() = %q, %q; want %q, %q", network, address, tc.network, tc.address)
			}
		})
	}
}

func TestParseRejectsTCPProblems(t *testing.T) {
	withUpstream := func(v string) string { return strings.Replace(validTCP, "127.0.0.1:27016", v, 1) }
	withPort := func(v string) string { return strings.Replace(validTCP, "port = 27017", "port = "+v, 1) }
	cases := map[string]struct {
		text string
		want string
	}{
		"no upstream":        {withUpstream(""), "tcp.upstream is required"},
		"upstream no port":   {withUpstream("127.0.0.1"), "tcp.upstream must be host:port or unix:/absolute/path"},
		"upstream no host":   {withUpstream(":27016"), "tcp.upstream must be host:port or unix:/absolute/path"},
		"upstream bad port":  {withUpstream("127.0.0.1:99999"), "tcp.upstream must be host:port or unix:/absolute/path"},
		"upstream is a URL":  {withUpstream("mongodb://127.0.0.1:27016"), "tcp.upstream must be host:port or unix:/absolute/path"},
		"relative socket":    {withUpstream("unix:run/mongo.sock"), "tcp.upstream must be host:port or unix:/absolute/path"},
		"socket with dots":   {withUpstream("unix:/tmp/../etc/x.sock"), "tcp.upstream must be host:port or unix:/absolute/path"},
		"home in socket":     {withUpstream("unix:~/mongo.sock"), "tcp.upstream must be host:port or unix:/absolute/path"},
		"no port":            {strings.Replace(validTCP, "port = 27017\n", "", 1), "tcp.port must be between 1 and 65535"},
		"port too large":     {withPort("70000"), "tcp.port must be between 1 and 65535"},
		"negative port":      {withPort("-1"), "tcp.port must be between 1 and 65535"},
		"broker port":        {withPort("7777"), "tcp.port 7777 is the broker's own port"},
		"ssh port":           {withPort("22"), "tcp.port 22 is the guest's SSH port"},
		"two kinds":          {validTCP + "\n[exec]\ncommand = \"x\"\n", "exactly one of"},
		"secret in guest":    {strings.Replace(validTCP, "mongodb://127.0.0.1:27017/app", `{{ secret \"env:A\" }}`, 1), "secret is not available in guest sections"},
		"unknown tcp key":    {strings.Replace(validTCP, "port = 27017", "port = 27017\npassword = \"x\"", 1), "unknown keys: tcp.password"},
		"template upstream":  {withUpstream(`{{ secret \"env:A\" }}`), "tcp.upstream must be host:port or unix:/absolute/path"},
		"whitespace in host": {withUpstream("my host:5432"), "tcp.upstream must be host:port or unix:/absolute/path"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(tc.text, "test")
			if err == nil {
				t.Fatalf("want an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func tcpCap(name, upstream string, port int) Cap {
	return Cap{Name: name, TCP: &TCP{Upstream: upstream, Port: port}}
}

func TestTCPForwards(t *testing.T) {
	set := Set{
		"mongo":    tcpCap("mongo", "127.0.0.1:27016", 27017),
		"postgres": tcpCap("postgres", "unix:/tmp/pg.sock", 5432),
		"mongo2":   tcpCap("mongo2", "127.0.0.1:27018", 27017),
		"claude":   {Name: "claude", Proxy: &Proxy{Upstream: "https://api.anthropic.com"}},
	}
	t.Run("granted tcp caps in name order", func(t *testing.T) {
		got, err := set.TCPForwards([]string{"postgres", "claude", "mongo", "gone"})
		if err != nil {
			t.Fatalf("TCPForwards: %v", err)
		}
		want := []TCPForward{
			{Cap: "mongo", Port: 27017, Upstream: "127.0.0.1:27016"},
			{Cap: "postgres", Port: 5432, Upstream: "unix:/tmp/pg.sock"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})
	t.Run("none granted", func(t *testing.T) {
		got, err := set.TCPForwards([]string{"claude"})
		if err != nil || len(got) != 0 {
			t.Errorf("got %+v, %v; want none", got, err)
		}
	})
	t.Run("two caps on one guest port", func(t *testing.T) {
		_, err := set.TCPForwards([]string{"mongo2", "mongo"})
		if err == nil {
			t.Fatal("want an error for a port forwarded twice")
		}
		for _, want := range []string{"mongo", "mongo2", "27017"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not name %q", err, want)
			}
		}
	})
}
