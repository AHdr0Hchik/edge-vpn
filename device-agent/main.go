package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type Config struct {
	ServerURL          string `json:"server_url"`
	DeviceID           string `json:"device_id"`
	Token              string `json:"token"`
	WgConfPath         string `json:"wg_conf_path"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`

	WanIf string `json:"wan_if"`
	LanIf string `json:"lan_if"`
}

type Message struct {
	Type     string          `json:"type"`
	DeviceID string          `json:"deviceId,omitempty"`
	Version  string          `json:"version,omitempty"`
	Action   string          `json:"action,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
	OK       bool            `json:"ok,omitempty"`
	Error    string          `json:"error,omitempty"`
}

type Profile struct {
	Endpoint            string   `json:"endpoint"`
	ServerPublicKey     string   `json:"serverPublicKey"`
	AddressCidr         string   `json:"addressCidr"`
	DNS                 []string `json:"dns"`
	AllowedIPs          []string `json:"allowedIPs"`
	PersistentKeepalive int      `json:"persistentKeepalive"`
}

type Policy struct {
	VpnEnabled    bool     `json:"vpnEnabled"`
	BypassDomains []string `json:"bypassDomains"`
}

var (
	confPath string
	version  = "device-agent-2.1"
	privPath = "/etc/wireguard/private.key"
	pubPath  = "/etc/wireguard/public.key"
)

func main() {
	flag.StringVar(&confPath, "config", "/etc/mgmt-agent/config.json", "path to config")
	flag.Parse()

	cfg, err := loadConfig(confPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := ensureKeyPair(); err != nil {
		log.Fatalf("keys: %v", err)
	}
	// Базовая PBR/kill-switch и nft (можно выполнять смело много раз)
	_ = run("/usr/local/bin/ensure-pbr.sh")

	for {
		if err := runOnce(cfg); err != nil {
			log.Printf("WSS error: %v", err)
		}
		time.Sleep(5 * time.Second)
	}
}

func runOnce(cfg *Config) error {
	u, err := url.Parse(cfg.ServerURL)
	if err != nil {
		return err
	}
	// Маршрут до mgmt-хоста вне VPN (policy rule: to <mgmt_ip> -> main)
	if err := ensureMgmtRoute(u.Hostname(), cfg.WanIf); err != nil {
		log.Printf("ensureMgmtRoute: %v", err)
	}

	q := u.Query()
	q.Set("device_id", cfg.DeviceID)
	q.Set("token", cfg.Token)
	u.RawQuery = q.Encode()

	dialer := websocket.Dialer{
		HandshakeTimeout:  15 * time.Second,
		EnableCompression: true,
	}
	if u.Scheme == "wss" {
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
	}

	log.Printf("connecting to %s", u.Redacted())
	c, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}
	defer c.Close()

	hello := map[string]any{
		"type":     "hello",
		"deviceId": cfg.DeviceID,
		"version":  version,
		"pubKey":   readStr(pubPath),
	}
	if err := c.WriteJSON(hello); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go periodicGetProfile(ctx, c)

	c.SetReadLimit(1 << 20)
	c.SetReadDeadline(time.Now().Add(120 * time.Second))
	c.SetPongHandler(func(string) error {
		c.SetReadDeadline(time.Now().Add(120 * time.Second))
		return nil
	})

	for {
		_, data, err := c.ReadMessage()
		if err != nil {
			return err
		}
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			log.Printf("bad json: %v", err)
			continue
		}
		if msg.Type != "action" {
			continue
		}
		switch msg.Action {
		case "profile":
			var p Profile
			if err := json.Unmarshal(msg.Data, &p); err != nil {
				log.Printf("profile payload err: %v", err)
				continue
			}
			if err := applyProfile(cfg.WgConfPath, p); err != nil {
				log.Printf("apply profile: %v", err)
				continue
			}
			if err := restartWGAndRoutes(cfg.LanIf); err != nil {
				log.Printf("wg restart: %v", err)
				continue
			}
			log.Printf("profile applied: %s %s", p.Endpoint, p.AddressCidr)

		case "policy":
			var pol Policy
			if err := json.Unmarshal(msg.Data, &pol); err != nil {
				log.Printf("policy payload err: %v", err)
				continue
			}
			if err := applyPolicy(pol); err != nil {
				log.Printf("policy apply err: %v", err)
				continue
			}
			log.Printf("policy applied: vpn=%v bypass=%d", pol.VpnEnabled, len(pol.BypassDomains))
		default:
			// noop
		}
	}
}

func periodicGetProfile(ctx context.Context, c *websocket.Conn) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = c.WriteJSON(map[string]any{"type": "action", "action": "get_profile"})
		}
	}
}

func applyProfile(path string, p Profile) error {
	priv := readStr(privPath)
	wgConf := buildWGConf(priv, p)
	old := readFile(path)
	if hash(old) == hash(wgConf) {
		return nil
	}
	_ = os.MkdirAll("/etc/wireguard", 0o700)
	if _, err := os.Stat(path); err == nil {
		_ = copyFile(path, path+".bak")
	}
	return os.WriteFile(path, []byte(wgConf), 0o600)
}

func buildWGConf(priv string, p Profile) string {
	return fmt.Sprintf(`[Interface]
Address = %s
PrivateKey = %s
DNS = %s
Table = off

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = %d
`,
		p.AddressCidr, strings.TrimSpace(priv), strings.Join(p.DNS, ","),
		strings.TrimSpace(p.ServerPublicKey), p.Endpoint,
		strings.Join(p.AllowedIPs, ", "), p.PersistentKeepalive)
}

func applyPolicy(p Policy) error {
	// Включение/выключение VPN
	if !p.VpnEnabled {
		_ = run("wg-quick down wg0")
	} else {
		_ = run("wg-quick up wg0")
	}
	// Обновить bypass список
	_ = os.MkdirAll("/etc/mgmt-agent", 0o755)
	if err := os.WriteFile("/etc/mgmt-agent/bypass.txt", []byte(strings.Join(p.BypassDomains, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	_ = run("/usr/local/bin/update-bypass.sh")
	return nil
}

func restartWGAndRoutes(lanIf string) error {
	_ = run("wg-quick down wg0")
	if out, err := exec.Command("bash", "-lc", "wg-quick up wg0").CombinedOutput(); err != nil {
		return fmt.Errorf("wg-quick up: %v (%s)", err, string(out))
	}
	// Таблица 100 — default через wg0; весь трафик с LAN в table 100
	_ = exec.Command("ip", "route", "replace", "default", "dev", "wg0", "table", "100").Run()
	_ = exec.Command("ip", "-6", "route", "replace", "default", "dev", "wg0", "table", "100").Run()
	_ = exec.Command("ip", "rule", "add", "iif", lanIf, "lookup", "100", "priority", "10000").Run()
	_ = exec.Command("ip", "-6", "rule", "add", "iif", lanIf, "lookup", "100", "priority", "10000").Run()
	return nil
}

func ensureKeyPair() error {
	if _, err := os.Stat(privPath); err == nil {
		if _, err := os.Stat(pubPath); err == nil {
			return nil
		}
	}
	if err := os.MkdirAll("/etc/wireguard", 0o700); err != nil {
		return err
	}
	cmd := exec.Command("bash", "-lc", "umask 077; wg genkey | tee "+privPath+" | wg pubkey > "+pubPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg genkey: %v (%s)", err, string(out))
	}
	return nil
}

func ensureMgmtRoute(host, wanIf string) error {
	if net.ParseIP(host) == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return fmt.Errorf("resolve mgmt host: %v", err)
		}
		host = ips[0].String()
	}
	// Правило: весь трафик к mgmt IP идёт по main (WAN), вне table 100
	_ = exec.Command("ip", "rule", "add", "to", host, "lookup", "main", "priority", "50").Run()
	// Маршрут по умолчанию в main уже ведёт через WAN; дополнительно можно закрепить dev:
	if wanIf != "" {
		// ничего не делаем, если нет необходимости; основной default и так на WAN
	}
	return nil
}

func run(cmd string) error {
	c := exec.Command("bash", "-lc", cmd)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v (%s)", cmd, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// utils
func loadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil { return nil, err }
	defer f.Close()
	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil { return nil, err }
	return &cfg, nil
}
func readFile(path string) string {
	f, err := os.Open(path)
	if err != nil { return "" }
	defer f.Close()
	b, _ := io.ReadAll(bufio.NewReader(f))
	return string(b)
}
func readStr(path string) string {
	b, err := os.ReadFile(path)
	if err != nil { return "" }
	return strings.TrimSpace(string(b))
}
func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil { return err }
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil { return err }
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil { return err }
	return out.Close()
}