package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BurntSushi/toml"
	"go.uber.org/ratelimit"
)

const (
	appName = "Leak-Scanner"

	colorReset = "\033[0m"

	// Обычные цвета
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"

	// Жирные (Bold)
	boldRed    = "\033[1;31m"
	boldGreen  = "\033[1;32m"
	boldYellow = "\033[1;33m"
	boldBlue   = "\033[1;34m"
	boldPurple = "\033[1;35m"
	boldCyan   = "\033[1;36m"
	boldWhite  = "\033[1;37m"

	// Дополнительные эффекты
	underline = "\033[4m"

	chromeAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	chromeLang   = "en-US,en;q=0.9"

	maxErrors = 3
)

type Rule struct {
	Path         string   `toml:"path"`
	ContentTypes []string `toml:"content_types"`
	MinSize      int64    `toml:"min_size"`
}

type Config struct {
	Rules []Rule `toml:"rule"`
}

type Task struct {
	URL          string
	BaseURL      string
	ContentTypes []string
	MinSize      int64
}

var (
	inputFile   string
	workers     int
	timeout     time.Duration
	readTimeout time.Duration
	insecure    bool
	configPath  string
	verbose     bool
	rps         int
	baseErrors  sync.Map
	seenUrls    sync.Map
	defaultConf = Config{
		Rules: []Rule{
			// Shell & Env (Home dir)
			// Zsh configuration
			{Path: "/.zshrc", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 100},
			// Zsh environment
			{Path: "/.zshenv", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 100},
			// Bash configuration
			{Path: "/.bashrc", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 100},
			// Common environment variables
			{Path: "/.env", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 100},
			{Path: "/prod.env", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 100},
			{Path: "/.env.prod", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 100},

			// PHP Frameworks & CMS Backups (.bak, .old, ~)
			// Laravel: Database config backup
			{Path: "/config/database.php.bak", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// Laravel: Old database config
			{Path: "/config/database.php.old", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// Editor swap file
			{Path: "/config/database.php~", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// Laravel: App config backup
			{Path: "/config/app.php.bak", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// Laravel: Old app config
			{Path: "/config/app.php.old", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// Editor swap file
			{Path: "/config/app.php~", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// Laravel: Cached config backup
			{Path: "/bootstrap/cache/config.php.bak", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 500},
			// Laravel: Old cached config
			{Path: "/bootstrap/cache/config.php.old", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 500},
			// Editor swap file
			{Path: "/bootstrap/cache/config.php~", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 500},
			// WordPress: Config backup
			{Path: "/wp-config.php.bak", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// WordPress: Old config
			{Path: "/wp-config.php.old", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// Editor swap file
			{Path: "/wp-config.php~", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// Yii2: Web config backup
			{Path: "/config/web.php.bak", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// Yii2: Old web config
			{Path: "/config/web.php.old", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// Editor swap file
			{Path: "/config/web.php~", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// Yii2: DB config backup
			{Path: "/config/db.php.bak", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// Yii2: Old DB config
			{Path: "/config/db.php.old", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// Editor swap file
			{Path: "/config/db.php~", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// Generic: Database backup
			{Path: "/database.php.bak", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// Generic: Old database backup
			{Path: "/database.php.old", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},
			// Editor swap file
			{Path: "/database.php~", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 200},

			// Cloud, AI & Infrastructure
			// AWS CLI credentials
			{Path: "/.aws/credentials", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 100},
			// Google Cloud CLI credentials
			{Path: "/.config/gcloud/credentials.db", ContentTypes: []string{}, MinSize: 512},

			// SSH Keys
			// SSH client configuration
			{Path: "/.ssh/config", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 100},

			// Database & Backups (SQL)
			// Domain-named SQL dump
			{Path: "/{{domainName}}.sql", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 128 * 1024},
			// Domain-named gzipped SQL dump
			{Path: "/{{domainName}}.sql.gz", ContentTypes: []string{"application/gzip"}, MinSize: 128 * 1024},
			// Base domain-named SQL dump
			{Path: "/{{baseDomainName}}.sql", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 128 * 1024},
			// Base domain-named gzipped SQL dump
			{Path: "/{{baseDomainName}}.sql.gz", ContentTypes: []string{"application/gzip"}, MinSize: 128 * 1024},
			// Generic SQL backup
			{Path: "/backup.sql", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 128 * 1024},
			// Generic gzipped SQL backup
			{Path: "/backup.sql.gz", ContentTypes: []string{"application/gzip"}, MinSize: 128 * 1024},
			// Generic SQL dump
			{Path: "/dump.sql", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 128 * 1024},
			// Generic gzipped SQL dump
			{Path: "/dump.sql.gz", ContentTypes: []string{"application/gzip"}, MinSize: 128 * 1024},
			// Generic database dump
			{Path: "/database.sql", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 128 * 1024},
			// Generic gzipped database dump
			{Path: "/database.sql.gz", ContentTypes: []string{"application/gzip"}, MinSize: 128 * 1024},
			// Short generic SQL dump
			{Path: "/db.sql", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 128 * 1024},
			// Short generic gzipped SQL dump
			{Path: "/db.sql.gz", ContentTypes: []string{"application/gzip"}, MinSize: 128 * 1024},

			// IDE & Tooling
			// VSCode SFTP plugin config
			{Path: "/.vscode/sftp.json", ContentTypes: []string{"text/plain", "application/json", "text/html"}, MinSize: 100},
			// VSCode workspace settings
			{Path: "/.vscode/settings.json", ContentTypes: []string{"text/plain", "application/json", "text/html"}, MinSize: 100},
			// JetBrains IDE workspace
			{Path: "/.idea/workspace.xml", ContentTypes: []string{"text/plain", "text/xml", "text/html"}, MinSize: 500},
			// Auto-login configuration
			{Path: "/.netrc", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 100},

			// History
			// Bash command history
			{Path: "/.bash_history", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 100},
			// Zsh command history
			{Path: "/.zsh_history", ContentTypes: []string{"text/plain", "text/html"}, MinSize: 100},

			// Site Archives (500KB+)
			{Path: "/{{domainName}}.zip", ContentTypes: []string{"application/zip"}, MinSize: 128 * 1024},
			{Path: "/{{domainName}}.rar", ContentTypes: []string{"application/vnd.rar", "application/x-rar-compressed"}, MinSize: 128 * 1024},
			{Path: "/{{domainName}}.tar.gz", ContentTypes: []string{"application/gzip"}, MinSize: 128 * 1024},

			{Path: "/{{baseDomainName}}.zip", ContentTypes: []string{"application/zip"}, MinSize: 128 * 1024},
			{Path: "/{{baseDomainName}}.rar", ContentTypes: []string{"application/vnd.rar"}, MinSize: 128 * 1024},
			{Path: "/{{baseDomainName}}.tar.gz", ContentTypes: []string{"application/gzip"}, MinSize: 128 * 1024},

			{Path: "/backup.zip", ContentTypes: []string{"application/zip"}, MinSize: 128 * 1024},
			{Path: "/backup.rar", ContentTypes: []string{"application/vnd.rar"}, MinSize: 128 * 1024},
			{Path: "/backup.tar.gz", ContentTypes: []string{"application/gzip"}, MinSize: 128 * 1024},

			{Path: "/archive.zip", ContentTypes: []string{"application/zip"}, MinSize: 128 * 1024},
			{Path: "/archive.rar", ContentTypes: []string{"application/vnd.rar"}, MinSize: 128 * 1024},
			{Path: "/archive.tar.gz", ContentTypes: []string{"application/gzip"}, MinSize: 128 * 1024},

			{Path: "/site.zip", ContentTypes: []string{"application/zip"}, MinSize: 128 * 1024},
			{Path: "/site.rar", ContentTypes: []string{"application/vnd.rar"}, MinSize: 128 * 1024},
			{Path: "/site.tar.gz", ContentTypes: []string{"application/gzip"}, MinSize: 128 * 1024},

			{Path: "/www.zip", ContentTypes: []string{"application/zip"}, MinSize: 128 * 1024},
			{Path: "/www.rar", ContentTypes: []string{"application/vnd.rar"}, MinSize: 128 * 1024},
			{Path: "/www.tar.gz", ContentTypes: []string{"application/gzip"}, MinSize: 128 * 1024},

			{Path: "/project.zip", ContentTypes: []string{"application/zip"}, MinSize: 128 * 1024},
			{Path: "/project.rar", ContentTypes: []string{"application/vnd.rar"}, MinSize: 128 * 1024},
			{Path: "/project.tar.gz", ContentTypes: []string{"application/gzip"}, MinSize: 128 * 1024},

			{Path: "/old.zip", ContentTypes: []string{"application/zip"}, MinSize: 128 * 1024},
			{Path: "/old.rar", ContentTypes: []string{"application/vnd.rar"}, MinSize: 128 * 1024},
			{Path: "/old.tar.gz", ContentTypes: []string{"application/gzip"}, MinSize: 128 * 1024},

			{Path: "/public_html.zip", ContentTypes: []string{"application/zip"}, MinSize: 128 * 1024},
			{Path: "/public_html.rar", ContentTypes: []string{"application/vnd.rar"}, MinSize: 128 * 1024},
			{Path: "/public_html.tar.gz", ContentTypes: []string{"application/gzip"}, MinSize: 128 * 1024},
		},
	}
)

func logDebug(format string, a ...any) {
	fmt.Fprintf(os.Stderr, colorBlue+"[D] "+format+colorReset+"\n", a...)
}

func logInfo(format string, a ...any) {
	fmt.Fprintf(os.Stderr, colorGreen+"[+] "+format+colorReset+"\n", a...)
}

func logWarn(format string, a ...any) {
	fmt.Fprintf(os.Stderr, colorRed+"[!] "+format+colorReset+"\n", a...)
}

func logError(format string, a ...any) {
	fmt.Fprintf(os.Stderr, boldRed+"[E] "+format+colorReset+"\n", a...)
}

func init() {
	flag.StringVar(&inputFile, "i", "", "File with URL list")
	flag.IntVar(&workers, "w", 20, "Number of workers")
	flag.DurationVar(&timeout, "t", 15*time.Second, "Dial timeout")
	flag.DurationVar(&readTimeout, "rt", 10*time.Second, "Total HTTP client timeout")
	flag.BoolVar(&insecure, "k", false, "Ignore SSL errors")
	flag.StringVar(&configPath, "c", "", "Path to TOML config")
	flag.BoolVar(&verbose, "v", false, "Verbose mode")
	flag.IntVar(&rps, "r", 0, "Requests per second")
}

func getBaseDomainName(host string) string {
	host = strings.ToLower(strings.TrimPrefix(host, "www."))
	parts := strings.Split(host, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return host
}

func setBrowserHeaders(req *http.Request, baseURL string) {
	v := rand.Intn(24) + 120
	version := fmt.Sprintf("%d", v)
	ua := fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36", version)

	if verbose {
		logDebug(ua)
	}

	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", chromeAccept)
	req.Header.Set("Accept-Language", chromeLang)
	req.Header.Set("Referer", baseURL+"/")
	req.Header.Set("Origin", baseURL)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Sec-Ch-Ua", fmt.Sprintf("\"Chromium\";v=\"%s\", \"Not(A:Brand\";v=\"24\", \"Google Chrome\";v=\"%s\"", version, version))
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", "\"Windows\"")
	// Пробуем обойти говно-фильтры, представившись локальным сервисом
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Real-IP", "127.0.0.1")
}

func main() {
	flag.Parse()

	logInfo("Starting %s", appName)
	config := loadConfig(configPath)
	urls := readURLs(inputFile)

	if len(urls) == 0 {
		logError("No URLs to process")
		os.Exit(1)
	}

	var rl ratelimit.Limiter
	if rps > 0 {
		rl = ratelimit.New(rps)
	} else {
		rl = ratelimit.NewUnlimited()
	}

	tasks := make(chan Task, workers*2)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Go(func() {

			transport := &http.Transport{
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecure},
				ResponseHeaderTimeout: timeout,
				DialContext: (&net.Dialer{
					Timeout: timeout,
				}).DialContext,
			}
			client := &http.Client{
				Timeout:   readTimeout,
				Transport: transport,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			for task := range tasks {
				if _, loaded := seenUrls.LoadOrStore(task.URL, true); loaded {
					if verbose {
						logWarn("Skip: already seen: %s", task.URL)
					}
					continue
				}

				val, _ := baseErrors.LoadOrStore(task.BaseURL, new(int32))
				errCount := val.(*int32)

				if atomic.LoadInt32(errCount) >= maxErrors {
					if verbose {
						logWarn("Skip checking URL: %s", task.URL)
					}
					continue
				}

				rl.Take()

				if checkURL(client, task, errCount) {
					if verbose {
						logInfo("Found %s", task.URL)
					}
					fmt.Println(task.URL)
				}
			}
		})
	}

	for _, rawURL := range urls {
		if !strings.HasPrefix(rawURL, "http") {
			rawURL = "http://" + rawURL
		}
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Host == "" {
			logWarn("Invalid URL skipped: %s", rawURL)
			continue
		}

		domainName := parsed.Host
		baseDomainName := getBaseDomainName(domainName)
		baseURL := fmt.Sprintf("%s://%s", parsed.Scheme, domainName)

		for _, rule := range config.Rules {
			path := rule.Path
			path = strings.ReplaceAll(path, "{{domainName}}", domainName)
			path = strings.ReplaceAll(path, "{{baseDomainName}}", baseDomainName)

			minSize := rule.MinSize
			if minSize <= 0 {
				minSize = 100
			}

			fullURL := strings.TrimSuffix(baseURL, "/") + path
			tasks <- Task{
				URL:          fullURL,
				BaseURL:      baseURL,
				ContentTypes: rule.ContentTypes,
				MinSize:      minSize,
			}
		}
	}

	close(tasks)
	wg.Wait()

	logInfo("%s finished!", appName)
}

func checkURL(client *http.Client, task Task, errCount *int32) bool {
	if verbose {
		logDebug("Check %s", task.URL)
	}

	req, _ := http.NewRequest("GET", task.URL, nil)
	setBrowserHeaders(req, task.BaseURL)

	resp, err := client.Do(req)
	if err != nil {
		if atomic.AddInt32(errCount, 1) == maxErrors {
			logWarn("Host %s ignored after %d errors", task.BaseURL, maxErrors)
		}
		return false
	}
	defer resp.Body.Close()

	if verbose {
		logDebug("%d %s %s", resp.StatusCode, resp.Request.Method, resp.Request.URL)
	}

	if resp.StatusCode == 200 {
		// Clean Content-Type (remove charset etc.)
		ct := strings.ToLower(resp.Header.Get("Content-Type"))

		if idx := strings.Index(ct, ";"); idx != -1 {
			ct = strings.TrimSpace(ct[:idx])
		}

		if verbose {
			logDebug("URL %s returns %s as Content-Type and %d as Content-Length", resp.Request.URL, ct, resp.ContentLength)
		}

		// Read first 1000 bytes to check for HTML (Soft 404 detection)
		buf := make([]byte, 1000)
		n, _ := io.ReadFull(resp.Body, buf)
		peek := ""
		if n > 0 {
			peek = strings.ToLower(string(buf[:n]))
		}

		if strings.Contains(peek, "<html") {
			if verbose {
				logWarn("Skip: resource looks like HTML: %s", task.URL)
			}
			return false
		}

		if task.MinSize > resp.ContentLength {
			if verbose {
				logWarn("Skip %s: size too small (%d < %d)", task.URL, resp.ContentLength, task.MinSize)
			}
			return false
		}

		contentTypes := append([]string(nil), task.ContentTypes...)
		contentTypes = append(contentTypes, "application/octet-stream", "application/x-binary")

		for _, expected := range contentTypes {
			expected = strings.ToLower(expected)
			if strings.Contains(ct, expected) {
				return true
			}
		}
	}

	return false
}

func readURLs(path string) []string {
	var scanner *bufio.Scanner
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			logError("File error: %v", err)
			os.Exit(1)
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	} else {
		scanner = bufio.NewScanner(os.Stdin)
	}

	var results []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			results = append(results, line)
		}
	}
	return results
}

func loadConfig(path string) Config {
	if path == "" {
		logInfo("Using default rules")
		return defaultConf
	}
	var conf Config
	if _, err := toml.DecodeFile(path, &conf); err != nil {
		logWarn("Config error: %v. Using defaults.", err)
		return defaultConf
	}
	logInfo("Loaded config from %s", path)
	return conf
}
