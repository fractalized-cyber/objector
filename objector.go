package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

func init() {
	// Redirect all logging to /dev/null
	log.SetOutput(ioutil.Discard)
}

// Pattern represents a pattern configuration
type Pattern struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
}

// Config represents the configuration file structure
type Config struct {
	Patterns     []Pattern `json:"patterns"`
	IgnoredPaths []string  `json:"ignoredPaths"`
	MaxDepth     int       `json:"maxDepth"`
}

// Match represents a detected pattern match
type Match struct {
	Pattern     string    `json:"pattern"`
	Path        string    `json:"path"`
	Value       string    `json:"value"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

// ObjectMonitor represents the monitoring functionality
type ObjectMonitor struct {
	patterns     map[string]struct{ pattern, description string }
	ignoredPaths map[string]bool
	maxDepth     int
	foundMatches map[string]bool
	debug        bool
	stats        struct {
		objectsScanned int
		matchesFound   int
	}
}

// NewObjectMonitor creates a new ObjectMonitor instance
func NewObjectMonitor() *ObjectMonitor {
	// Initialize with hardcoded patterns
	patterns := make(map[string]struct{ pattern, description string })

	// Add default patterns
	patterns["AWS Access Key"] = struct{ pattern, description string }{
		pattern:     `\b(AKIA|ASIA)[A-Z0-9]{16}\b`,
		description: "AWS Access Key ID",
	}
	patterns["AWS Secret Key"] = struct{ pattern, description string }{
		pattern:     `\b[0-9a-zA-Z/+]{40}\b`,
		description: "AWS Secret Access Key",
	}
	patterns["Private Key"] = struct{ pattern, description string }{
		pattern:     `-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`,
		description: "Private Key File",
	}
	patterns["API Key"] = struct{ pattern, description string }{
		pattern:     `\b[a-zA-Z0-9]{32,}\b`,
		description: "Generic API Key",
	}
	patterns["JWT Token"] = struct{ pattern, description string }{
		pattern:     `\bey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b`,
		description: "JWT Token",
	}

	// Default ignored paths
	ignoredPaths := map[string]bool{
		"performance":       true,
		"localStorage":      true,
		"sessionStorage":    true,
		"indexedDB":         true,
		"webkitStorageInfo": true,
		"chrome":            true,
		"document":          true,
		"history":           true,
	}

	return &ObjectMonitor{
		patterns:     patterns,
		ignoredPaths: ignoredPaths,
		maxDepth:     10,
		foundMatches: make(map[string]bool),
		debug:        false,
	}
}

// AddPattern adds a new pattern to monitor
func (m *ObjectMonitor) AddPattern(name, pattern, description string) {
	m.patterns[name] = struct{ pattern, description string }{
		pattern:     pattern,
		description: description,
	}
}

// LogMatch handles a detected match
func (m *ObjectMonitor) LogMatch(match Match) {
	// Print match in a clean format
	fmt.Printf("\033[31m[ObjectMonitor Match]\033[0m\n")
	fmt.Printf("Timestamp:   %s\n", match.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("Pattern:     %s\n", match.Pattern)
	fmt.Printf("Path:        %s\n", match.Path)
	fmt.Printf("Value:       %s\n", match.Value)
	fmt.Printf("Description: %s\n\n", match.Description)
}

// GetMonitoringScript returns the JavaScript code for monitoring
func (m *ObjectMonitor) GetMonitoringScript() string {
	return `
		class ObjectMonitor {
			constructor(options = {}) {
				this.patterns = new Map();
				this.ignoredPaths = new Set(options.ignoredPaths || [
					'performance', 'localStorage', 'sessionStorage', 'indexedDB',
					'webkitStorageInfo', 'chrome', 'document', 'history'
				]);
				this.maxDepth = options.maxDepth || 10;
				this.foundMatches = new Set();
				this.debug = false;
				this.scanInterval = null;
				this.stats = {
					objectsScanned: 0,
					matchesFound: 0
				};
			}

			addPattern(name, pattern, description = '') {
				if (!(pattern instanceof RegExp)) {
					pattern = new RegExp(pattern);
				}
				this.patterns.set(name, { pattern, description });
				return this;
			}

			checkValue(value, path) {
				if (typeof value !== 'string') return;
				
				for (const [name, { pattern, description }] of this.patterns) {
					const matches = value.match(pattern);
					if (matches) {
						const match = {
							pattern: name,
							path,
							value,
							matches,
							description,
							timestamp: new Date().toISOString()
						};
						
						const matchKey = path + ':' + value;
						if (!this.foundMatches.has(matchKey)) {
							this.foundMatches.add(matchKey);
							this.logMatch(match);
						}
					}
				}
			}

			logMatch(match) {
				const output = {
					timestamp: match.timestamp,
					pattern: match.pattern,
					path: match.path,
					value: match.value,
					description: match.description
				};

				console.log('%c[ObjectMonitor Match]', 'color: #ff0000; font-weight: bold');
				console.table([output]);
				
				const event = new CustomEvent('objectMonitorMatch', { detail: match });
				window.dispatchEvent(event);
			}

			start() {
				if (!window.__objectMonitorActive) {
					try {
						this.scanObject(window, 'window');
						window.__objectMonitorActive = true;

						const originalString = String;
						window.String = function(value) {
							const str = originalString(value);
							monitor.checkValue(str, 'String constructor');
							return str;
						};
						window.String.prototype = originalString.prototype;

						const originalDefineProperty = Object.defineProperty;
						Object.defineProperty = function(obj, prop, descriptor) {
							if (descriptor && descriptor.value) {
								if (typeof descriptor.value === 'string') {
									monitor.checkValue(descriptor.value, obj.constructor ? obj.constructor.name + '.' + prop : 'Object.' + prop);
								}
							}
							return originalDefineProperty.call(this, obj, prop, descriptor);
						};

						const originalDefineProperties = Object.defineProperties;
						Object.defineProperties = function(obj, props) {
							for (const [prop, descriptor] of Object.entries(props)) {
								if (descriptor && descriptor.value) {
									if (typeof descriptor.value === 'string') {
										monitor.checkValue(descriptor.value, obj.constructor ? obj.constructor.name + '.' + prop : 'Object.' + prop);
									}
								}
							}
							return originalDefineProperties.call(this, obj, props);
						};

						const originalCreate = Object.create;
						Object.create = function(proto, properties) {
							const obj = originalCreate.call(this, proto, properties);
							if (properties) {
								for (const [prop, descriptor] of Object.entries(properties)) {
									if (descriptor && descriptor.value) {
										if (typeof descriptor.value === 'string') {
											monitor.checkValue(descriptor.value, 'Object.create.' + prop);
										}
									}
								}
							}
							return obj;
						};

						const originalAssign = Object.assign;
						Object.assign = function(target, ...sources) {
							const result = originalAssign.call(this, target, ...sources);
							for (const source of sources) {
								for (const [prop, value] of Object.entries(source)) {
									if (typeof value === 'string') {
										monitor.checkValue(value, 'Object.assign.' + prop);
									}
								}
							}
							return result;
						};

						const originalSet = Reflect.set;
						Reflect.set = function(target, prop, value) {
							if (typeof value === 'string') {
								monitor.checkValue(value, target.constructor ? target.constructor.name + '.' + prop : 'Object.' + prop);
							}
							return originalSet.call(this, target, prop, value);
						};

						this.scanInterval = setInterval(() => {
							this.scanObject(window, 'window');
						}, 1000);

						const windowHandler = {
							get: (target, prop) => {
								const value = target[prop];
								if (typeof value === 'string') {
									monitor.checkValue(value, 'window.' + String(prop));
								}
								return value;
							},
							set: (target, prop, value) => {
								if (typeof value === 'string') {
									monitor.checkValue(value, 'window.' + String(prop));
								}
								return Reflect.set(target, prop, value);
							}
						};

						const windowProxy = new Proxy(window, windowHandler);
						try {
							Object.defineProperty(window, '__proto__', {
								get: () => windowProxy.__proto__,
								set: (value) => {
									windowProxy.__proto__ = value;
									return true;
								},
								configurable: true
							});
						} catch (e) {
							console.warn('[ObjectMonitor] Could not proxy window.__proto__, continuing with limited monitoring');
						}

						const globalHandler = {
							set: (target, prop, value) => {
								if (typeof value === 'string') {
									monitor.checkValue(value, 'global.' + String(prop));
								}
								return Reflect.set(target, prop, value);
							}
						};

						const globalObject = Function('return this')();
						const globalProxy = new Proxy(globalObject, globalHandler);
						try {
							Object.defineProperty(globalObject, '__proto__', {
								get: () => globalProxy.__proto__,
								set: (value) => {
									globalProxy.__proto__ = value;
									return true;
								},
								configurable: true
							});
						} catch (e) {
							console.warn('[ObjectMonitor] Could not proxy global.__proto__, continuing with limited monitoring');
						}
						
						console.log('%c[ObjectMonitor] Started monitoring all objects', 'color: #00ff00');
					} catch (e) {
						console.error('[ObjectMonitor] Failed to start:', e);
					}
				}
			}

			scanObject(obj, path = 'window', depth = 0, visited = new Set()) {
				if (depth > this.maxDepth) return;
				if (!obj || typeof obj !== 'object') return;
				if (visited.has(obj)) return;
				if (this.ignoredPaths.has(path)) return;

				visited.add(obj);
				this.stats.objectsScanned++;

				try {
					for (const prop in obj) {
						try {
							const value = obj[prop];
							const newPath = path + '.' + prop;
							
							if (typeof value === 'string') {
								this.checkValue(value, newPath);
							} else if (value && typeof value === 'object') {
								this.scanObject(value, newPath, depth + 1, visited);
							}
						} catch (e) {}
					}
				} catch (e) {}
			}

			getStats() {
				return this.stats;
			}
		}

		const monitor = new ObjectMonitor({
			debug: false,
			maxDepth: 5
		});

		// Add patterns to monitor
		monitor.addPattern(
			'AWS Access Key',
			/\\b(AKIA|ASIA)[A-Z0-9]{16}\\b/,
			'AWS Access Key ID'
		).addPattern(
			'AWS Secret Key',
			/\\b[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/,
			'AWS Secret Access Key'
		).addPattern(
			'Private Key',
			/-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----/,
			'Private Key Header'
		).addPattern(
			'API Key',
			/(?:api[_-]?key|api[_-]?secret|client[_-]?secret)['\\"]?\\s*[:=]\\s*['"]([a-zA-Z0-9_\\-]{32,})['"]/i,
			'API Key Assignment'
		).addPattern(
			'JWT Token',
			/eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$/,
			'JWT Token'
		);

		// Start monitoring
		monitor.start();
	`
}

func wrapText(text string, width int) []string {
	if len(text) <= width {
		return []string{text}
	}

	var lines []string
	// Split by newlines first
	paragraphs := strings.Split(text, "\n")

	for _, paragraph := range paragraphs {
		// Then wrap each paragraph
		for len(paragraph) > 0 {
			if len(paragraph) <= width {
				lines = append(lines, paragraph)
				break
			}
			// Try to break at a space if possible
			breakPoint := width
			if breakPoint < len(paragraph) {
				// Look for the last space before the break point
				for i := breakPoint; i > 0; i-- {
					if paragraph[i-1] == ' ' {
						breakPoint = i
						break
					}
				}
			}
			lines = append(lines, paragraph[:breakPoint])
			paragraph = strings.TrimSpace(paragraph[breakPoint:])
		}
	}
	return lines
}

func printTableRow(w *os.File, pattern, path, value, description string) {
	// Define column widths
	const (
		patternWidth = 15
		pathWidth    = 30
		valueWidth   = 40
		descWidth    = 30
	)

	// Wrap each field
	patternLines := wrapText(pattern, patternWidth)
	pathLines := wrapText(path, pathWidth)
	valueLines := wrapText(value, valueWidth)
	descLines := wrapText(description, descWidth)

	// Find the maximum number of lines needed
	maxLines := len(patternLines)
	if len(pathLines) > maxLines {
		maxLines = len(pathLines)
	}
	if len(valueLines) > maxLines {
		maxLines = len(valueLines)
	}
	if len(descLines) > maxLines {
		maxLines = len(descLines)
	}

	// Print each line
	for i := 0; i < maxLines; i++ {
		pattern := ""
		if i < len(patternLines) {
			pattern = patternLines[i]
		}
		path := ""
		if i < len(pathLines) {
			path = pathLines[i]
		}
		value := ""
		if i < len(valueLines) {
			value = valueLines[i]
		}
		desc := ""
		if i < len(descLines) {
			desc = descLines[i]
		}

		// Print the row with proper padding and red pattern
		fmt.Fprintf(w, "│ \033[31m%-*s\033[0m │ %-*s │ %-*s │ %-*s │\n",
			patternWidth, pattern,
			pathWidth, path,
			valueWidth, value,
			descWidth, desc)
	}

	// Print bottom border for the last row
	if maxLines > 0 {
		fmt.Println("└" + strings.Repeat("─", patternWidth+2) + "┴" +
			strings.Repeat("─", pathWidth+2) + "┴" +
			strings.Repeat("─", valueWidth+2) + "┴" +
			strings.Repeat("─", descWidth+2) + "┘")
	}
}

func printUsage() {
	fmt.Println(`
OBJECTOR - JavaScript Object Monitor

  A powerful tool for monitoring JavaScript objects and detecting exposed
  credentials, API keys, and sensitive data in web applications.

  USAGE:
    objector -u <URL> [OPTIONS]

  REQUIRED ARGUMENTS:
    -u, --url <URL>              Target URL to monitor

  OPTIONAL ARGUMENTS:
    --timeout <duration>         Monitoring timeout (default: 20s)
    --headers <headers>          Custom headers for requests
    --string <custom_string>     Custom string to search for
    --help, -h                   Show this help message

  EXAMPLES:
    objector -u [url]
    objector -u [url] --timeout 30s
    objector -u [url] --headers "Authorization: Bearer token"
    objector -u [url] --string "my-secret-key"

  DETECTED PATTERNS:
    • AWS Access Keys (AKIA/ASIA format)
    • AWS Secret Keys (40-character base64)
    • Private Keys (RSA, DSA, EC, OpenSSH)
    • JWT Tokens (eyJ format)
    • Generic API Keys (32+ characters)
`)
}

func main() {
	// Parse command line flags
	url := flag.String("u", "", "URL to monitor (required)")
	urlLong := flag.String("url", "", "URL to monitor (required)")
	timeout := flag.Duration("timeout", 20*time.Second, "Monitoring timeout")
	headers := flag.String("headers", "", "Headers to include in requests (format: 'HEADER: VALUE,HEADER2: VALUE2')")
	customString := flag.String("string", "", "Custom string to search for (if provided, ignores default patterns)")
	help := flag.Bool("help", false, "Show help message")
	helpShort := flag.Bool("h", false, "Show help message")

	// Custom usage function
	flag.Usage = printUsage

	flag.Parse()

	// Check if help is requested
	if *help || *helpShort {
		printUsage()
		os.Exit(0)
	}

	// Check if no arguments provided
	if len(os.Args) == 1 {
		printUsage()
		os.Exit(1)
	}

	// Use either -u or --url
	targetURL := *url
	if targetURL == "" {
		targetURL = *urlLong
	}

	if targetURL == "" {
		fmt.Println("\033[31mError: URL is required. Use -u or --url to specify the target URL.\033[0m")
		fmt.Println("Run 'objector --help' for usage information.")
		os.Exit(1)
	}

	// Animation frames for the spinner
	spinnerFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinnerIndex := 0

	// Function to print the spinner
	printSpinner := func() {
		fmt.Printf("\r\033[K%s Scanning for secrets...", spinnerFrames[spinnerIndex])
		spinnerIndex = (spinnerIndex + 1) % len(spinnerFrames)
	}

	// Clear the spinner line
	clearSpinner := func() {
		fmt.Print("\r\033[K")
	}

	// Parse headers
	headerMap := make(map[string]string)
	if *headers != "" {
		headerPairs := strings.Split(*headers, ",")
		for _, pair := range headerPairs {
			parts := strings.SplitN(strings.TrimSpace(pair), ":", 2)
			if len(parts) == 2 {
				headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Create a new context with options to suppress errors
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("log-level", "3"), // Suppress all logging
		chromedp.Flag("silent", true),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	// Create a new context
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Set timeout
	ctx, cancel = context.WithTimeout(ctx, *timeout)
	defer cancel()

	// Create monitor
	monitor := NewObjectMonitor()

	// Track printed secrets
	seenSecrets := make(map[string]bool)

	// Define column widths
	const (
		patternWidth = 15
		pathWidth    = 30
		valueWidth   = 40
		descWidth    = 30
	)

	// Print top border
	fmt.Println("┌" + strings.Repeat("─", patternWidth+2) + "┬" +
		strings.Repeat("─", pathWidth+2) + "┬" +
		strings.Repeat("─", valueWidth+2) + "┬" +
		strings.Repeat("─", descWidth+2) + "┐")

	// Print header
	fmt.Printf("│ \033[1m%-*s\033[0m │ %-*s │ %-*s │ %-*s │\n",
		patternWidth, "Pattern",
		pathWidth, "Path",
		valueWidth, "Value",
		descWidth, "Description")

	// Print header separator
	fmt.Println("├" + strings.Repeat("─", patternWidth+2) + "┼" +
		strings.Repeat("─", pathWidth+2) + "┼" +
		strings.Repeat("─", valueWidth+2) + "┼" +
		strings.Repeat("─", descWidth+2) + "┤")

	// Run the browser
	err := chromedp.Run(ctx,
		// Set headers for all requests
		chromedp.ActionFunc(func(ctx context.Context) error {
			headers := make(map[string]interface{})
			for k, v := range headerMap {
				headers[k] = v
			}
			return network.SetExtraHTTPHeaders(network.Headers(headers)).Do(ctx)
		}),

		// Navigate to the target page
		chromedp.Navigate(targetURL),

		// Wait for the page to be fully loaded
		chromedp.WaitReady("body", chromedp.ByQuery),

		// Inject our monitoring script
		chromedp.Evaluate(monitor.GetMonitoringScript(), nil),

		// Set custom search string if provided
		chromedp.ActionFunc(func(ctx context.Context) error {
			if *customString != "" {
				return chromedp.Evaluate(fmt.Sprintf(`window.__customSearchString = "%s";`, *customString), nil).Do(ctx)
			}
			return nil
		}),

		// Check for credentials multiple times
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Now do our credential scan
			var result string
			var finalStats struct {
				ObjectsScanned int `json:"objectsScanned"`
				MatchesFound   int `json:"matchesFound"`
			}

			err := chromedp.Evaluate(`
				(function() {
					try {
						let matches = [];
						let visited = new Set();
						let stats = {
							objectsScanned: 0,
							matchesFound: 0
						};
						
						function checkValue(value, path) {
							if (typeof value !== 'string') return;
							
							// Check for custom string if provided
							if (window.__customSearchString && value.includes(window.__customSearchString)) {
								stats.matchesFound++;
								matches.push({
									pattern: 'Custom String',
									path: path,
									value: value,
									description: 'Custom String Match'
								});
								return;
							}
							
							// Only check default patterns if no custom string is provided
							if (!window.__customSearchString) {
								// Check for AWS Access Key
								if (value.match(/AKIA[A-Z0-9]{16}/)) {
									stats.matchesFound++;
									matches.push({
										pattern: 'AWS Access Key',
										path: path,
										value: value,
										description: 'AWS Access Key ID'
									});
									return;
								}
								
								// Check for AWS Secret Key
								if (value.match(/secret[a-zA-Z0-9]{40}/)) {
									stats.matchesFound++;
									matches.push({
										pattern: 'AWS Secret Key',
										path: path,
										value: value,
										description: 'AWS Secret Access Key'
									});
									return;
								}
								
								// Check for Private Key
								if (value.match(/-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----/)) {
									stats.matchesFound++;
									matches.push({
										pattern: 'Private Key',
										path: path,
										value: value,
										description: 'Private Key Header'
									});
									return;
								}
								
								// Check for JWT Token
								if (value.match(/eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/)) {
									stats.matchesFound++;
									matches.push({
										pattern: 'JWT Token',
										path: path,
										value: value,
										description: 'JWT Token'
									});
									return;
								}
							}
						}
						
						function scanObject(obj, path = '', depth = 0) {
							if (depth > 5) return;
							if (!obj || typeof obj !== 'object') return;
							if (visited.has(obj)) return;
							
							const ignoredPaths = ['performance', 'localStorage', 'sessionStorage', 'indexedDB', 'webkitStorageInfo', 'chrome', 'document', 'history'];
							if (ignoredPaths.includes(path.split('.').pop())) return;
							
							visited.add(obj);
							stats.objectsScanned++;
							
							try {
								for (const prop in obj) {
									try {
										const value = obj[prop];
										const newPath = path ? path + '.' + prop : prop;
										
										if (typeof value === 'string') {
											checkValue(value, newPath);
										} else if (value && typeof value === 'object') {
											scanObject(value, newPath, depth + 1);
										}
									} catch (e) {
										// Ignore property access errors
									}
								}
							} catch (e) {
								// Ignore object access errors
							}
						}
						
						// Get the global object
						const globalObject = Function('return this')();
						
						// Start scanning from global object
						scanObject(globalObject);
						
						return JSON.stringify({
							matches: matches,
							stats: stats
						});
					} catch (e) {
						return JSON.stringify({ error: e.message });
					}
				})()
			`, &result).Do(ctx)

			if err != nil {
				return nil
			}

			// Parse and format the matches
			var response struct {
				Matches []struct {
					Pattern     string `json:"pattern"`
					Path        string `json:"path"`
					Value       string `json:"value"`
					Description string `json:"description"`
				} `json:"matches"`
				Stats struct {
					ObjectsScanned int `json:"objectsScanned"`
					MatchesFound   int `json:"matchesFound"`
				} `json:"stats"`
			}

			if err := json.Unmarshal([]byte(result), &response); err != nil {
				return nil
			}

			// Print only new matches
			for _, match := range response.Matches {
				// Create a unique key for this secret
				secretKey := match.Path + ":" + match.Value
				if !seenSecrets[secretKey] {
					seenSecrets[secretKey] = true
					printTableRow(os.Stdout, match.Pattern, match.Path, match.Value, match.Description)
				}
			}

			// Add a continuous monitoring loop
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

			// Print initial spinner
			printSpinner()

			for {
				select {
				case <-ticker.C:
					// Update spinner
					printSpinner()

					// Re-run the scan
					err = chromedp.Evaluate(`
						(function() {
							try {
								let matches = [];
								let visited = new Set();
								let stats = {
									objectsScanned: 0,
									matchesFound: 0
								};
								
								function checkValue(value, path) {
									if (typeof value !== 'string') return;
									
									if (value.match(/AKIA[A-Z0-9]{16}/)) {
										stats.matchesFound++;
										matches.push({
											pattern: 'AWS Access Key',
											path: path,
											value: value,
											description: 'AWS Access Key ID'
										});
										return;
									}
									
									if (value.match(/secret[a-zA-Z0-9]{40}/)) {
										stats.matchesFound++;
										matches.push({
											pattern: 'AWS Secret Key',
											path: path,
											value: value,
											description: 'AWS Secret Access Key'
										});
										return;
									}
									
									if (value.match(/-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----/)) {
										stats.matchesFound++;
										matches.push({
											pattern: 'Private Key',
											path: path,
											value: value,
											description: 'Private Key Header'
										});
										return;
									}
									
									if (value.match(/eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/)) {
										stats.matchesFound++;
										matches.push({
											pattern: 'JWT Token',
											path: path,
											value: value,
											description: 'JWT Token'
										});
										return;
									}
								}
								
								function scanObject(obj, path = '', depth = 0) {
									if (depth > 5) return;
									if (!obj || typeof obj !== 'object') return;
									if (visited.has(obj)) return;
									
									const ignoredPaths = ['performance', 'localStorage', 'sessionStorage', 'indexedDB', 'webkitStorageInfo', 'chrome', 'document', 'history'];
									if (ignoredPaths.includes(path.split('.').pop())) return;
									
									visited.add(obj);
									stats.objectsScanned++;
									
									try {
										for (const prop in obj) {
											try {
												const value = obj[prop];
												const newPath = path ? path + '.' + prop : prop;
												
												if (typeof value === 'string') {
													checkValue(value, newPath);
												} else if (value && typeof value === 'object') {
													scanObject(value, newPath, depth + 1);
												}
											} catch (e) {
												// Ignore property access errors
											}
										}
									} catch (e) {
										// Ignore object access errors
									}
								}
								
								// Get the global object
								const globalObject = Function('return this')();
								
								// Start scanning from global object
								scanObject(globalObject);
								
								return JSON.stringify({
									matches: matches,
									stats: stats
								});
							} catch (e) {
								return JSON.stringify({ error: e.message });
							}
						})()
					`, &result).Do(ctx)

					if err != nil {
						continue
					}

					if err := json.Unmarshal([]byte(result), &response); err != nil {
						continue
					}

					// Print only new matches
					for _, match := range response.Matches {
						// Create a unique key for this secret
						secretKey := match.Path + ":" + match.Value
						if !seenSecrets[secretKey] {
							seenSecrets[secretKey] = true
							printTableRow(os.Stdout, match.Pattern, match.Path, match.Value, match.Description)
						}
					}

					// Update final stats
					finalStats = response.Stats

				case <-ctx.Done():
					// Clear the spinner before showing stats
					clearSpinner()

					// Print final stats before exiting
					fmt.Println("\n┌" + strings.Repeat("─", 50) + "┐")
					fmt.Println("│ \033[1mMonitoring Statistics\033[0m" + strings.Repeat(" ", 28) + "│")
					fmt.Println("├" + strings.Repeat("─", 50) + "┤")
					fmt.Printf("│ Total Objects Scanned: %-25d │\n", finalStats.ObjectsScanned)
					fmt.Printf("│ Total Matches Found:   %-25d │\n", finalStats.MatchesFound)
					fmt.Println("└" + strings.Repeat("─", 50) + "┘")
					return nil
				}
			}
		}),

		// Wait for the timeout
		chromedp.Sleep(*timeout),
	)

	if err != nil {
		log.Fatal(err)
	}
}
