package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Pola kerentanan (tanpa backreference \1 yang menyebabkan error di Go)
var vulnerabilityPatterns = map[string]*regexp.Regexp{
	"eval":           regexp.MustCompile(`\beval\((.*?)\)`),
	"setTimeout":     regexp.MustCompile(`setTimeout\(["'][^"']*["']\s*,\s*\d+\)`),
	"setInterval":    regexp.MustCompile(`setInterval\(["'][^"']*["']\s*,\s*\d+\)`),
	"newFunction":    regexp.MustCompile(`new Function\((.*?)\)`),
	"windowFunction": regexp.MustCompile(`window\.Function\((.*?)\)`),
	"documentWrite":  regexp.MustCompile(`document\.write\((.*?)\)`),
	"innerHTML":      regexp.MustCompile(`\.innerHTML\s*=\s*["'].*?["']`),
	"evalLocation":   regexp.MustCompile(`eval\(location\.hash`),
}

// Jenis file yang didukung
var fileExtensions = []string{".js", ".php", ".py", ".java", ".go", ".html", ".css"}

type Detection struct {
	LineNumber int
	Original   string
	Fixed      string
	Pattern    string
	Severity   string
}

var autoFix = true

func detectSeverity(pattern string) string {
	switch pattern {
	case "eval", "evalLocation", "innerHTML":
		return "High"
	case "documentWrite", "setTimeout", "setInterval", "windowFunction":
		return "Medium"
	default:
		return "Low"
	}
}

func color(severity string) string {
	switch severity {
	case "High":
		return "\033[1;31m" // merah
	case "Medium":
		return "\033[1;33m" // kuning
	case "Low":
		return "\033[1;34m" // biru
	default:
		return "\033[0m"
	}
}

func resetColor() string {
	return "\033[0m"
}

func scanFile(path string) ([]Detection, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var detections []Detection
	scanner := bufio.NewScanner(file)
	lineNumber := 1

	for scanner.Scan() {
		line := scanner.Text()
		originalLine := line
		fixedLine := line

		for patternName, pattern := range vulnerabilityPatterns {
			if pattern.MatchString(line) {
				severity := detectSeverity(patternName)
				fmt.Printf("%s[!] %s vulnerability at line %d: %s%s\n", color(severity), patternName, lineNumber, line, resetColor())

				// Fix: Komentari line
				fixedLine = "//[FIXED] " + line

				detections = append(detections, Detection{
					LineNumber: lineNumber,
					Original:   originalLine,
					Fixed:      fixedLine,
					Pattern:    patternName,
					Severity:   severity,
				})
				break
			}
		}
		lineNumber++
	}

	return detections, scanner.Err()
}

func saveFixedFile(path string, detections []Detection) error {
	input, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(input), "\n")
	for _, det := range detections {
		lines[det.LineNumber-1] = det.Fixed
	}

	err = ioutil.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
	if err != nil {
		return err
	}

	fmt.Printf("\033[1;32m[✔] File successfully fixed: %s\033[0m\n", path)
	return nil
}

func saveLog(path string, detections []Detection) error {
	if len(detections) == 0 {
		return nil
	}

	logsDir := "logs"
	if _, err := os.Stat(logsDir); os.IsNotExist(err) {
		os.Mkdir(logsDir, os.ModePerm)
	}

	logFile := filepath.Join(logsDir, filepath.Base(path)+"_log.txt")
	logContent := ""

	for _, det := range detections {
		logContent += fmt.Sprintf("Line %d:\n[BEFORE]: %s\n[AFTER]: %s\n[Pattern]: %s\n[Severity]: %s\n\n",
			det.LineNumber, det.Original, det.Fixed, det.Pattern, det.Severity)
	}

	return ioutil.WriteFile(logFile, []byte(logContent), 0644)
}

func processFile(path string) {
	fmt.Printf("\n\033[1;34m[*] Scanning: %s\033[0m\n", path)
	detections, err := scanFile(path)
	if err != nil {
		fmt.Printf("[ERROR] Failed to scan: %s\n", err)
		return
	}

	if len(detections) == 0 {
		fmt.Println("\033[1;34m[✓] No vulnerabilities found\033[0m")
		return
	}

	if autoFix {
		saveFixedFile(path, detections)
	}
	saveLog(path, detections)
}

func walkDir(root string) {
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			for _, ext := range fileExtensions {
				if filepath.Ext(path) == ext {
					processFile(path)
				}
			}
		}
		return nil
	})
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run Eval_vuln_detector3.V_1.13.go [file_or_directory]")
		return
	}

	target := os.Args[1]
	info, err := os.Stat(target)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err)
		return
	}

	if info.IsDir() {
		walkDir(target)
	} else {
		processFile(target)
	}
}
