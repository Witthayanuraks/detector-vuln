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

// Pola kerentanan
var vulnerabilityPatterns = map[string]*regexp.Regexp{
    "eval":               regexp.MustCompile(`\beval\((.*?)\)`),
    "setTimeout":         regexp.MustCompile(`setTimeout\(["'].*?["']\)`),
    "setInterval":        regexp.MustCompile(`setInterval\(["'].*?["']\)`),
    "newFunction":        regexp.MustCompile(`new Function\((.*?)\)`),
    "windowFunction":     regexp.MustCompile(`window\.Function\((.*?)\)`),
    "documentWrite":      regexp.MustCompile(`document\.write\((.*?)\)`),
    "innerHTML":          regexp.MustCompile(`\.innerHTML\s*=\s*["'].*?["']`),
    "evalLocation":       regexp.MustCompile(`eval\(location\.hash`),
}

// Jenis file yang akan diperiksa
var fileExtensions = []string{".js", ".php", ".py", ".java", ".go", ".html", ".css"}

// Hasil deteksi
type Detection struct {
    LineNumber int
    Original   string
    Fixed      string
    Pattern    string
}

// Variabel global untuk perbaikan otomatis
var autoFix = false

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
                fmt.Printf("[!] Potential %s vulnerability at line %d: %s\n", patternName, lineNumber, line)
                
                // Lakukan perbaikan dengan menambahkan komentar
                fixedLine = pattern.ReplaceAllString(line, "//[FIXED] "+line)
                
                detections = append(detections, Detection{
                    LineNumber: lineNumber,
                    Original:   originalLine,
                    Fixed:      fixedLine,
                    Pattern:    patternName,
                })
                break
            }
        }
        lineNumber++
    }

    return detections, scanner.Err()
}

func saveResults(path string, detections []Detection) error {
    if len(detections) == 0 {
        return nil
    }

    // Membuat direktori logs jika belum ada
    if _, err := os.Stat("logs"); os.IsNotExist(err) {
        os.Mkdir("logs", os.ModePerm)
    }

    fileName := filepath.Base(path)
    logFile := fmt.Sprintf("logs/%s_fixed.log", fileName)
    f, err := os.Create(logFile)
    if err != nil {
        return err
    }
    defer f.Close()

    // Tulis hasil before dan after
    for _, det := range detections {
        logEntry := fmt.Sprintf("Line %d:\n[BEFORE]: %s\n[AFTER]: %s\n[Pattern]: %s\n\n",
            det.LineNumber, det.Original, det.Fixed, det.Pattern)
        f.WriteString(logEntry)
    }

    fmt.Printf("[+] Log saved to %s\n", logFile)
    return nil
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

    fixedFile := strings.TrimSuffix(path, filepath.Ext(path)) + "_fixed" + filepath.Ext(path)
    output := strings.Join(lines, "\n")
    err = ioutil.WriteFile(fixedFile, []byte(output), 0644)
    if err != nil {
        return err
    }

    fmt.Printf("[+] Fixed file saved to %s\n", fixedFile)
    return nil
}

func processFile(path string) {
    fmt.Printf("[*] Scanning file: %s\n", path)
    detections, err := scanFile(path)
    if err != nil {
        fmt.Printf("[ERROR] Failed to scan file: %s\n", err)
        return
    }

    if len(detections) > 0 {
        fmt.Printf("[!] Found %d vulnerabilities in %s\n", len(detections), path)

        if autoFix {
            err = saveFixedFile(path, detections)
            if err != nil {
                fmt.Printf("[ERROR] Failed to save fixed file: %s\n", err)
            }
            err = saveResults(path, detections)
            if err != nil {
                fmt.Printf("[ERROR] Failed to save log: %s\n", err)
            }
        } else {
            fmt.Println("[*] No changes applied.")
        }
    } else {
        fmt.Println("[*] No vulnerabilities found.")
    }
}

func walkDir(root string) {
    err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }

        if !info.IsDir() {
            ext := filepath.Ext(path)
            for _, fileExt := range fileExtensions {
                if ext == fileExt {
                    processFile(path)
                    break
                }
            }
        }
        return nil
    })

    if err != nil {
        fmt.Printf("[ERROR] Error walking directory: %s\n", err)
    }
}

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Usage: go run Eval_vuln_detector3.4.go [directory_or_file]")
        return
    }

    target := os.Args[1]
    fileInfo, err := os.Stat(target)
    if err != nil {
        fmt.Printf("[ERROR] %s\n", err)
        return
    }

    // Tanya hanya sekali di awal
    fmt.Printf("[?] Do you want to automatically fix all vulnerabilities? (Y/N): ")
    var response string
    fmt.Scanln(&response)
    if strings.ToLower(response) == "y" {
        autoFix = true
        fmt.Println("[*] Auto-fix is enabled.")
    } else {
        fmt.Println("[*] Auto-fix is disabled.")
    }

    if fileInfo.IsDir() {
        walkDir(target)
    } else {
        processFile(target)
    }
}
