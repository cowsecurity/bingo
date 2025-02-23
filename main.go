package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	internal "github.com/cowsecurity/bingo/internal"
)

// Rule represents a single pattern rule from git-deny-patterns.json
type Rule struct {
	Part        string `json:"part"`
	Type        string `json:"type"`
	Pattern     string `json:"pattern"`
	Caption     string `json:"caption"`
	Description string `json:"description,omitempty"`
}

// FileChecker handles the file checking logic
type FileChecker struct {
	rules    []Rule
	patterns map[string]*regexp.Regexp
}

// NewFileChecker creates and initializes a new FileChecker
func NewFileChecker(rulesPath string) (*FileChecker, error) {
	data, err := os.ReadFile(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("error reading rules file: %w", err)
	}

	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("error parsing rules: %w", err)
	}

	fc := &FileChecker{
		rules:    rules,
		patterns: make(map[string]*regexp.Regexp),
	}

	// Compile all regex patterns
	for i, rule := range rules {
		if rule.Type == "regex" {
			// Convert Python-style regex to Go regex
			pattern := rule.Pattern
			pattern = regexp.QuoteMeta(pattern)
			pattern = strings.ReplaceAll(pattern, "\\\\A", "^")
			pattern = strings.ReplaceAll(pattern, "\\\\z", "$")
			pattern = strings.ReplaceAll(pattern, "\\\\.", ".")

			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regex pattern in rule %d: %w", i, err)
			}
			fc.patterns[rule.Pattern] = re
		}
	}

	return fc, nil
}

// Violation represents a rule violation found in a file
type Violation struct {
	FilePath    string
	RuleCaption string
	Description string
}

// CheckFile checks a single file against all rules
func (fc *FileChecker) CheckFile(path string) []Violation {
	var violations []Violation

	filename := filepath.Base(path)
	ext := filepath.Ext(path)
	if ext != "" {
		ext = ext[1:] // Remove leading dot
	}

	for _, rule := range fc.rules {
		var match bool

		switch rule.Part {
		case "filename":
			if rule.Type == "regex" {
				match = fc.patterns[rule.Pattern].MatchString(filename)
			} else { // match
				match = filename == rule.Pattern
			}

		case "extension":
			if rule.Type == "regex" {
				match = fc.patterns[rule.Pattern].MatchString(ext)
			} else { // match
				match = ext == rule.Pattern
			}

		case "path":
			if rule.Type == "regex" {
				match = fc.patterns[rule.Pattern].MatchString(path)
			} else { // match
				match = path == rule.Pattern
			}
		}

		if match {
			violations = append(violations, Violation{
				FilePath:    path,
				RuleCaption: rule.Caption,
				Description: rule.Description,
			})
		}
	}

	// Special check for .npmrc files
	if filename == ".npmrc" {
		if npmrcViolations, err := internal.CheckNPMRC(path); err == nil {
			for _, v := range npmrcViolations {
				violations = append(violations, Violation{
					FilePath:    path,
					RuleCaption: v,
				})
			}
		}
	}

	return violations
}

// CheckFiles checks multiple files concurrently
func (fc *FileChecker) CheckFiles(files []string) []Violation {
	var wg sync.WaitGroup
	violationsChan := make(chan []Violation, len(files))

	// Process files concurrently
	for _, file := range files {
		wg.Add(1)
		go func(f string) {
			defer wg.Done()
			violations := fc.CheckFile(f)
			if len(violations) > 0 {
				violationsChan <- violations
			}
		}(file)
	}

	// Wait for all goroutines to finish and close channel
	go func() {
		wg.Wait()
		close(violationsChan)
	}()

	// Collect all violations
	var allViolations []Violation
	for violations := range violationsChan {
		allViolations = append(allViolations, violations...)
	}

	return allViolations
}

func main() {
	checkAll := flag.Bool("all", false, "Check all tracked files instead of just staged ones")
	rulesPath := flag.String("rules", "git-deny-patterns.json", "Path to rules JSON file")
	flag.Parse()

	repoPath := "."
	if flag.NArg() > 0 {
		repoPath = flag.Arg(0)
	}

	checker, err := NewFileChecker(*rulesPath)
	if err != nil {
		log.Fatalf("Error initializing checker: %v", err)
	}

	var files []string
	if *checkAll {
		files, err = internal.GetAllTrackedFiles(repoPath)
	} else {
		files, err = internal.GetStagedFiles(repoPath)
	}
	if err != nil {
		log.Fatalf("Error getting files to check: %v", err)
	}

	for i, file := range files {
		files[i] = filepath.Join(repoPath, file)
	}

	violations := checker.CheckFiles(files)
	if len(violations) > 0 {
		fmt.Printf("Found %d sensitive file violations:\n\n", len(violations))
		for _, v := range violations {
			fmt.Printf("File: %s\nViolation: %s\n", v.FilePath, v.RuleCaption)
			if v.Description != "" {
				fmt.Printf("Description: %s\n", v.Description)
			}
			fmt.Println()
		}
		os.Exit(1)
	}
}
