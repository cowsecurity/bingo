package internal

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// checkNPMRC checks a .npmrc file for sensitive content
func CheckNPMRC(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening .npmrc: %w", err)
	}
	defer file.Close()

	var violations []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Check for auth tokens
		if strings.Contains(line, "_auth=") {
			violations = append(violations, fmt.Sprintf("Found _auth token at line %d", lineNum))
		}
		if strings.Contains(line, "_authToken=") {
			violations = append(violations, fmt.Sprintf("Found _authToken at line %d", lineNum))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading .npmrc: %w", err)
	}

	return violations, nil
}
