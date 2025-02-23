package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// GetAllTrackedFiles returns all tracked files in the git repository
func GetAllTrackedFiles(repoPath string) ([]string, error) {
	cmd := exec.Command("git", "ls-files")
	cmd.Dir = repoPath
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("error running git ls-files in %s: %w", repoPath, err)
	}

	var files []string
	for _, file := range strings.Split(out.String(), "\n") {
		if file = strings.TrimSpace(file); file != "" {
			files = append(files, file)
		}
	}

	return files, nil
}

// GetStagedFiles returns all staged files in the git repository
func GetStagedFiles(repoPath string) ([]string, error) {
	cmd := exec.Command("git", "diff", "--cached", "--name-only", "--diff-filter=ACM")
	cmd.Dir = repoPath
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("error getting staged files in %s: %w", repoPath, err)
	}

	var files []string
	for _, file := range strings.Split(out.String(), "\n") {
		if file = strings.TrimSpace(file); file != "" {
			files = append(files, file)
		}
	}

	return files, nil
}
