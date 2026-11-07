// Command check runs every quality gate of this repository, in order, stopping at the first failure.
//
// Usage: go run ./scripts/check (the same command runs locally, in the factory and in CI).
//
// Gates: gofmt, go vet, tests with statement coverage >= 80 % of the library, documentation
// manifest, secrets (gitleaks) and known vulnerabilities (govulncheck).
// Standard library only, no shell: it behaves the same on Windows and Linux.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	minCoverage          = 80.0
	docsManifest         = "docs-manifest.json"
	allowMissingGitleaks = "FABRICA_ALLOW_MISSING_GITLEAKS"
	allowOfflineAudit    = "FABRICA_ALLOW_OFFLINE_AUDIT"
	govulncheckModule    = "golang.org/x/vuln/cmd/govulncheck@latest"
)

var gitleaksHint = "gitleaks is not installed. Install it (https://github.com/gitleaks/gitleaks#installing), " +
	"e.g. `winget install Gitleaks.Gitleaks`, `brew install gitleaks` or a release binary, " +
	"or set " + allowMissingGitleaks + "=1 to skip this gate locally."

type gate struct {
	name string
	run  func() error
}

func main() {
	if _, err := os.Stat("go.mod"); err != nil {
		fmt.Fprintln(os.Stderr, "check: run from the repository root (go.mod not found)")
		os.Exit(2)
	}
	gates := []gate{
		{"format", formatGate},
		{"vet", vetGate},
		{"tests", testsGate},
		{"docs", docsGate},
		{"secrets", secretsGate},
		{"vulnerabilities", vulnGate},
	}
	for _, g := range gates {
		fmt.Printf("==> %s\n", g.name)
		if err := g.run(); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", g.name, err)
			fmt.Fprintf(os.Stderr, "==> %s: FAILED\n", g.name)
			os.Exit(1)
		}
		fmt.Printf("==> %s: ok\n", g.name)
	}
	fmt.Println("==> all gates passed")
}

// run executes a tool from the repository root, streaming its output.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// output executes a tool and returns its trimmed standard output.
func output(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

func goEnv(key string) string {
	value, err := output("go", "env", key)
	if err != nil {
		return ""
	}
	return value
}

func formatGate() error {
	gofmt, err := exec.LookPath("gofmt")
	if err != nil {
		gofmt = filepath.Join(goEnv("GOROOT"), "bin", "gofmt")
	}
	files, err := output(gofmt, "-l", ".")
	if err != nil {
		return fmt.Errorf("gofmt failed: %w", err)
	}
	if files != "" {
		return fmt.Errorf("files are not gofmt-formatted (run `gofmt -w .`):\n%s", files)
	}
	fmt.Println("gofmt: every file is formatted")
	return nil
}

func vetGate() error {
	return run("go", "vet", "./...")
}

// libraryPackages lists every package of the module except the gate tooling under scripts/.
func libraryPackages() ([]string, error) {
	list, err := output("go", "list", "-f", "{{.ImportPath}} {{.Dir}}", "./...")
	if err != nil {
		return nil, fmt.Errorf("go list failed: %w", err)
	}
	scripts, err := filepath.Abs("scripts")
	if err != nil {
		return nil, err
	}
	var pkgs []string
	for _, line := range strings.Split(list, "\n") {
		importPath, dir, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		if rel, err := filepath.Rel(scripts, dir); err == nil && !strings.HasPrefix(rel, "..") {
			continue
		}
		pkgs = append(pkgs, importPath)
	}
	if len(pkgs) == 0 {
		return nil, errors.New("no library packages found")
	}
	return pkgs, nil
}

// raceUnavailable returns why the race detector cannot run here, or "" when it can.
func raceUnavailable() string {
	if goEnv("CGO_ENABLED") != "1" {
		return "cgo is disabled (the race detector needs cgo and a C compiler)"
	}
	cc := strings.Fields(goEnv("CC"))
	if len(cc) == 0 {
		cc = []string{"gcc"}
	}
	if _, err := exec.LookPath(cc[0]); err != nil {
		return fmt.Sprintf("C compiler %q not found on PATH (the race detector needs it)", cc[0])
	}
	return ""
}

func testsGate() error {
	pkgs, err := libraryPackages()
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "fabrica-cover-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	profile := filepath.Join(tmp, "cover.out")

	args := []string{"test", "-count=1", "-covermode=atomic", "-coverprofile=" + profile}
	if reason := raceUnavailable(); reason != "" {
		fmt.Printf("tests: running without -race: %s\n", reason)
	} else {
		args = append(args, "-race")
	}
	if err := run("go", append(args, pkgs...)...); err != nil {
		return fmt.Errorf("go test failed: %w", err)
	}
	report, err := output("go", "tool", "cover", "-func="+profile)
	if err != nil {
		return fmt.Errorf("go tool cover failed: %w", err)
	}
	fmt.Println(report)
	total, err := totalCoverage(report)
	if err != nil {
		return err
	}
	if total < minCoverage {
		return fmt.Errorf("total coverage %.1f%% is below %.0f%%", total, minCoverage)
	}
	fmt.Printf("tests: total coverage %.1f%% (minimum %.0f%%)\n", total, minCoverage)
	return nil
}

// totalCoverage extracts the percentage from the "total:" line of `go tool cover -func`.
func totalCoverage(report string) (float64, error) {
	for _, line := range strings.Split(report, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "total:" {
			return strconv.ParseFloat(strings.TrimSuffix(fields[len(fields)-1], "%"), 64)
		}
	}
	return 0, errors.New("no total line in coverage report")
}

type manifest struct {
	Required      []string          `json:"required"`
	RequiredGlobs []string          `json:"required_globs"`
	MaxLines      map[string]int    `json:"max_lines"`
	MustReference map[string]string `json:"must_reference"`
}

// docsErrors returns every violation of docs-manifest.json; an empty slice means the gate passes.
func docsErrors(root string) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(root, docsManifest))
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", docsManifest, err)
	}
	read := func(rel string) (string, bool) {
		path := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return "", false
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", false
		}
		return string(data), true
	}
	var errs []string
	for _, rel := range m.Required {
		text, ok := read(rel)
		switch {
		case !ok:
			errs = append(errs, "missing required file: "+rel)
		case strings.TrimSpace(text) == "":
			errs = append(errs, "required file is empty: "+rel)
		}
	}
	for _, pattern := range m.RequiredGlobs {
		matches, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
		if err != nil {
			return nil, fmt.Errorf("bad pattern %q: %w", pattern, err)
		}
		found := false
		for _, match := range matches {
			if info, err := os.Stat(match); err == nil && info.Mode().IsRegular() {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, "no file matches required pattern: "+pattern)
		}
	}
	for rel, limit := range m.MaxLines {
		if text, ok := read(rel); ok {
			if count := countLines(text); count > limit {
				errs = append(errs, fmt.Sprintf("%s has %d lines (max %d)", rel, count, limit))
			}
		}
	}
	for rel, needle := range m.MustReference {
		if text, ok := read(rel); ok && !strings.Contains(text, needle) {
			errs = append(errs, fmt.Sprintf("%s must reference %s", rel, needle))
		}
	}
	return errs, nil
}

func countLines(text string) int {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	if text == "" {
		return 0
	}
	return len(strings.Split(strings.TrimSuffix(text, "\n"), "\n"))
}

func docsGate() error {
	errs, err := docsErrors(".")
	if err != nil {
		return err
	}
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "docs: %s\n", e)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d documentation problem(s)", len(errs))
	}
	fmt.Println("docs: every file in docs-manifest.json is present")
	return nil
}

func secretsGate() error {
	exe, err := exec.LookPath("gitleaks")
	if err != nil {
		if os.Getenv(allowMissingGitleaks) == "1" {
			fmt.Println("gitleaks: SKIPPED (not installed)")
			return nil
		}
		return errors.New("FAIL - " + gitleaksHint)
	}
	return run(exe, "dir", ".", "--redact", "--verbose", "--no-banner")
}

func vulnGate() error {
	if exe, err := exec.LookPath("govulncheck"); err == nil {
		return run(exe, "./...")
	}
	// Probe first, so "cannot download the tool" is told apart from "vulnerabilities found".
	if _, err := output("go", "run", govulncheckModule, "-version"); err != nil {
		if os.Getenv(allowOfflineAudit) == "1" {
			fmt.Println("govulncheck: SKIPPED (not installed and could not be downloaded)")
			return nil
		}
		return fmt.Errorf("govulncheck is not installed and `go run %s` failed (offline?): "+
			"install it with `go install %s` or set %s=1 to skip this gate locally",
			govulncheckModule, govulncheckModule, allowOfflineAudit)
	}
	return run("go", "run", govulncheckModule, "./...")
}
