// Command thirdparty generates deterministic third-party notice artifacts for
// every shipped Go binary in this repository. Dependencies are the union over
// every shipped platform, so the output does not depend on the host.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

const (
	rootModule   = "github.com/synit-io/synit-waf"
	noAssertion  = "NOASSERTION"
	noticeFile   = "THIRD_PARTY_NOTICES.txt"
	manifestFile = "manifest.json"
)

type platform struct {
	GOOS   string
	GOARCH string
}

func (p platform) String() string { return p.GOOS + "/" + p.GOARCH }

type binarySpec struct {
	Name       string
	ModuleDir  string
	EntryPoint string
	Platforms  []platform
}

type moduleInfo struct {
	Path    string      `json:"Path"`
	Version string      `json:"Version"`
	Dir     string      `json:"Dir"`
	Main    bool        `json:"Main"`
	Replace *moduleInfo `json:"Replace"`
}

type packageInfo struct {
	Standard bool        `json:"Standard"`
	Module   *moduleInfo `json:"Module"`
}

type dependency struct {
	Path           string        `json:"path"`
	Version        string        `json:"version"`
	License        string        `json:"license"`
	ReplacedByPath string        `json:"replaced_by_path,omitempty"`
	ReplacedByVers string        `json:"replaced_by_version,omitempty"`
	UsedBy         []string      `json:"used_by"`
	LicenseFiles   []licenseFile `json:"license_files"`
	dir            string
	copyleft       []string
}

type licenseFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	text   []byte
}

type coverage struct {
	Binary     string   `json:"binary"`
	Module     string   `json:"module"`
	EntryPoint string   `json:"entry_point"`
	Platforms  []string `json:"platforms"`
}

type manifest struct {
	FormatVersion int          `json:"format_version"`
	Generator     string       `json:"generator"`
	Coverage      []coverage   `json:"coverage"`
	NoticeSHA256  string       `json:"notice_sha256"`
	Dependencies  []dependency `json:"dependencies"`
}

// releasePlatforms mirrors the publish-binaries matrix in
// .github/workflows/release.yml; imagePlatforms mirrors its image platforms.
var (
	releasePlatforms = []platform{
		{GOOS: "linux", GOARCH: "amd64"},
		{GOOS: "linux", GOARCH: "arm64"},
		{GOOS: "linux", GOARCH: "386"},
		{GOOS: "linux", GOARCH: "arm"},
		{GOOS: "darwin", GOARCH: "amd64"},
		{GOOS: "darwin", GOARCH: "arm64"},
		{GOOS: "windows", GOARCH: "amd64"},
		{GOOS: "windows", GOARCH: "arm64"},
		{GOOS: "windows", GOARCH: "386"},
	}
	imagePlatforms = []platform{
		{GOOS: "linux", GOARCH: "amd64"},
		{GOOS: "linux", GOARCH: "arm64"},
	}
)

var binaries = []binarySpec{
	{Name: "synit-waf", ModuleDir: ".", EntryPoint: "./cmd/synit-waf", Platforms: releasePlatforms},
	{Name: "ai-logs-receiver", ModuleDir: "services/ai-logs-receiver", EntryPoint: ".", Platforms: imagePlatforms},
	{Name: "synit-llm-guard", ModuleDir: "services/synit-llm-guard", EntryPoint: ".", Platforms: imagePlatforms},
}

var outputDirs = []string{
	"third_party",
	"services/ai-logs-receiver/third_party",
	"services/synit-llm-guard/third_party",
}

func main() {
	check := flag.Bool("check", false, "fail if committed artifacts differ from generated output or a dependency is GPL, AGPL, or LGPL")
	rootFlag := flag.String("root", "", "repository root (default: found with git, then by walking up to the root go.mod)")
	flag.Parse()

	root, err := repositoryRoot(*rootFlag)
	if err != nil {
		fatal(err)
	}

	dependencies, covered, err := collect(root)
	if err != nil {
		fatal(err)
	}
	if err := copyleftError(dependencies); err != nil {
		if *check {
			fatal(err)
		}
		fmt.Fprintln(os.Stderr, "warning:", err)
	}

	notice := renderNotice(dependencies, covered)
	metadata, err := renderManifest(dependencies, covered, notice)
	if err != nil {
		fatal(err)
	}

	for _, outputDir := range outputDirs {
		dir := filepath.Join(root, outputDir)
		if *check {
			if err := checkFile(filepath.Join(dir, noticeFile), notice); err != nil {
				fatal(err)
			}
			if err := checkFile(filepath.Join(dir, manifestFile), metadata); err != nil {
				fatal(err)
			}
			continue
		}

		if err := os.MkdirAll(dir, 0o755); err != nil {
			fatal(fmt.Errorf("create %s: %w", dir, err))
		}
		if err := os.WriteFile(filepath.Join(dir, noticeFile), notice, 0o644); err != nil {
			fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, manifestFile), metadata, 0o644); err != nil {
			fatal(err)
		}
	}
}

// repositoryRoot prefers an explicit root, then git, then the nearest parent
// of the working directory holding the root module's go.mod.
func repositoryRoot(explicit string) (string, error) {
	if explicit != "" {
		root, err := filepath.Abs(explicit)
		if err != nil {
			return "", fmt.Errorf("resolve -root: %w", err)
		}
		if !isRepositoryRoot(root) {
			return "", fmt.Errorf("-root %s does not contain the go.mod of module %s", root, rootModule)
		}
		return root, nil
	}
	if output, err := exec.Command("git", "rev-parse", "--show-toplevel").Output(); err == nil {
		if root := strings.TrimSpace(string(output)); isRepositoryRoot(root) {
			return root, nil
		}
	}
	workDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("find repository root: %w", err)
	}
	return findRepositoryRoot(workDir)
}

func findRepositoryRoot(start string) (string, error) {
	for dir := start; ; dir = filepath.Dir(dir) {
		if isRepositoryRoot(dir) {
			return dir, nil
		}
		if dir == filepath.Dir(dir) {
			return "", fmt.Errorf("find repository root: no go.mod of module %s in %s or its parents; use -root", rootModule, start)
		}
	}
}

func isRepositoryRoot(dir string) bool {
	content, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	return err == nil && goModModulePath(content) == rootModule
}

// goModModulePath returns the path of the module directive in go.mod content.
func goModModulePath(content []byte) string {
	for line := range strings.Lines(string(content)) {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "module" {
			return strings.Trim(fields[1], "\"`")
		}
	}
	return ""
}

func collect(root string) ([]dependency, []coverage, error) {
	byKey := make(map[string]*dependency)
	covered := make([]coverage, 0, len(binaries))

	for _, binary := range binaries {
		moduleDir := filepath.Join(root, binary.ModuleDir)
		modulePath, err := modulePath(moduleDir)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", binary.Name, err)
		}
		platforms := make([]string, 0, len(binary.Platforms))
		perPlatform := make([][]moduleInfo, 0, len(binary.Platforms))
		for _, target := range binary.Platforms {
			modules, err := packageModules(moduleDir, binary.EntryPoint, target)
			if err != nil {
				return nil, nil, fmt.Errorf("%s (%s): %w", binary.Name, target, err)
			}
			platforms = append(platforms, target.String())
			perPlatform = append(perPlatform, modules)
		}
		sort.Strings(platforms)
		covered = append(covered, coverage{
			Binary:     binary.Name,
			Module:     modulePath,
			EntryPoint: binary.EntryPoint,
			Platforms:  platforms,
		})

		for _, module := range unionModules(perPlatform...) {
			key := moduleKey(module)
			actual := module
			if module.Replace != nil {
				actual = *module.Replace
			}

			item, ok := byKey[key]
			if !ok {
				item = &dependency{
					Path:    module.Path,
					Version: module.Version,
					dir:     actual.Dir,
				}
				if module.Replace != nil {
					item.ReplacedByPath = actual.Path
					item.ReplacedByVers = actual.Version
				}
				byKey[key] = item
			}
			if !slices.Contains(item.UsedBy, binary.Name) {
				item.UsedBy = append(item.UsedBy, binary.Name)
			}
		}
	}

	dependencies := make([]dependency, 0, len(byKey)+1)
	goLicense, err := goToolchainLicense()
	if err != nil {
		return nil, nil, err
	}
	toolchain := dependency{
		Path:         "go.dev/toolchain",
		Version:      "standard-library-and-runtime",
		UsedBy:       []string{"ai-logs-receiver", "synit-llm-guard", "synit-waf"},
		LicenseFiles: goLicense,
	}
	toolchain.License, toolchain.copyleft = dependencyLicense(goLicense)
	dependencies = append(dependencies, toolchain)

	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		item := byKey[key]
		sort.Strings(item.UsedBy)
		files, err := findLicenseFiles(item.dir)
		if err != nil {
			return nil, nil, fmt.Errorf("%s@%s: %w", item.Path, item.Version, err)
		}
		item.LicenseFiles = files
		item.License, item.copyleft = dependencyLicense(files)
		dependencies = append(dependencies, *item)
	}

	return dependencies, covered, nil
}

func modulePath(moduleDir string) (string, error) {
	cmd := goCommand(moduleDir, "list", "-m", "-f", "{{.Path}}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go list module: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

// packageModules lists the third-party modules compiled into entryPoint for
// one target platform. A module that cannot be downloaded fails the listing.
func packageModules(moduleDir, entryPoint string, target platform) ([]moduleInfo, error) {
	cmd := goCommand(moduleDir, "list", "-deps", "-json=Standard,Module", entryPoint)
	cmd.Env = append(cmd.Env, "GOOS="+target.GOOS, "GOARCH="+target.GOARCH)
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	modules, err := decodeModules(output)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("go list dependencies: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return modules, nil
}

// decodeModules reads a `go list -deps -json` stream and returns the distinct
// third-party modules in key order.
func decodeModules(output io.Reader) ([]moduleInfo, error) {
	var modules []moduleInfo
	decoder := json.NewDecoder(output)
	for {
		var pkg packageInfo
		err := decoder.Decode(&pkg)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		if pkg.Standard || pkg.Module == nil || pkg.Module.Main {
			continue
		}
		modules = append(modules, *pkg.Module)
	}
	return unionModules(modules), nil
}

func moduleKey(module moduleInfo) string {
	key := module.Path + "@" + module.Version
	if module.Replace != nil {
		key += "=>" + module.Replace.Path + "@" + module.Replace.Version
	}
	return key
}

// unionModules merges module lists into one list without duplicates, sorted by key.
func unionModules(lists ...[]moduleInfo) []moduleInfo {
	byKey := make(map[string]moduleInfo)
	for _, modules := range lists {
		for _, module := range modules {
			byKey[moduleKey(module)] = module
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	union := make([]moduleInfo, 0, len(keys))
	for _, key := range keys {
		union = append(union, byKey[key])
	}
	return union
}

// goCommand pins every setting that selects which packages are compiled, so the
// result does not depend on the host or the caller's environment. exec uses the
// last value of a duplicate key. The feature levels are the Go defaults used by
// the release build, except GOARM, which the release matrix sets to 7.
func goCommand(dir string, args ...string) *exec.Cmd {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GOWORK=off",
		"GOFLAGS=-mod=readonly",
		"CGO_ENABLED=0",
		"GOARM=7",
		"GOAMD64=v1",
		"GOARM64=v8.0",
		"GO386=sse2",
	)
	return cmd
}

func findLicenseFiles(dir string) ([]licenseFile, error) {
	if dir == "" {
		return nil, fmt.Errorf("module directory is empty; run go mod download")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read module directory: %w", err)
	}

	var paths []string
	for _, entry := range entries {
		if !entry.IsDir() && isLicenseName(entry.Name()) {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no root license or notice file found")
	}
	return readLicenseFiles(paths)
}

func isLicenseName(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".go") {
		return false // Go source such as license.go is not a notice file.
	}
	for _, prefix := range []string{"license", "licence", "copying", "notice", "patents", "copyright", "authors", "contributors", "unlicense"} {
		if lower == prefix || strings.HasPrefix(lower, prefix+".") || strings.HasPrefix(lower, prefix+"-") || strings.HasPrefix(lower, prefix+"_") {
			return true
		}
	}
	return false
}

// isLicenseTextName reports whether a collected file is expected to hold licence
// terms, as opposed to notices, patent grants, or contributor lists.
func isLicenseTextName(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"license", "licence", "copying", "unlicense"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// licenseRules identify licence texts by phrases of their normalized form (see
// normalizeLicenseText). The GNU rules match the dated title so that texts
// which only mention the GPL, such as MPL-2.0, do not match.
var licenseRules = []struct {
	id       string
	required []string
	excluded []string
}{
	{id: "Apache-2.0", required: []string{"apache license version 2 0"}},
	{id: "MIT", required: []string{
		"permission is hereby granted free of charge to any person obtaining a copy",
		"the above copyright notice and this permission notice shall be included in all copies or substantial portions of the software",
		"the software is provided as is without warranty of any kind",
	}, excluded: []string{"except as contained in this notice"}},
	{id: "BSD-2-Clause", required: []string{
		"redistribution and use in source and binary forms with or without modification are permitted provided that the following conditions are met",
	}, excluded: []string{"endorse or promote products", "advertising materials", "views and conclusions contained in the software"}},
	{id: "BSD-3-Clause", required: []string{
		"redistribution and use in source and binary forms with or without modification are permitted provided that the following conditions are met",
		"endorse or promote products",
	}, excluded: []string{"advertising materials"}},
	{id: "ISC", required: []string{"permission to use copy modify and or distribute this software for any purpose with or without fee is hereby granted"}},
	{id: "ISC", required: []string{"permission to use copy modify and distribute this software for any purpose with or without fee is hereby granted"}},
	{id: "MPL-2.0", required: []string{"mozilla public license version 2 0"}},
	{id: "CC0-1.0", required: []string{"cc0 1 0 universal"}},
	{id: "Unlicense", required: []string{"this is free and unencumbered software released into the public domain"}},
	{id: "AGPL-3.0-only", required: []string{"gnu affero general public license version 3 19 november 2007"}},
	{id: "GPL-2.0-only", required: []string{"gnu general public license version 2 june 1991"}},
	{id: "GPL-3.0-only", required: []string{"gnu general public license version 3 29 june 2007"}},
	{id: "LGPL-2.0-only", required: []string{"gnu library general public license version 2 june 1991"}},
	{id: "LGPL-2.1-only", required: []string{"gnu lesser general public license version 2 1 february 1999"}},
	{id: "LGPL-3.0-only", required: []string{"gnu lesser general public license version 3 29 june 2007"}},
}

// normalizeLicenseText lower-cases text and reduces every run of other
// characters to one space, so wrapping and punctuation do not affect matching.
func normalizeLicenseText(text []byte) string {
	var normalized strings.Builder
	pendingSpace := false
	for _, r := range strings.ToLower(string(text)) {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			pendingSpace = true
			continue
		}
		if pendingSpace && normalized.Len() > 0 {
			normalized.WriteByte(' ')
		}
		pendingSpace = false
		normalized.WriteRune(r)
	}
	return normalized.String()
}

// licenseIDs returns the sorted SPDX identifiers of the licence texts found in text.
func licenseIDs(text []byte) []string {
	normalized := normalizeLicenseText(text)
	var ids []string
	for _, rule := range licenseRules {
		matches := func(phrase string) bool { return strings.Contains(normalized, phrase) }
		if slices.ContainsFunc(rule.excluded, matches) || slices.ContainsFunc(rule.required, func(phrase string) bool { return !matches(phrase) }) {
			continue
		}
		if !slices.Contains(ids, rule.id) {
			ids = append(ids, rule.id)
		}
	}
	sort.Strings(ids)
	return ids
}

// dependencyLicense returns the SPDX identifier of a dependency when every one
// of its licence files holds the same single known licence, and NOASSERTION
// otherwise. GPL-family identifiers are reported even when the result is
// NOASSERTION.
func dependencyLicense(files []licenseFile) (string, []string) {
	var ids, copyleft []string
	reliable := true
	for _, file := range files {
		if !isLicenseTextName(file.Name) {
			continue
		}
		found := licenseIDs(file.text)
		if len(found) != 1 {
			reliable = false
		}
		for _, id := range found {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
			if isCopyleft(id) && !slices.Contains(copyleft, id) {
				copyleft = append(copyleft, id)
			}
		}
	}
	sort.Strings(copyleft)
	if !reliable || len(ids) != 1 {
		return noAssertion, copyleft
	}
	return ids[0], copyleft
}

func isCopyleft(id string) bool {
	return strings.HasPrefix(id, "GPL-") || strings.HasPrefix(id, "AGPL-") || strings.HasPrefix(id, "LGPL-")
}

// copyleftError reports every dependency that carries a GPL, AGPL, or LGPL text.
func copyleftError(dependencies []dependency) error {
	var found []string
	for _, item := range dependencies {
		if len(item.copyleft) > 0 {
			found = append(found, fmt.Sprintf("%s@%s (%s)", item.Path, item.Version, strings.Join(item.copyleft, ", ")))
		}
	}
	if len(found) == 0 {
		return nil
	}
	return fmt.Errorf("GPL-family licensed dependencies are not allowed: %s", strings.Join(found, "; "))
}

func goToolchainLicense() ([]licenseFile, error) {
	cmd := exec.Command("go", "env", "GOROOT")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("find GOROOT: %w", err)
	}
	goRoot := strings.TrimSpace(string(output))
	candidates := []string{
		filepath.Join(goRoot, "LICENSE"),
		filepath.Join(filepath.Dir(goRoot), "LICENSE"),
		filepath.Join(goRoot, "PATENTS"),
	}
	var paths []string
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() && !slices.Contains(paths, candidate) {
			paths = append(paths, candidate)
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no Go toolchain LICENSE or PATENTS file found under %s", goRoot)
	}
	return readLicenseFiles(paths)
}

func readLicenseFiles(paths []string) ([]licenseFile, error) {
	files := make([]licenseFile, 0, len(paths))
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		content = normalizeText(content)
		hash := sha256.Sum256(content)
		files = append(files, licenseFile{
			Name:   filepath.Base(path),
			SHA256: hex.EncodeToString(hash[:]),
			text:   content,
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, nil
}

func normalizeText(content []byte) []byte {
	content = bytes.TrimPrefix(content, []byte{0xef, 0xbb, 0xbf})
	content = bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n"))
	content = bytes.ReplaceAll(content, []byte("\r"), []byte("\n"))
	return append(bytes.TrimRight(content, "\n"), '\n')
}

func renderNotice(dependencies []dependency, covered []coverage) []byte {
	var output strings.Builder
	output.WriteString("THIRD-PARTY NOTICES\n")
	output.WriteString("===================\n\n")
	output.WriteString("Generated by `go run ./tools/thirdparty`. DO NOT EDIT.\n")
	output.WriteString("Coverage is the compiled package dependency closure, with CGO_ENABLED=0 and\n")
	output.WriteString("as the union over every listed platform, of:\n")
	for _, item := range covered {
		fmt.Fprintf(&output, "- %s (%s, %s): %s\n", item.Binary, item.Module, item.EntryPoint, strings.Join(item.Platforms, ", "))
	}
	output.WriteString("\n")

	for _, item := range dependencies {
		output.WriteString("--------------------------------------------------------------------------------\n")
		fmt.Fprintf(&output, "%s %s\n", item.Path, item.Version)
		fmt.Fprintf(&output, "Used by: %s\n", strings.Join(item.UsedBy, ", "))
		if item.ReplacedByPath != "" {
			fmt.Fprintf(&output, "Replaced by: %s %s\n", item.ReplacedByPath, item.ReplacedByVers)
		}
		for _, file := range item.LicenseFiles {
			fmt.Fprintf(&output, "\n--- %s (SHA-256: %s) ---\n\n", file.Name, file.SHA256)
			output.Write(file.text)
		}
		output.WriteString("\n")
	}

	return []byte(output.String())
}

func renderManifest(dependencies []dependency, covered []coverage, notice []byte) ([]byte, error) {
	hash := sha256.Sum256(notice)
	metadata := manifest{
		FormatVersion: 2,
		Generator:     "tools/thirdparty",
		Coverage:      covered,
		NoticeSHA256:  hex.EncodeToString(hash[:]),
		Dependencies:  dependencies,
	}
	encoded, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func checkFile(path string, expected []byte) error {
	actual, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read generated artifact %s: %w", path, err)
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("generated artifact is stale: %s", path)
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
