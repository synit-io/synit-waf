package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	mitText = `MIT License

Copyright (c) 2026 Example

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED.`

	bsd2Text = `Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice.
2. Redistributions in binary form must reproduce the above copyright notice.`

	bsd3Text = bsd2Text + `
3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software.`

	apacheText = `                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION`

	mplText = `Mozilla Public License Version 2.0
==================================

1.12. "Secondary License"
    means either the GNU General Public License, Version 2.0, the GNU
    Lesser General Public License, Version 2.1, the GNU Affero General
    Public License, Version 3.0, or any later versions of those licenses.`

	gpl3Text = `                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007`
)

func TestLicenseIDs(t *testing.T) {
	tests := []struct {
		name string
		text string
		want []string
	}{
		{name: "Apache-2.0", text: apacheText, want: []string{"Apache-2.0"}},
		{name: "Apache-2.0 short form", text: `Licensed under the Apache License, Version 2.0 (the "License");`, want: []string{"Apache-2.0"}},
		{name: "MIT", text: mitText, want: []string{"MIT"}},
		{name: "MIT with CRLF and wrapping", text: strings.ReplaceAll(strings.ReplaceAll(mitText, " ", "  "), "\n", "\r\n"), want: []string{"MIT"}},
		{name: "X11 is not MIT", text: mitText + "\nExcept as contained in this notice, the name of X shall not be used.", want: nil},
		{name: "BSD-2-Clause", text: bsd2Text, want: []string{"BSD-2-Clause"}},
		{name: "BSD-3-Clause", text: bsd3Text, want: []string{"BSD-3-Clause"}},
		{name: "BSD-4-Clause is unknown", text: bsd3Text + "\nAll advertising materials mentioning features must display an acknowledgement.", want: nil},
		{name: "ISC", text: "Permission to use, copy, modify, and/or distribute this software for any\npurpose with or without fee is hereby granted, provided that", want: []string{"ISC"}},
		{name: "ISC without or", text: "Permission to use, copy, modify, and distribute this software for any purpose with or without fee is hereby granted", want: []string{"ISC"}},
		{name: "MPL-2.0 mentions GPL", text: mplText, want: []string{"MPL-2.0"}},
		{name: "CC0-1.0", text: "Creative Commons Legal Code\n\nCC0 1.0 Universal", want: []string{"CC0-1.0"}},
		{name: "Unlicense", text: "This is free and unencumbered software released into the public domain.", want: []string{"Unlicense"}},
		{name: "GPL-3.0", text: gpl3Text, want: []string{"GPL-3.0-only"}},
		{name: "GPL-2.0", text: "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991", want: []string{"GPL-2.0-only"}},
		{name: "LGPL-3.0", text: "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007", want: []string{"LGPL-3.0-only"}},
		{name: "LGPL-2.1", text: "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1, February 1999", want: []string{"LGPL-2.1-only"}},
		{name: "AGPL-3.0", text: "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007", want: []string{"AGPL-3.0-only"}},
		{name: "several texts are sorted", text: mitText + "\n\n" + apacheText, want: []string{"Apache-2.0", "MIT"}},
		{name: "unknown", text: "All rights reserved.", want: nil},
		{name: "empty", text: "", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := licenseIDs([]byte(tt.text)); !slices.Equal(got, tt.want) {
				t.Fatalf("licenseIDs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDependencyLicense(t *testing.T) {
	file := func(name, text string) licenseFile { return licenseFile{Name: name, text: []byte(text)} }
	tests := []struct {
		name         string
		files        []licenseFile
		want         string
		wantCopyleft []string
	}{
		{name: "single licence", files: []licenseFile{file("LICENSE", mitText)}, want: "MIT"},
		{name: "notice and patents are ignored", files: []licenseFile{file("LICENSE", bsd3Text), file("PATENTS", "patent grant"), file("NOTICE", apacheText)}, want: "BSD-3-Clause"},
		{name: "same licence twice", files: []licenseFile{file("LICENSE", mitText), file("LICENSE.md", mitText)}, want: "MIT"},
		{name: "two licence files disagree", files: []licenseFile{file("LICENSE-APACHE", apacheText), file("LICENSE-MIT", mitText)}, want: noAssertion},
		{name: "one file with two licences", files: []licenseFile{file("LICENSE", mitText+apacheText)}, want: noAssertion},
		{name: "unknown licence file", files: []licenseFile{file("LICENSE", mitText), file("LICENSE.docs", "custom terms")}, want: noAssertion},
		{name: "no licence file", files: []licenseFile{file("NOTICE", "notice")}, want: noAssertion},
		{name: "copyleft", files: []licenseFile{file("COPYING", gpl3Text)}, want: "GPL-3.0-only", wantCopyleft: []string{"GPL-3.0-only"}},
		{name: "copyleft beside a permissive licence", files: []licenseFile{file("LICENSE", mitText), file("COPYING.LESSER", "GNU LESSER GENERAL PUBLIC LICENSE Version 3, 29 June 2007")}, want: noAssertion, wantCopyleft: []string{"LGPL-3.0-only"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, copyleft := dependencyLicense(tt.files)
			if got != tt.want || !slices.Equal(copyleft, tt.wantCopyleft) {
				t.Fatalf("dependencyLicense() = %q, %v, want %q, %v", got, copyleft, tt.want, tt.wantCopyleft)
			}
		})
	}
}

func TestCopyleftError(t *testing.T) {
	permissive := []dependency{{Path: "example.com/mit", Version: "v1.0.0", License: "MIT"}}
	if err := copyleftError(permissive); err != nil {
		t.Fatalf("copyleftError() = %v, want nil", err)
	}

	err := copyleftError(append(permissive, dependency{Path: "example.com/gpl", Version: "v2.0.0", License: noAssertion, copyleft: []string{"GPL-3.0-only"}}))
	if err == nil || !strings.Contains(err.Error(), "example.com/gpl@v2.0.0 (GPL-3.0-only)") {
		t.Fatalf("copyleftError() = %v, want the GPL dependency named", err)
	}
}

func TestIsLicenseName(t *testing.T) {
	tests := map[string]bool{
		"LICENSE":         true,
		"LICENSE.txt":     true,
		"LICENCE-MIT":     true,
		"COPYING":         true,
		"NOTICE":          true,
		"PATENTS":         true,
		"UNLICENSE":       true,
		"license.go":      false,
		"license_test.go": false,
		"licenses":        false,
		"README.md":       false,
	}
	for name, want := range tests {
		if got := isLicenseName(name); got != want {
			t.Errorf("isLicenseName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestUnionModulesIsSortedAndDistinct(t *testing.T) {
	procfs := moduleInfo{Path: "github.com/prometheus/procfs", Version: "v0.21.1"}
	purego := moduleInfo{Path: "github.com/ebitengine/purego", Version: "v0.9.1"}
	sys := moduleInfo{Path: "golang.org/x/sys", Version: "v0.47.0"}
	replaced := moduleInfo{Path: "golang.org/x/sys", Version: "v0.47.0", Replace: &moduleInfo{Path: "example.com/sys", Version: "v1.0.0"}}

	linux := []moduleInfo{sys, procfs}
	darwin := []moduleInfo{sys, purego, replaced}
	want := []string{
		"github.com/ebitengine/purego@v0.9.1",
		"github.com/prometheus/procfs@v0.21.1",
		"golang.org/x/sys@v0.47.0",
		"golang.org/x/sys@v0.47.0=>example.com/sys@v1.0.0",
	}
	for _, lists := range [][][]moduleInfo{{linux, darwin}, {darwin, linux}, {darwin, linux, darwin}} {
		var got []string
		for _, module := range unionModules(lists...) {
			got = append(got, moduleKey(module))
		}
		if !slices.Equal(got, want) {
			t.Fatalf("unionModules() keys = %v, want %v", got, want)
		}
	}
	if got := unionModules(); len(got) != 0 {
		t.Fatalf("unionModules() of nothing = %v, want empty", got)
	}
}

func TestDecodeModules(t *testing.T) {
	stream := `{"Standard": true}
{"Module": {"Path": "github.com/synit-io/synit-waf", "Main": true}}
{"Module": {"Path": "golang.org/x/sys", "Version": "v0.47.0", "Dir": "/cache/sys"}}
{"Module": {"Path": "golang.org/x/sys", "Version": "v0.47.0", "Dir": "/cache/sys"}}
{"Module": {"Path": "github.com/fsnotify/fsnotify", "Version": "v1.10.1"}}
{}`
	modules, err := decodeModules(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("decodeModules() error = %v", err)
	}
	var got []string
	for _, module := range modules {
		got = append(got, moduleKey(module))
	}
	if want := []string{"github.com/fsnotify/fsnotify@v1.10.1", "golang.org/x/sys@v0.47.0"}; !slices.Equal(got, want) {
		t.Fatalf("decodeModules() keys = %v, want %v", got, want)
	}

	if _, err := decodeModules(strings.NewReader(`{"Module": `)); err == nil {
		t.Fatal("decodeModules() accepted a truncated stream")
	}
}

func TestGoModModulePath(t *testing.T) {
	tests := map[string]string{
		"module github.com/synit-io/synit-waf\n\ngo 1.27.0\n":     "github.com/synit-io/synit-waf",
		"// comment\nmodule \"example.com/quoted\" // trailing\n": "example.com/quoted",
		"go 1.27.0\n\nmodule\texample.com/tabbed\r\n":             "example.com/tabbed",
		"go 1.27.0\nrequire example.com/module v1.0.0\n":          "",
		"":         "",
		"module\n": "",
		"modules example.com/not-a-directive\nmodule example.com/ok\n": "example.com/ok",
	}
	for content, want := range tests {
		if got := goModModulePath([]byte(content)); got != want {
			t.Errorf("goModModulePath(%q) = %q, want %q", content, got, want)
		}
	}
}

func TestFindRepositoryRoot(t *testing.T) {
	root := t.TempDir()
	service := filepath.Join(root, "services", "ai-logs-receiver")
	if err := os.MkdirAll(filepath.Join(service, "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "go.mod"), "module "+rootModule+"\n")
	// A nested module must not be mistaken for the repository root.
	writeFile(t, filepath.Join(service, "go.mod"), "module "+rootModule+"/services/ai-logs-receiver\n")

	for _, start := range []string{root, service, filepath.Join(service, "deep")} {
		got, err := findRepositoryRoot(start)
		if err != nil || got != root {
			t.Fatalf("findRepositoryRoot(%s) = %q, %v, want %q", start, got, err, root)
		}
	}

	if _, err := findRepositoryRoot(t.TempDir()); err == nil {
		t.Fatal("findRepositoryRoot() found a root outside the repository")
	}
}

func TestRepositoryRootFlag(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module "+rootModule+"\n")
	got, err := repositoryRoot(root)
	if err != nil || got != root {
		t.Fatalf("repositoryRoot(%s) = %q, %v", root, got, err)
	}

	if _, err := repositoryRoot(t.TempDir()); err == nil {
		t.Fatal("repositoryRoot() accepted a -root without the root go.mod")
	}
}

func TestRenderIsDeterministicAndComplete(t *testing.T) {
	dependencies := []dependency{{
		Path:         "example.com/mit",
		Version:      "v1.0.0",
		License:      "MIT",
		UsedBy:       []string{"synit-waf"},
		LicenseFiles: []licenseFile{{Name: "LICENSE", SHA256: "abc", text: []byte(mitText + "\n")}},
	}}
	covered := []coverage{{Binary: "synit-waf", Module: rootModule, EntryPoint: "./cmd/synit-waf", Platforms: []string{"linux/amd64", "windows/386"}}}

	notice := renderNotice(dependencies, covered)
	for _, want := range []string{"- synit-waf (" + rootModule + ", ./cmd/synit-waf): linux/amd64, windows/386\n", "example.com/mit v1.0.0\n", "Permission is hereby granted"} {
		if !strings.Contains(string(notice), want) {
			t.Fatalf("notice does not contain %q", want)
		}
	}
	metadata, err := renderManifest(dependencies, covered, notice)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"license": "MIT"`, `"module": "` + rootModule + `"`, `"windows/386"`} {
		if !strings.Contains(string(metadata), want) {
			t.Fatalf("manifest does not contain %q", want)
		}
	}

	dir := t.TempDir()
	path := filepath.Join(dir, manifestFile)
	writeFile(t, path, string(metadata))
	if err := checkFile(path, metadata); err != nil {
		t.Fatalf("checkFile() = %v for identical content", err)
	}
	if err := checkFile(path, append(metadata, '\n')); err == nil {
		t.Fatal("checkFile() accepted stale content")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
