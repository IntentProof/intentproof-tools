package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/intentproof/intentproof-tools/pkg/doctor"
)

func runReferenceList(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "Usage: intentproof reference list")
		return 1
	}

	packs, err := loadReferencePacks()
	if err != nil {
		fmt.Fprintf(stderr, "reference list failed: %v\n", err)
		return 1
	}
	for _, pack := range packs {
		fmt.Fprintf(stdout, "%s\t%s\t%s\n", pack.Manifest.ReferenceID, pack.Manifest.DisplayName, pack.Manifest.Summary)
	}
	return 0
}

func loadReferencePacks() ([]referencePack, error) {
	root, err := doctor.ResolveReferencePoliciesDir("")
	if err != nil {
		return nil, err
	}

	packs := make([]referencePack, 0)
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() != "pack.json" {
			return nil
		}
		pack, err := readReferencePack(path)
		if err != nil {
			return err
		}
		packs = append(packs, pack)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(packs, func(i, j int) bool {
		return packs[i].Manifest.ReferenceID < packs[j].Manifest.ReferenceID
	})
	return packs, nil
}

func findReferencePack(referenceID string) (referencePack, error) {
	packs, err := loadReferencePacks()
	if err != nil {
		return referencePack{}, err
	}
	for _, pack := range packs {
		if pack.Manifest.ReferenceID == referenceID {
			return pack, nil
		}
	}
	return referencePack{}, fmt.Errorf("reference policy %q not found", referenceID)
}

func readReferencePack(manifestPath string) (referencePack, error) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return referencePack{}, err
	}
	var manifest referencePackManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return referencePack{}, fmt.Errorf("parse %s: %w", manifestPath, err)
	}
	if strings.TrimSpace(manifest.ReferenceID) == "" {
		return referencePack{}, fmt.Errorf("%s: reference_id is required", manifestPath)
	}
	return referencePack{
		Manifest: manifest,
		Dir:      filepath.Dir(manifestPath),
	}, nil
}
