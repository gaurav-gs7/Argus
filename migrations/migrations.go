// Package migrations embeds the versioned SQL files that define the Argus
// schema. internal/db applies them in order and records each one in
// schema_migrations; these files are the only source of schema truth.
//
// Rules for adding a migration:
//   - name it NNNN_short_description.sql with the next version number;
//   - never edit or renumber a file once it has been released, because the
//     runner stores each file's SHA-256 and refuses to start on a mismatch;
//   - each file runs in one transaction, so it must not use statements that
//     cannot run inside one (CREATE INDEX CONCURRENTLY, VACUUM, ...);
//   - keep migrations backward compatible (add columns, tables and indexes;
//     backfill; do not drop or rename what a released build still reads), so
//     the previous release can keep running against the new schema during a
//     rolling deploy or a rollback. A migration that cannot be compatible
//     must say so with a line "-- argus:breaking" before its first
//     statement; older builds then refuse to start against it.
package migrations

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed *.sql
var files embed.FS

// Migration is one versioned schema change.
type Migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum string
	// Breaking marks a migration older builds cannot run against.
	Breaking bool
}

var fileName = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

// All returns the embedded migrations in version order.
func All() ([]Migration, error) {
	return Load(files)
}

// Load reads migrations from fsys. Versions must start at 1 and be
// contiguous, so a mis-numbered or missing file fails at startup rather than
// being silently skipped or applied out of order.
func Load(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	var out []Migration
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		match := fileName.FindStringSubmatch(entry.Name())
		if match == nil {
			return nil, fmt.Errorf("migration file %q does not match NNNN_name.sql", entry.Name())
		}
		body, err := fs.ReadFile(fsys, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		version, _ := strconv.Atoi(match[1])
		sum := sha256.Sum256(body)
		out = append(out, Migration{Version: version, Name: match[2], SQL: string(body), Checksum: hex.EncodeToString(sum[:]), Breaking: declaresBreaking(string(body))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, m := range out {
		if m.Version != i+1 {
			return nil, fmt.Errorf("migration versions must be contiguous from 0001: found %04d_%s at position %d", m.Version, m.Name, i+1)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no migrations embedded")
	}
	return out, nil
}

// declaresBreaking reports whether the comment block before the first
// statement contains "-- argus:breaking".
func declaresBreaking(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "--") {
			return false
		}
		if strings.TrimSpace(strings.TrimPrefix(line, "--")) == "argus:breaking" {
			return true
		}
	}
	return false
}
