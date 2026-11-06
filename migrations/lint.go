package migrations

import (
	"fmt"
	"regexp"
	"strings"
)

// Lint reports statements in m that an older build may not survive: they
// remove or rename something it reads, change a type, or tighten what it
// may write. A migration that declares "-- argus:breaking" is allowed them
// (older builds refuse to start against it). One that has been reviewed and
// is still compatible, for example SET NOT NULL on a column every released
// build fills, declares "-- argus:compatible <reason>" before its first
// statement. The baseline predates this check and is not linted.
//
// The check is a guard rail, not a proof: it reads statements, not intent.
func Lint(m Migration) []string {
	if m.Version == 1 || m.Breaking || declares(m.SQL, "argus:compatible") {
		return nil
	}
	var problems []string
	for _, stmt := range statements(m.SQL) {
		for _, rule := range lintRules {
			if rule.match(stmt) {
				problems = append(problems, fmt.Sprintf("%04d_%s: %s in %q; make it compatible, or mark the file -- argus:breaking (or -- argus:compatible <reason> after review)", m.Version, m.Name, rule.why, abbreviate(stmt)))
			}
		}
	}
	return problems
}

type lintRule struct {
	why   string
	match func(stmt string) bool
}

func matches(pattern string) func(string) bool {
	re := regexp.MustCompile(pattern)
	return re.MatchString
}

var lintRules = []lintRule{
	{"drops an object older builds may use", matches(`^drop (table|view|materialized view|schema|type|sequence|function)\b`)},
	{"drops a column", func(s string) bool {
		if !strings.HasPrefix(s, "alter table ") {
			return false
		}
		for _, part := range strings.Split(s, ",") {
			i := strings.Index(part, " drop ")
			if i < 0 {
				continue
			}
			rest := strings.TrimPrefix(part[i+len(" drop "):], "column ")
			// Relaxations are compatible: an older build is unaffected by a
			// dropped constraint, default or NOT NULL.
			if !(strings.HasPrefix(rest, "constraint ") || strings.HasPrefix(rest, "default") ||
				strings.HasPrefix(rest, "not null") || strings.HasPrefix(rest, "identity") || strings.HasPrefix(rest, "expression")) {
				return true
			}
		}
		return false
	}},
	{"renames an object", matches(`\brename\b`)},
	{"changes a column type", matches(`\balter column \S+ (set data )?type\b`)},
	{"makes a column NOT NULL", matches(`\bset not null\b`)},
	{"adds a NOT NULL column without a default", func(s string) bool {
		for _, part := range strings.Split(s, ",") {
			if regexp.MustCompile(`\badd (column )?(if not exists )?\S+ `).MatchString(part) &&
				strings.Contains(part, "not null") && !strings.Contains(part, " default ") {
				return true
			}
		}
		return false
	}},
	{"adds a constraint older writers may violate", matches(`\badd (constraint \S+ )?(check|unique|foreign key|primary key)\b`)},
	{"deletes data", matches(`^(truncate|delete from)\b`)},
}

var comment = regexp.MustCompile(`--[^\n]*`)
var space = regexp.MustCompile(`\s+`)

// statements splits a file into lower-cased, whitespace-normalized
// statements without comments. Dollar-quoted bodies are kept whole.
func statements(sql string) []string {
	sql = comment.ReplaceAllString(sql, "")
	var out []string
	var b strings.Builder
	inDollar := false
	for i := 0; i < len(sql); i++ {
		if strings.HasPrefix(sql[i:], "$$") {
			inDollar = !inDollar
			b.WriteString("$$")
			i++
			continue
		}
		if sql[i] == ';' && !inDollar {
			out = appendStatement(out, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(sql[i])
	}
	return appendStatement(out, b.String())
}

func appendStatement(out []string, stmt string) []string {
	stmt = strings.TrimSpace(space.ReplaceAllString(strings.ToLower(stmt), " "))
	if stmt == "" {
		return out
	}
	return append(out, stmt)
}

func abbreviate(s string) string {
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}

// declares reports whether the comment block before the first statement
// contains a line starting with directive.
func declares(body, directive string) bool {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "--") {
			return false
		}
		text := strings.TrimSpace(strings.TrimPrefix(line, "--"))
		if text == directive || strings.HasPrefix(text, directive+" ") {
			return true
		}
	}
	return false
}
