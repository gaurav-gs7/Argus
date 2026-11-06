package migrations

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestEmbeddedMigrationsLoad(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if all[0].Version != 1 || all[0].Name != "baseline" || len(all[0].Checksum) != 64 {
		t.Fatalf("first migration = %+v", all[0])
	}
}

func TestLoadRejectsBadSets(t *testing.T) {
	file := func(body string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(body)} }
	cases := map[string]struct {
		fs   fstest.MapFS
		want string
	}{
		"bad name": {fstest.MapFS{"0001_init.sql": file("x"), "2_more.sql": file("y")}, "does not match"},
		"gap":      {fstest.MapFS{"0001_init.sql": file("x"), "0003_more.sql": file("y")}, "contiguous"},
		"no start": {fstest.MapFS{"0002_init.sql": file("x")}, "contiguous"},
		"dup":      {fstest.MapFS{"0001_init.sql": file("x"), "0001_again.sql": file("y")}, "contiguous"},
		"empty":    {fstest.MapFS{}, "no migrations"},
	}
	for name, tc := range cases {
		if _, err := Load(tc.fs); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err=%v, want %q", name, err, tc.want)
		}
	}
}

func TestLoadOrdersByVersionAndChecksumsContent(t *testing.T) {
	set, err := Load(fstest.MapFS{
		"0002_second.sql": {Data: []byte("SELECT 2;")},
		"0001_first.sql":  {Data: []byte("SELECT 1;")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if set[0].Name != "first" || set[1].Name != "second" || set[0].Checksum == set[1].Checksum {
		t.Fatalf("set=%+v", set)
	}
}

func TestBreakingDirectiveMustPrecedeStatements(t *testing.T) {
	cases := map[string]bool{
		"-- argus:breaking\nALTER TABLE t DROP COLUMN c;":                    true,
		"-- Drops a column.\n--   argus:breaking  \n\nALTER TABLE t DROP c;": true,
		"-- Adds a column.\nALTER TABLE t ADD c INT;":                        false,
		"ALTER TABLE t ADD c INT;\n-- argus:breaking":                        false,
		"-- argus:breaking-ish\nSELECT 1;":                                   false,
	}
	for body, want := range cases {
		set, err := Load(fstest.MapFS{"0001_x.sql": {Data: []byte(body)}})
		if err != nil {
			t.Fatal(err)
		}
		if set[0].Breaking != want {
			t.Fatalf("%q: breaking=%v want %v", body, set[0].Breaking, want)
		}
	}
	all, _ := All()
	if all[0].Breaking {
		t.Fatal("the baseline must not be breaking")
	}
}

// Every released migration must be compatible with the previous release or
// say that it is not.
func TestEmbeddedMigrationsAreCompatibleOrMarkedBreaking(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range all {
		if problems := Lint(m); len(problems) > 0 {
			t.Errorf("%v", problems)
		}
	}
}

func TestLintFlagsIncompatibleStatements(t *testing.T) {
	flagged := []string{
		"DROP TABLE incidents;",
		"ALTER TABLE incidents DROP COLUMN summary;",
		"ALTER TABLE incidents DROP summary;",
		"ALTER TABLE incidents ADD COLUMN owner TEXT, DROP COLUMN summary;",
		"ALTER TABLE incidents RENAME COLUMN summary TO details;",
		"ALTER TABLE incidents RENAME TO cases;",
		"ALTER TABLE incidents ALTER COLUMN severity TYPE INTEGER USING 1;",
		"ALTER TABLE incidents ALTER COLUMN severity SET DATA TYPE TEXT;",
		"ALTER TABLE incidents ALTER COLUMN summary SET NOT NULL;",
		"ALTER TABLE incidents ADD COLUMN owner TEXT NOT NULL;",
		"ALTER TABLE incidents ADD CONSTRAINT owner_set CHECK (owner <> '');",
		"ALTER TABLE incidents ADD UNIQUE (title);",
		"TRUNCATE signals;",
		"DELETE FROM signals;",
		"-- a comment mentioning nothing\nalter   table\n incidents   drop\tcolumn summary ;",
	}
	for _, sql := range flagged {
		if problems := Lint(Migration{Version: 2, Name: "x", SQL: sql}); len(problems) == 0 {
			t.Errorf("not flagged: %q", sql)
		}
	}
	allowed := []string{
		"CREATE TABLE things (id TEXT PRIMARY KEY, name TEXT NOT NULL CHECK (name <> ''));",
		"ALTER TABLE incidents ADD COLUMN IF NOT EXISTS owner TEXT;",
		"ALTER TABLE incidents ADD COLUMN owner TEXT NOT NULL DEFAULT 'unknown';",
		"ALTER TABLE incidents ALTER COLUMN summary DROP NOT NULL;",
		"ALTER TABLE incidents ALTER COLUMN summary DROP DEFAULT;",
		"ALTER TABLE incidents DROP CONSTRAINT incidents_severity_check;",
		"CREATE INDEX IF NOT EXISTS idx_x ON incidents(title);",
		"UPDATE incidents SET environment = 'local' WHERE environment IS NULL;",
		"CREATE OR REPLACE FUNCTION f() RETURNS trigger AS $$ BEGIN DELETE FROM x; RETURN NEW; END $$ LANGUAGE plpgsql;",
		"-- drop table incidents; (a comment)\nSELECT 1;",
	}
	for _, sql := range allowed {
		if problems := Lint(Migration{Version: 2, Name: "x", SQL: sql}); len(problems) > 0 {
			t.Errorf("flagged a compatible statement: %v", problems)
		}
	}
	for _, header := range []string{"-- argus:breaking\n", "-- argus:compatible every released build writes summary\n"} {
		if problems := Lint(Migration{Version: 2, Name: "x", SQL: header + "ALTER TABLE incidents ALTER COLUMN summary SET NOT NULL;", Breaking: header == "-- argus:breaking\n"}); len(problems) > 0 {
			t.Errorf("declared migration still flagged: %v", problems)
		}
	}
}
