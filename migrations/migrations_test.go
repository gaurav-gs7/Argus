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
