package database

import "testing"

func TestPostgresQuestionPlaceholders_PreservesQuotedLiterals(t *testing.T) {
	query := "SELECT COALESCE(parent_task_id,''), COALESCE(scan_options,'{}') FROM task_config WHERE task_id=?"
	want := "SELECT COALESCE(parent_task_id,''), COALESCE(scan_options,'{}') FROM task_config WHERE task_id=$1"
	if got := postgresQuestionPlaceholders(query); got != want {
		t.Fatalf("postgresQuestionPlaceholders() = %q, want %q", got, want)
	}
}

func TestPostgresQuestionPlaceholders_IgnoresQuestionMarksInsideQuotedText(t *testing.T) {
	query := "SELECT '?', \"??\", note FROM task_logs WHERE task_id=? AND message LIKE '%?%'"
	want := "SELECT '?', \"??\", note FROM task_logs WHERE task_id=$1 AND message LIKE '%?%'"
	if got := postgresQuestionPlaceholders(query); got != want {
		t.Fatalf("postgresQuestionPlaceholders() = %q, want %q", got, want)
	}
}

func TestPostgresQuestionPlaceholders_IgnoresQuestionMarksInsideCommentsAndDollarQuotes(t *testing.T) {
	query := "SELECT $tag$?$tag$, col /* ? */ FROM demo -- ?\nWHERE id=?"
	want := "SELECT $tag$?$tag$, col /* ? */ FROM demo -- ?\nWHERE id=$1"
	if got := postgresQuestionPlaceholders(query); got != want {
		t.Fatalf("postgresQuestionPlaceholders() = %q, want %q", got, want)
	}
}
