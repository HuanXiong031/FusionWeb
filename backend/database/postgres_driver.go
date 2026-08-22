package database

import (
	"context"
	"database/sql/driver"
	"fmt"
	"io"
	"strings"

	"github.com/lib/pq"
)

type postgresQuestionConnector struct {
	base driver.Connector
}

func openPostgresQuestionDB(dsn string) (driver.Connector, error) {
	base, err := pq.NewConnector(dsn)
	if err != nil {
		return nil, err
	}
	return &postgresQuestionConnector{base: base}, nil
}

func (c *postgresQuestionConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &postgresQuestionConn{Conn: conn}, nil
}

func (c *postgresQuestionConnector) Driver() driver.Driver {
	return c.base.Driver()
}

type postgresQuestionConn struct {
	driver.Conn
}

func (c *postgresQuestionConn) Prepare(query string) (driver.Stmt, error) {
	stmt, err := c.Conn.Prepare(postgresCompatSQL(query))
	if err != nil {
		return nil, err
	}
	return stmt, nil
}

func (c *postgresQuestionConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if conn, ok := c.Conn.(driver.ConnPrepareContext); ok {
		return conn.PrepareContext(ctx, postgresCompatSQL(query))
	}
	return c.Prepare(query)
}

func (c *postgresQuestionConn) Exec(query string, args []driver.Value) (driver.Result, error) {
	if conn, ok := c.Conn.(driver.Execer); ok {
		return conn.Exec(postgresCompatSQL(query), args)
	}
	return nil, driver.ErrSkip
}

func (c *postgresQuestionConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if conn, ok := c.Conn.(driver.ExecerContext); ok {
		return conn.ExecContext(ctx, postgresCompatSQL(query), args)
	}
	return nil, driver.ErrSkip
}

func (c *postgresQuestionConn) Query(query string, args []driver.Value) (driver.Rows, error) {
	if conn, ok := c.Conn.(driver.Queryer); ok {
		return conn.Query(postgresCompatSQL(query), args)
	}
	return nil, driver.ErrSkip
}

func (c *postgresQuestionConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if conn, ok := c.Conn.(driver.QueryerContext); ok {
		return conn.QueryContext(ctx, postgresCompatSQL(query), args)
	}
	return nil, driver.ErrSkip
}

func (c *postgresQuestionConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if conn, ok := c.Conn.(driver.ConnBeginTx); ok {
		return conn.BeginTx(ctx, opts)
	}
	return c.Conn.Begin()
}

func (c *postgresQuestionConn) Ping(ctx context.Context) error {
	if conn, ok := c.Conn.(driver.Pinger); ok {
		return conn.Ping(ctx)
	}
	return nil
}

func (c *postgresQuestionConn) ResetSession(ctx context.Context) error {
	if conn, ok := c.Conn.(driver.SessionResetter); ok {
		return conn.ResetSession(ctx)
	}
	return nil
}

func (c *postgresQuestionConn) CheckNamedValue(value *driver.NamedValue) error {
	if conn, ok := c.Conn.(driver.NamedValueChecker); ok {
		return conn.CheckNamedValue(value)
	}
	return driver.ErrSkip
}

var _ driver.Conn = (*postgresQuestionConn)(nil)
var _ driver.ConnPrepareContext = (*postgresQuestionConn)(nil)
var _ driver.ExecerContext = (*postgresQuestionConn)(nil)
var _ driver.QueryerContext = (*postgresQuestionConn)(nil)
var _ driver.ConnBeginTx = (*postgresQuestionConn)(nil)
var _ driver.Pinger = (*postgresQuestionConn)(nil)
var _ driver.SessionResetter = (*postgresQuestionConn)(nil)
var _ driver.NamedValueChecker = (*postgresQuestionConn)(nil)

func postgresCompatSQL(query string) string {
	return postgresQuestionPlaceholders(query)
}

func postgresQuestionPlaceholders(query string) string {
	var b strings.Builder
	b.Grow(len(query) + 8)
	arg := 1
	for i := 0; i < len(query); i++ {
		ch := query[i]
		switch ch {
		case '\'':
			next := copySingleQuoted(&b, query, i)
			i = next - 1
		case '"':
			next := copyDoubleQuoted(&b, query, i)
			i = next - 1
		case '-':
			if i+1 < len(query) && query[i+1] == '-' {
				next := copyLineComment(&b, query, i)
				i = next - 1
			} else {
				b.WriteByte(ch)
			}
		case '/':
			if i+1 < len(query) && query[i+1] == '*' {
				next := copyBlockComment(&b, query, i)
				i = next - 1
			} else {
				b.WriteByte(ch)
			}
		case '$':
			if tag, ok := readDollarQuoteTag(query, i); ok {
				next := copyDollarQuoted(&b, query, i, tag)
				i = next - 1
			} else {
				b.WriteByte(ch)
			}
		case '?':
			b.WriteString(fmt.Sprintf("$%d", arg))
			arg++
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}

func copySingleQuoted(b *strings.Builder, query string, start int) int {
	for i := start; i < len(query); i++ {
		b.WriteByte(query[i])
		if query[i] == '\'' {
			if i+1 < len(query) && query[i+1] == '\'' {
				i++
				b.WriteByte(query[i])
				continue
			}
			return i + 1
		}
	}
	return len(query)
}

func copyDoubleQuoted(b *strings.Builder, query string, start int) int {
	for i := start; i < len(query); i++ {
		b.WriteByte(query[i])
		if query[i] == '"' {
			if i+1 < len(query) && query[i+1] == '"' {
				i++
				b.WriteByte(query[i])
				continue
			}
			return i + 1
		}
	}
	return len(query)
}

func copyLineComment(b *strings.Builder, query string, start int) int {
	for i := start; i < len(query); i++ {
		b.WriteByte(query[i])
		if query[i] == '\n' {
			return i + 1
		}
	}
	return len(query)
}

func copyBlockComment(b *strings.Builder, query string, start int) int {
	for i := start; i < len(query); i++ {
		b.WriteByte(query[i])
		if i+1 < len(query) && query[i] == '*' && query[i+1] == '/' {
			i++
			b.WriteByte(query[i])
			return i + 1
		}
	}
	return len(query)
}

func readDollarQuoteTag(query string, start int) (string, bool) {
	end := start + 1
	for end < len(query) {
		ch := query[end]
		if ch == '$' {
			return query[start : end+1], true
		}
		if !(ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
			return "", false
		}
		end++
	}
	return "", false
}

func copyDollarQuoted(b *strings.Builder, query string, start int, tag string) int {
	end := strings.Index(query[start+len(tag):], tag)
	if end < 0 {
		b.WriteString(query[start:])
		return len(query)
	}
	next := start + len(tag) + end + len(tag)
	_, _ = io.WriteString(b, query[start:next])
	return next
}
