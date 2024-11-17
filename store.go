package sqlstore

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

type Statements struct {
	Upsert *sql.Stmt
	Delete *sql.Stmt
	Select *sql.Stmt
}

type Store struct {
	statements Statements
	Codecs     []securecookie.Codec
	Options    *sessions.Options
}

func NewSqlStore(db *sql.DB, stmts Statements, keyPairs ...[]byte) *Store {
	return &Store{
		statements: stmts,
		Codecs:     securecookie.CodecsFromPairs(keyPairs...),
		Options:    &sessions.Options{},
	}
}

// Get should return a cached session.
func (m *Store) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(m, name)
}

// New should create and return a new session.
//
// Note that New should never return a nil session, even in the case of
// an error if using the Registry infrastructure to cache the session.
func (s *Store) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true

	var err error

	c, errCookie := r.Cookie(name)
	if errCookie != nil {
		return session, nil
	}

	err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...)
	if err != nil {
		return session, fmt.Errorf("Failed to decode session id: %w", err)
	}

	var sessionValue string
	err = s.statements.Select.QueryRow(session.ID).Scan(&sessionValue)
	if err != nil {
		return session, fmt.Errorf("Failed to db select session value: %w", err)
	}

	err = securecookie.DecodeMulti(name, string(sessionValue), &session.Values, s.Codecs...)
	if err == nil {
		session.IsNew = false
	}

	return session, err
}

// Save should persist session to the underlying store implementation.
func (s *Store) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	// Delete if max-age is <= 0
	if session.Options.MaxAge <= 0 {
		_, err := s.statements.Delete.Exec(session.ID)
		if err != nil {
			return fmt.Errorf("Failed to delete cookie: %w", err)
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		return nil
	}

	encodedValues, err := securecookie.EncodeMulti(session.Name(), session.Values,
		s.Codecs...)
	if err != nil {
		return fmt.Errorf("Failed to encode cookie value: %w", err)
	}

	result, err := s.statements.Upsert.Exec(encodedValues)
	if err != nil {
		return fmt.Errorf("Failed to db insert cookie: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("Failed to fetch last insert ID: %w", err)
	}

	idString := strconv.FormatInt(id, 10)

	encodedId, err := securecookie.EncodeMulti(session.Name(), idString,
		s.Codecs...)
	if err != nil {
		return fmt.Errorf("Failed to encode cookie id: %w", err)
	}

	http.SetCookie(w, sessions.NewCookie(session.Name(), encodedId, session.Options))

	return nil
}
