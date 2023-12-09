package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/alecthomas/kong"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

const (
	RegistrationEndpoint = "/register"
	AuthEndpoint         = "/auth"
	JWKSEndpoint         = "/.well-known/jwks.json"
	Username             = "userABC"
	Password             = "password123"
)

type (
	grammar struct {
		Project1 Project1Cmd `name:"project1" cmd:"" help:"Run the Project 1 checkers."`
		Project2 Project2Cmd `name:"project2" cmd:"" help:"Run the Project 2 checkers."`
		Project3 Project3Cmd `name:"project3" cmd:"" help:"Run the Project 3 checkers."`
	}
	options struct {
		Port  int  `env:"PORT" short:"p" help:"Port to check." default:"8080"`
		Debug bool `help:"Debug output."`
		Total bool `help:"Print total only"`
	}
	Project1Cmd struct {
		options
	}
	Project2Cmd struct {
		options
		DatabaseFile string `help:"Path to the database file."         default:"totally_not_my_privateKeys.db"`
		CodeDir      string `help:"Path to the source code directory." default:"."`
	}
	Project3Cmd struct {
		options
		DatabaseFile string `help:"Path to the database file."         default:"totally_not_my_privateKeys.db"`
		CodeDir      string `help:"Path to the source code directory." default:"."`
	}
)

func main() {
	var cli grammar
	if err := kong.Parse(&cli,
		kong.Name("gradebot"),
		kong.Description("Gradebot 9000 is a tool to grade your 3550 projects."),
		kong.UsageOnError(),
	).Run(); err != nil {
		slog.Error("error running gradebot", slog.String("err", err.Error()))
	}
	pauseForInput(os.Stdout, os.Stdin)
}

func pauseForInput(w io.Writer, r io.Reader) {
	_, _ = fmt.Fprintf(w, "press any key to continue...")
	input := bufio.NewScanner(r)
	input.Scan()
}

type (
	Context struct {
		hostURL      string
		validJWT     *jwt.Token
		expiredJWT   *jwt.Token
		username     string
		password     string
		databaseFile string
		srcDir       string
	}
	Check  func(*Context) (Result, error)
	Result struct {
		label    string
		awarded  int
		possible int
		message  string
	}
)

func (o *options) setup() {
	// Set up logging.
	lvl := new(slog.LevelVar)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: lvl,
	}))
	if o.Debug {
		lvl.Set(slog.LevelDebug)
	}
	if o.Total {
		lvl.Set(10)
	}
	slog.SetDefault(logger)
}

func (cmd Project1Cmd) Run() error {
	cmd.options.setup()

	var (
		rubric  Context
		results = make([]Result, 0)
	)
	rubric.hostURL = fmt.Sprintf("http://127.0.0.1:%d", cmd.Port)
	for _, check := range []Check{
		CheckValidJWT,
		CheckExpiredJWT,
		CheckProperHTTPMethodsAndStatusCodes,
		CheckValidJWKFoundInJWKS,
		CheckExpiredJWTIsExpired,
		CheckExpiredJWKNotFoundInJWKS,
	} {
		result, err := check(&rubric)
		if err != nil {
			slog.Error(result.label, slog.String("err", err.Error()))
		}
		results = append(results, result)
	}

	printRubricResults(cmd.Total, results...)

	return nil
}

func (cmd Project2Cmd) Run() error {
	cmd.options.setup()

	rubric := Context{
		databaseFile: cmd.DatabaseFile,
		srcDir:       cmd.CodeDir,
	}
	results := make([]Result, 0)
	rubric.hostURL = fmt.Sprintf("http://127.0.0.1:%d", cmd.Port)
	for _, check := range []Check{
		CheckValidJWT,
		CheckValidJWKFoundInJWKS,
		CheckDatabaseExists,
		CheckDatabaseQueryUsesParameters,
	} {
		result, err := check(&rubric)
		if err != nil {
			slog.Error(result.label, slog.String("err", err.Error()))
		}
		results = append(results, result)
	}

	printRubricResults(cmd.Total, results...)

	return nil
}

func (cmd Project3Cmd) Run() error {
	cmd.options.setup()

	rubric := Context{
		databaseFile: cmd.DatabaseFile,
		srcDir:       cmd.CodeDir,
		username:     "testor_" + uuid.NewString()[0:8],
	}
	slog.Debug("using username", slog.String("username", rubric.username))
	results := make([]Result, 0)
	rubric.hostURL = fmt.Sprintf("http://127.0.0.1:%d", cmd.Port)
	for _, check := range []Check{
		CheckTableExists("users", 5),
		CheckRegistrationWorks,
		CheckPrivateKeysAreEncrypted,
		CheckTableExists("auth_logs", 5),
		CheckAuthRequestsAreLogged,
		CheckEndpointIsRateLimited("/auth", 10),
	} {
		result, err := check(&rubric)
		if err != nil {
			slog.Error(result.label, slog.String("err", err.Error()))
		}
		results = append(results, result)
	}

	printRubricResults(cmd.Total, results...)

	return nil
}

func printRubricResults(onlyTotal bool, results ...Result) {
	if onlyTotal {
		totalPoints := 0
		for i := range results {
			totalPoints += results[i].awarded
		}
		fmt.Println(totalPoints)
		return
	}

	t := table.NewWriter()
	t.AppendHeader(table.Row{"Rubric Item", "Error?", "Possible", "Awarded"})
	t.SetStyle(table.StyleRounded)
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AlignFooter: text.AlignRight},
	})

	var (
		possiblePoints int
		totalPoints    int
	)
	for i := range results {
		t.AppendRow([]any{results[i].label, results[i].message, results[i].possible, results[i].awarded})
		possiblePoints += results[i].possible
		totalPoints += results[i].awarded
	}
	t.AppendFooter(table.Row{"", "Total", possiblePoints, totalPoints})
	fmt.Println(t.Render())
}

//region Checkers

func CheckDatabaseExists(c *Context) (result Result, err error) {
	result = Result{
		label:    "Database exists",
		awarded:  0,
		possible: 15,
	}
	messages := make([]string, 0)
	defer func() {
		result.message = strings.Join(messages, "\n")
	}()
	if _, err := os.Stat(c.databaseFile); err != nil {
		messages = append(messages, err.Error())
		return result, err
	}
	result.awarded += 5

	db, err := sql.Open("sqlite", c.databaseFile)
	if err != nil {
		messages = append(messages, err.Error())
		return result, err
	}
	rows, err := db.Query("SELECT * FROM keys")
	if err != nil {
		return result, err
	}
	var (
		validKey   bool
		expiredKey bool
		now        = time.Now().UTC()
	)
	for rows.Next() {
		var (
			kid int
			key string
			exp int64
		)
		if err := rows.Scan(&kid, &key, &exp); err != nil {
			return result, err
		}
		expiredAt := time.Unix(exp, 0)
		expired := now.After(expiredAt)
		slog.Debug("Found key in DB",
			slog.Int("kid", kid),
			slog.String("key", trimPEMKey(key)),
			slog.Int64("exp", exp),
			slog.String("expired_at", expiredAt.String()),
			slog.Bool("expired", expired),
		)
		if !expiredKey && expired {
			expiredKey = true
		} else if !validKey && !expired {
			validKey = true
		}
	}
	if validKey {
		result.awarded += 5
		slog.Debug("Valid priv key found in DB", slog.Int("pts", 5))
	} else {
		messages = append(messages, "no valid priv key found in DB")
	}
	if expiredKey {
		result.awarded += 5
		slog.Debug("Expired priv key found in DB", slog.Int("pts", 5))
	} else {
		messages = append(messages, "no expired priv key found in DB")
	}

	return result, nil
}

const (
	rsaPrefix = "-----BEGIN RSA PRIVATE KEY-----"
	rsaSuffix = "-----END RSA PRIVATE KEY-----"
)

func trimPEMKey(key string) string {
	key = strings.ReplaceAll(key, "\n", "")
	key = strings.ReplaceAll(key, "\r", "")
	key = strings.ReplaceAll(key, "\t", "")
	key = strings.ReplaceAll(key, " ", "")
	key = strings.TrimPrefix(key, rsaPrefix)
	key = strings.TrimSuffix(key, rsaSuffix)

	return key[0:15] + "..." + key[len(key)-15:]
}

var parameterizedInsertion = regexp.MustCompile(`(?i)INSERT *(OR *REPLACE *)?INTO *(?-i)keys(?i) *(\( *key, *exp *\) *VALUES *\(\?, *\? *\)|\( *kid, *key, *exp *\) *VALUES *\(\?, *\?, *\? *\))`)

func CheckDatabaseQueryUsesParameters(c *Context) (Result, error) {
	result := Result{
		label:    "Database query uses parameters",
		awarded:  0,
		possible: 15,
	}

	if err := fs.WalkDir(os.DirFS(c.srcDir), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(filepath.Join(c.srcDir, p))
		if err != nil {
			return err
		}
		lines := bytes.Split(b, []byte("\n"))
		for i, line := range lines {
			if parameterizedInsertion.Match(line) {
				slog.Debug("Found SQL insertion query", slog.String("file", p), slog.Int("line", i+1))
				result.awarded = 15
				break
			}
		}

		return nil
	}); err != nil {
		return result, err
	}
	if result.awarded == 0 {
		result.message = "No sources files found with SQL insertion parameters"
	}

	return result, nil
}

func CheckValidJWT(c *Context) (Result, error) {
	result := Result{
		label:    "/auth valid JWT authN",
		awarded:  0,
		possible: 15,
	}
	var err error
	if c.validJWT, err = authentication(c.hostURL, false); err != nil && !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		result.message = err.Error()
		return result, err
	}
	result.awarded += 15
	slog.Debug("Valid JWT", slog.Int("pts", 15))

	return result, nil
}

func CheckExpiredJWT(c *Context) (Result, error) {
	result := Result{
		label:    "/auth?expired=true JWT authN (expired)",
		awarded:  0,
		possible: 5,
	}

	t, err := authentication(c.hostURL, true)
	switch {
	case t == nil:
		result.message = "expected expired JWT to exist"
		return result, fmt.Errorf("expected expired JWT to exist")
	case t.Header == nil:
		result.message = "expected expired JWT header to exist"
		return result, fmt.Errorf("expected expired JWT header to exist")
	case err == nil:
		result.message = "expected expired JWT to error"
		return result, fmt.Errorf("expected expired JWT to error")
	case t.Valid:
		result.message = "expected expired JWT to be invalid"
		return result, fmt.Errorf("expected expired JWT to be invalid")
	default:
		c.expiredJWT = t
	}
	result.awarded += 5
	slog.Debug("Expired JWT", slog.Int("pts", 5))

	return result, nil
}

func CheckProperHTTPMethodsAndStatusCodes(c *Context) (Result, error) {
	result := Result{
		label:    "Proper HTTP methods/Status codes",
		awarded:  1, // free point to make the math even.
		possible: 10,
	}
	badMethods := map[string][]string{
		AuthEndpoint: {
			http.MethodGet,
			http.MethodPut,
			http.MethodDelete,
			http.MethodPatch,
			http.MethodHead,
		},
		JWKSEndpoint: {
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodPatch,
			//http.MethodHead, -> same as GET without body... foreshadowing Project 2
		},
	}
	client := http.Client{
		Transport: http.DefaultTransport,
		Timeout:   2 * time.Second, // extra generous timeout for slower languages.
	}
	for endpoint, methods := range badMethods {
		for _, method := range methods {
			logger := slog.With(
				slog.String("endpoint", endpoint),
				slog.String("method", method),
			)
			req, err := http.NewRequest(method, c.hostURL+endpoint, http.NoBody)
			if err != nil {
				logger.Error("could not create request", slog.String("err", err.Error()))
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				logger.Error("error in response", slog.String("err", err.Error()))
				continue
			}
			if resp.StatusCode != http.StatusMethodNotAllowed {
				logger.Debug(fmt.Sprintf("expected status code: %d, got %d", http.StatusMethodNotAllowed, resp.StatusCode))
				continue
			}
			logger.Debug("Proper HTTP Method and Status Code", slog.Int("pts", 1))
			result.awarded++
		}
	}
	if result.awarded > 0 {
		slog.Debug("All Proper HTTP Methods and Status Codes", slog.Int("pts", result.awarded))
	}

	return result, nil
}

func CheckValidJWKFoundInJWKS(c *Context) (Result, error) {
	result := Result{
		label:    "Valid JWK found in JWKS",
		awarded:  0,
		possible: 20,
	}
	if c.validJWT == nil {
		result.message = "no valid JWT found"
		return result, fmt.Errorf("no valid JWT found")
	}

	jwks, err := keyfunc.Get(c.hostURL+JWKSEndpoint, keyfunc.Options{})
	if err != nil {
		result.message = err.Error()
		return result, fmt.Errorf("JWKS: %w", err)
	}

	token, err := jwt.ParseWithClaims(c.validJWT.Raw, &jwt.RegisteredClaims{}, jwks.Keyfunc)
	if err != nil {
		result.message = err.Error()
		resp, err2 := http.Get(c.hostURL + JWKSEndpoint)
		if err2 != nil {
			return result, fmt.Errorf("failed to get JWKS endpoint: %w", err2)
		}
		b, _ := httputil.DumpResponse(resp, true)
		if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
			fmt.Println("JWKS Response:\n", string(b))
		}
		return result, fmt.Errorf("failed to validate token: %w", err)
	}

	result.awarded += 20
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		printJWT("Valid", token)
	}
	slog.Debug("Valid JWK found in JWKS", slog.Int("pts", 20))

	return result, nil
}

func CheckExpiredJWTIsExpired(c *Context) (Result, error) {
	result := Result{
		label:    "Expired JWT is expired",
		awarded:  0,
		possible: 5,
	}
	if c.expiredJWT == nil {
		result.message = "no expired JWT found"
		return result, fmt.Errorf("no expired JWT found")
	}
	expiry, err := c.expiredJWT.Claims.GetExpirationTime()
	if err != nil {
		result.message = err.Error()
		return result, fmt.Errorf("expected expired token to have an expiry")
	}
	if expiry == nil {
		err := errors.New("expected expired JWT to be returned for query param 'expired=true'")
		result.message = err.Error()
		return result, err
	}
	if expiry.After(time.Now()) {
		err := errors.New("expected expired token to have an expiry in the past")
		result.message = err.Error()
		return result, fmt.Errorf("expected expired token to have an expiry in the past")
	}
	result.awarded += 5
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		printJWT("Expired", c.expiredJWT)
	}
	slog.Debug("Expired JWT actually expired", slog.Int("pts", 5))

	return result, nil
}

func CheckExpiredJWKNotFoundInJWKS(c *Context) (Result, error) {
	result := Result{
		label:    "Expired JWK does not exist in JWKS",
		awarded:  0,
		possible: 10,
	}
	if c.expiredJWT == nil {
		result.message = "no expired JWT found"
		return result, fmt.Errorf("no expired JWT found")
	}

	jwks, err := keyfunc.Get(c.hostURL+JWKSEndpoint, keyfunc.Options{})
	if err != nil {
		result.message = err.Error()
		return result, fmt.Errorf("JWKS error: %w", err)
	}

	_, err = jwt.ParseWithClaims(c.expiredJWT.Raw, &jwt.RegisteredClaims{}, jwks.Keyfunc)
	switch {
	case errors.Is(err, keyfunc.ErrKIDNotFound):
		result.awarded += 10
		slog.Debug("Expired JWK KID does not exist in JWKS", slog.Int("pts", 10))
	case err != nil:
		result.message = err.Error()
		return result, fmt.Errorf("unexpected error: %w", err)
	default:
		result.message = "expected KID to not be found"
		return result, fmt.Errorf("expected KID to not be found")
	}

	return result, nil
}

type key struct {
	KID                  int64  `db:"kid"`
	EncipheredPrivateKey []byte `db:"key"`
	Expiration           int64  `db:"exp"`
}

func CheckPrivateKeysAreEncrypted(c *Context) (Result, error) {
	result := Result{
		label:    "Private Keys are encrypted in the database",
		awarded:  0,
		possible: 25,
	}

	keys, err := dbSelect[key](c, "keys", nil)
	if err != nil {
		result.message = err.Error()
		return result, err
	}
	if len(keys) == 0 {
		result.message = "no keys found in database"
		return result, nil
	}

	// check if any of the keys are not encrypted
	for _, k := range keys {
		if bytes.HasPrefix(bytes.TrimSpace(k.EncipheredPrivateKey), []byte(rsaPrefix)) {
			result.message = fmt.Sprintf("private key %v is not encrypted", k.KID)
			return result, nil
		}
	}

	result.awarded += 25

	return result, nil
}

func CheckTableExists(table string, points int) func(c *Context) (Result, error) {
	return func(c *Context) (Result, error) {
		result := Result{
			label:    fmt.Sprintf("Create %v table", table),
			awarded:  0,
			possible: points,
		}
		if _, err := os.Stat(c.databaseFile); err != nil {
			result.message = err.Error()
			return result, err
		}

		db, err := sqlx.Connect("sqlite", "file:"+c.databaseFile)
		if err != nil {
			result.message = err.Error()
			return result, err
		}
		defer func() {
			_ = db.Close()
		}()

		exists, err := tableExists(db, table)
		if exists {
			result.awarded += points
			slog.Debug("table exists", slog.String("table", table), slog.Int("pts", points))
			return result, nil
		}

		result.message = table + " table does not exist"
		if err != nil {
			result.message = err.Error()
			return result, err
		}

		return result, nil
	}
}

func CheckRegistrationWorks(c *Context) (Result, error) {
	result := Result{
		label:    "/register endpoint",
		awarded:  0,
		possible: 20,
	}

	resp, err := registration(c.hostURL, c.username)
	if err != nil {
		result.message = err.Error()
		return result, fmt.Errorf("error during registration: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		result.message = fmt.Sprintf("expected status code %d or %d, got %d", http.StatusOK, http.StatusCreated, resp.StatusCode)
		return result, nil
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		result.message = err.Error()
		return result, err
	}
	slog.Debug("registration response", slog.String("body", string(b)))
	var body struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		result.message = err.Error()
		return result, err
	}

	if body.Password != "" {
		result.awarded += 5
	}

	if _, err := uuid.Parse(body.Password); err != nil {
		result.message = "password is not a valid UUID"
		return result, err
	}

	u, err := dbGet[user](c, "users", "username", c.username)
	if err != nil {
		result.message = err.Error()
		return result, err
	}
	result.awarded += 5 // user exists

	if u.PasswordHash == "" {
		result.message = "password hash is empty"
		return result, err
	} else if u.PasswordHash == body.Password {
		return result, fmt.Errorf("password hash is same as password")
	}

	result.awarded += 10 // password hash is hashed (hopefully)
	c.password = body.Password

	return result, nil
}

type user struct {
	ID           int64      `db:"id"`
	Username     string     `db:"username"`
	PasswordHash string     `db:"password_hash"`
	Email        string     `db:"email"`
	RegisteredAt time.Time  `db:"date_registered"`
	LastLoginAt  *time.Time `db:"last_login"`
}

type authLog struct {
	ID        int64     `db:"id"`
	RequestIP string    `db:"request_ip"`
	RequestTS time.Time `db:"request_timestamp"`
	UserID    int64     `db:"user_id"`
}

func CheckAuthRequestsAreLogged(c *Context) (Result, error) {
	result := Result{
		label:    "/auth requests are logged",
		awarded:  0,
		possible: 10,
	}
	// initial request to get a valid JWT
	if resp, err := authenticationWithCreds(c.hostURL, c.username, c.password); err != nil {
		return result, err
	} else if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	user, err := dbGet[user](c, "users", "username", c.username)
	if err != nil {
		result.message = err.Error()
		return result, err
	}

	slog.Debug("using user ID for auth log", slog.Int64("user_id", user.ID))
	logs, err := dbSelect[authLog](c, "auth_logs", map[string]any{"user_id": user.ID})
	if err != nil {
		result.message = err.Error()
		return result, err
	}
	slog.Debug("logs found", slog.Int("count", len(logs)))
	if len(logs) == 0 {
		result.message = "no logs found"
		return result, nil
	}

	result.awarded += 5 // log exists
	slog.Debug("found auth log", slog.Any("log", logs[0]), slog.Int("pts", 5))

	switch {
	case logs[0].RequestIP == "":
		result.message = "request IP is empty"
	case logs[0].RequestTS.IsZero():
		result.message = "request timestamp is zero"
	}
	if result.message == "" {
		result.awarded += 5
	}

	return result, nil
}

func CheckEndpointIsRateLimited(endpoint string, rps int) func(c *Context) (Result, error) {
	return func(c *Context) (Result, error) {
		result := Result{
			label:    endpoint + " is rate-limited (optional)",
			awarded:  0,
			possible: 25,
		}

		// quiesce for a second to let the rate limit recover
		slog.Debug("quiescing for a second to let the rate limit recover")
		time.Sleep(time.Second)
		ticker := time.NewTicker(time.Second / time.Duration(rps))
		defer ticker.Stop()
		// do requests that should not error
		start := time.Now()
		for i := rps; i > 0; i-- {
			<-ticker.C
			resp, err := authenticationWithCreds(c.hostURL, c.username, c.password)
			if err != nil {
				return result, err
			}
			slog.Debug("pumping rate-limit request",
				slog.Int("count", i),
				slog.Any("diff", time.Since(start)),
				slog.Int("status", resp.StatusCode),
			)
			if resp.StatusCode != http.StatusOK {
				return result, fmt.Errorf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
			}
		}

		// done pumping rate limiter
		slog.Debug("done pumping rate limiter", slog.Any("diff", time.Since(start)))
		resp, err := authenticationWithCreds(c.hostURL, c.username, c.password)
		if err != nil {
			return result, err
		}
		slog.Debug("rate-limited request",
			slog.Any("diff", time.Since(start)),
			slog.Int("status", resp.StatusCode),
		)
		if resp.StatusCode != http.StatusTooManyRequests {
			return result, fmt.Errorf("expected status code %d, got %d", http.StatusTooManyRequests, resp.StatusCode)
		}

		result.awarded += 25 // rate-limited

		return result, nil
	}
}

//endregion

func printJWT(name string, token *jwt.Token) {
	fmt.Printf("\t%v JWT valid: %v\n", name, token.Valid)
	fmt.Printf("\t%v JWT Header: %#v\n", name, token.Header)
	claims := token.Claims.(*jwt.RegisteredClaims)
	if claims.Issuer != "" {
		fmt.Printf("\t%v JWT Issuer: %v\n", name, claims.Issuer)
	}
	if claims.Subject != "" {
		fmt.Printf("\t%v JWT Subject: %v\n", name, claims.Subject)
	}
	if claims.Audience != nil {
		fmt.Printf("\t%v JWT Audience: %v\n", name, claims.Audience)
	}
	if !claims.ExpiresAt.IsZero() {
		fmt.Printf("\t%v JWT ExpiresAt: %v\n", name, claims.ExpiresAt)
	}
	if claims.NotBefore != nil {
		fmt.Printf("\t%v JWT NotBefore: %v\n", name, claims.NotBefore)
	}
	if claims.IssuedAt != nil {
		fmt.Printf("\t%v JWT IssuedAt: %v\n", name, claims.IssuedAt)
	}
	if claims.ID != "" {
		fmt.Printf("\t%v JWT ID: %v\n", name, claims.ID)
	}
}

func registration(hostURL, username string) (*http.Response, error) {
	payload := map[string]string{
		"username": username,
		"email":    username + "@test.com",
	}
	var bb bytes.Buffer
	if err := json.NewEncoder(&bb).Encode(payload); err != nil {
		return nil, err
	}
	slog.Debug("registration request", slog.Any("body", payload))
	req, err := http.NewRequest(http.MethodPost, hostURL+RegistrationEndpoint, &bb)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Type", "application/json")

	client := http.Client{
		Transport: http.DefaultTransport,
		Timeout:   2 * time.Second, // extra generous timeout for slower languages.
	}

	return client.Do(req)
}

func authenticationWithCreds(hostURL, username, password string) (*http.Response, error) {
	var bb bytes.Buffer
	if err := json.NewEncoder(&bb).Encode(map[string]string{
		"username": username,
		"password": password,
	}); err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, hostURL+AuthEndpoint, &bb)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Type", "application/json")

	client := http.Client{
		Transport: http.DefaultTransport,
		Timeout:   2 * time.Second, // extra generous timeout for slower languages.
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	return resp, nil
}

func authentication(hostURL string, expired bool) (*jwt.Token, error) {
	// try post form + basic auth
	resp, err := autheticatePostForm(hostURL, expired)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// try post json
		resp, err = autheticatePostJSON(hostURL, expired)
		if err != nil {
			return nil, err
		}
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	slog.Debug("Received POST:/auth body", slog.Int("status", resp.StatusCode), slog.String("body", string(body)))
	var jsonBody struct {
		JWT   string `json:"jwt"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &jsonBody); err == nil {
		// Must not be JSON, try to parse as JWT
		switch {
		case jsonBody.JWT != "":
			return jwt.ParseWithClaims(jsonBody.JWT, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
				return token, nil
			})
		case jsonBody.Token != "":
			return jwt.ParseWithClaims(jsonBody.Token, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
				return token, nil
			})
		default:
		}
	}

	if len(strings.Split(string(body), ".")) != 3 {
		return nil, errors.New(`no JWT found in response. Tried raw, JSON["jwt"] and JSON["token"]`)
	}

	return jwt.ParseWithClaims(string(body), &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		return token, nil
	})
}

func autheticatePostJSON(hostURL string, expired bool) (*http.Response, error) {
	var bb bytes.Buffer
	if err := json.NewEncoder(&bb).Encode(struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{
		Username: Username,
		Password: Password,
	}); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, hostURL+AuthEndpoint, &bb)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Type", "application/json")
	if expired {
		q := req.URL.Query()
		q.Add("expired", "true")
		req.URL.RawQuery = q.Encode()
	}

	client := http.Client{
		Transport: http.DefaultTransport,
		Timeout:   2 * time.Second, // extra generous timeout for slower languages.
	}

	return client.Do(req)
}

func autheticatePostForm(hostURL string, expired bool) (*http.Response, error) {
	data := url.Values{}
	data.Set("username", Username)
	data.Set("password", Password)

	req, err := http.NewRequest(http.MethodPost, hostURL+AuthEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.SetBasicAuth(Username, Password)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Type", "application/json")
	if expired {
		q := req.URL.Query()
		q.Add("expired", "true")
		req.URL.RawQuery = q.Encode()
	}

	client := http.Client{
		Transport: http.DefaultTransport,
		Timeout:   2 * time.Second, // extra generous timeout for slower languages.
	}

	return client.Do(req)
}

func tableExists(db *sqlx.DB, tableName string) (bool, error) {
	var name string
	if err := db.Get(&name, "SELECT name FROM sqlite_master WHERE type='table' AND name=?", tableName); errors.Is(err, sql.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
}

func dbGet[T any](c *Context, table, field string, value any) (*T, error) {
	db, err := sqlx.Connect("sqlite", "file:"+c.databaseFile)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = db.Close()
	}()

	var t T
	query := fmt.Sprintf(`SELECT * FROM %s WHERE %s=?`, table, field)
	if err := db.Get(&t, query, value); err != nil {
		return nil, err
	}

	return &t, nil
}

func dbSelect[T any](c *Context, table string, where map[string]any) ([]T, error) {
	db, err := sqlx.Connect("sqlite", "file:"+c.databaseFile)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = db.Close()
	}()

	keys := make([]string, 0)
	values := make([]any, 0)
	for k, v := range where {
		keys = append(keys, k)
		values = append(values, v)
	}
	query := "SELECT * FROM " + table
	if len(keys) > 0 {
		query += " WHERE "
		for i := range keys {
			if i > 0 && i < len(keys) {
				query += " AND "
			}
			query += keys[i] + "=?"
		}
	}

	var t []T
	if err := db.Select(&t, query, values...); err != nil {
		return t, err
	}

	return t, nil
}
