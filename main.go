package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/alecthomas/kong"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jedib0t/go-pretty/v6/table"
	_ "modernc.org/sqlite"
)

const (
	AuthEndpoint = "/auth"
	JWKSEndpoint = "/.well-known/jwks.json"
)

type (
	grammar struct {
		Project1 Project1Cmd `name:"project1" cmd:"" help:"Run the Project 1 checkers."`
		Project2 Project2Cmd `name:"project2" cmd:"" help:"Run the Project 2 checkers."`
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
	t.AppendHeader(table.Row{"Rubric Item", "Error?", "Points Awarded"})
	t.SetStyle(table.StyleRounded)

	var (
		possiblePoints int
		totalPoints    int
	)
	for i := range results {
		t.AppendRow([]any{results[i].label, results[i].message, results[i].awarded})
		possiblePoints += results[i].possible
		totalPoints += results[i].awarded
	}
	t.AppendFooter(table.Row{"", "Possible", possiblePoints})
	t.AppendFooter(table.Row{"", "Awarded", totalPoints})
	fmt.Println(t.Render())
}

//region Checkers

func CheckDatabaseExists(c *Context) (Result, error) {
	result := Result{
		label:    "Database exists",
		awarded:  0,
		possible: 15,
	}
	if _, err := os.Stat(c.databaseFile); err != nil {
		result.message = err.Error()
		return result, err
	}
	result.awarded += 5

	db, err := sql.Open("sqlite", c.databaseFile)
	if err != nil {
		result.message = err.Error()
		return result, err
	}
	rows, err := db.Query("SELECT * FROM keys")
	if err != nil {
		return result, err
	}
	var (
		validKey   bool
		expiredKey bool
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
		slog.Debug("Found key in DB",
			slog.Int("kid", kid),
			slog.String("key", trimPEMKey(key)),
			slog.Int64("exp", exp),
		)
		if t := time.Unix(exp, 0); time.Now().After(t) {
			expiredKey = true
		} else {
			validKey = true
		}
	}
	if validKey {
		result.awarded += 5
		slog.Debug("Valid key found in DB", slog.Int("pts", 5))
	}
	if expiredKey {
		result.awarded += 5
		slog.Debug("Expired key found in DB", slog.Int("pts", 5))
	}

	return result, nil
}

func trimPEMKey(key string) string {
	key = strings.ReplaceAll(key, "\n", "")
	key = strings.ReplaceAll(key, "\r", "")
	key = strings.ReplaceAll(key, "\t", "")
	key = strings.ReplaceAll(key, " ", "")
	key = strings.TrimLeft(key, "-----BEGIN RSA PRIVATE KEY-----")
	key = strings.TrimRight(key, "-----END RSA PRIVATE KEY-----")

	return key[0:15] + "..." + key[len(key)-15:]
}

var parameterizedInsertion = regexp.MustCompile(`INSERT *INTO *keys\((kid, *)*key, *exp\) *values\((\?, *)*\?, *\?\)`)

func CheckDatabaseQueryUsesParameters(c *Context) (Result, error) {
	result := Result{
		label:    "Database query uses parameters",
		awarded:  0,
		possible: 15,
	}

	if err := fs.WalkDir(os.DirFS(c.srcDir), ".", func(p string, d fs.DirEntry, err error) error {
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

func CheckValidJWT(r *Context) (Result, error) {
	result := Result{
		label:    "/auth valid JWT authN",
		awarded:  0,
		possible: 15,
	}
	var err error
	if r.validJWT, err = authentication(r.hostURL, false); err != nil && !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		result.message = err.Error()
		return result, err
	}
	result.awarded += 15
	slog.Debug("Valid JWT", slog.Int("pts", 15))

	return result, nil
}

func CheckExpiredJWT(r *Context) (Result, error) {
	result := Result{
		label:    "/auth?expired=true JWT authN (expired)",
		awarded:  0,
		possible: 5,
	}

	var err error
	r.expiredJWT, err = authentication(r.hostURL, true)
	if r.expiredJWT == nil {
		result.message = "expected expired JWT to exist"
		return result, fmt.Errorf("expected expired JWT to exist")
	} else if err == nil {
		result.message = "expected expired JWT to error"
		return result, fmt.Errorf("expected expired JWT to error")
	} else if r.expiredJWT.Valid {
		result.message = "expected expired JWT to be invalid"
		return result, fmt.Errorf("expected expired JWT to be invalid")
	}
	result.awarded += 5
	slog.Debug("Expired JWT", slog.Int("pts", 5))

	return result, nil
}

func CheckProperHTTPMethodsAndStatusCodes(ctx *Context) (Result, error) {
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
			req, err := http.NewRequest(method, ctx.hostURL+endpoint, http.NoBody)
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

func CheckValidJWKFoundInJWKS(r *Context) (Result, error) {
	result := Result{
		label:    "Valid JWK found in JWKS",
		awarded:  0,
		possible: 20,
	}
	if r.validJWT == nil {
		result.message = "no valid JWT found"
		return result, fmt.Errorf("no valid JWT found")
	}

	jwks, err := keyfunc.Get(r.hostURL+JWKSEndpoint, keyfunc.Options{})
	if err != nil {
		result.message = err.Error()
		return result, fmt.Errorf("JWKS: %w", err)
	}

	token, err := jwt.ParseWithClaims(r.validJWT.Raw, &jwt.RegisteredClaims{}, jwks.Keyfunc)
	if err != nil {
		result.message = err.Error()
		return result, fmt.Errorf("failed to validate token: %w", err)
	}

	result.awarded += 20
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		printJWT("Valid", token)
	}
	slog.Debug("Valid JWK found in JWKS", slog.Int("pts", 20))

	return result, nil
}

func CheckExpiredJWTIsExpired(r *Context) (Result, error) {
	result := Result{
		label:    "Expired JWT is expired",
		awarded:  0,
		possible: 5,
	}
	if r.expiredJWT == nil {
		result.message = "no expired JWT found"
		return result, fmt.Errorf("no expired JWT found")
	}
	expiry, err := r.expiredJWT.Claims.GetExpirationTime()
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
		printJWT("Expired", r.expiredJWT)
	}
	slog.Debug("Expired JWT actually expired", slog.Int("pts", 5))

	return result, nil
}

func CheckExpiredJWKNotFoundInJWKS(r *Context) (Result, error) {
	result := Result{
		label:    "Expired JWK does not exist in JWKS",
		awarded:  0,
		possible: 10,
	}
	if r.expiredJWT == nil {
		result.message = "no expired JWT found"
		return result, fmt.Errorf("no expired JWT found")
	}

	jwks, err := keyfunc.Get(r.hostURL+JWKSEndpoint, keyfunc.Options{})
	if err != nil {
		result.message = err.Error()
		return result, fmt.Errorf("JWKS error: %w", err)
	}

	_, err = jwt.ParseWithClaims(r.expiredJWT.Raw, &jwt.RegisteredClaims{}, jwks.Keyfunc)
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

func authentication(hostURL string, expired bool) (*jwt.Token, error) {
	req, err := http.NewRequest(http.MethodPost, hostURL+AuthEndpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	if expired {
		q := req.URL.Query()
		q.Add("expired", "true")
		req.URL.RawQuery = q.Encode()
	}
	client := http.Client{
		Transport: http.DefaultTransport,
		Timeout:   2 * time.Second, // extra generous timeout for slower languages.
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, fmt.Errorf("error authenticating: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return jwt.ParseWithClaims(string(body), &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return token, nil
	})
}
