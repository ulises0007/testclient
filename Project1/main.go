package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/alecthomas/kong"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jedib0t/go-pretty/v6/table"
)

const (
	AuthEndpoint = "/auth"
	JWKSEndpoint = "/.well-known/jwks.json"
)

type grammar struct {
	Port  int  `env:"PORT" short:"p" help:"Port to check." default:"8080"`
	Debug bool `help:"Debug output."`
	Total bool `help:"Print total only"`
}

func main() {
	var cli grammar
	if err := kong.Parse(&cli).Run(); err != nil {
		slog.Error("error running gradebot", slog.String("err", err.Error()))
	}
}

type (
	Context struct {
		hostURL    string
		validJWT   *jwt.Token
		expiredJWT *jwt.Token
	}
	Check  func(*Context) (Result, error)
	Result struct {
		label    string
		awarded  int
		possible int
		message  string
	}
)

func (g grammar) Run() error {
	// Set up logging.
	lvl := new(slog.LevelVar)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: lvl,
	}))
	if g.Debug {
		lvl.Set(slog.LevelDebug)
	}
	if g.Total {
		lvl.Set(10)
	}
	slog.SetDefault(logger)

	var (
		rubric  Context
		results = make([]Result, 0)
	)
	rubric.hostURL = fmt.Sprintf("http://127.0.0.1:%d", g.Port)
	for _, check := range []Check{
		CheckAuthentication,
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

	if g.Total {
		totalPoints := 0
		for i := range results {
			totalPoints += results[i].awarded
		}
		fmt.Println(totalPoints)
		return nil
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

	return nil
}

func CheckAuthentication(r *Context) (Result, error) {
	result := Result{
		label:    "/auth JWT authN",
		awarded:  0,
		possible: 20,
	}
	var err error
	if r.validJWT, err = authentication(r.hostURL, false); err != nil && !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		result.message = err.Error()
		return result, err
	}
	result.awarded += 15
	slog.Debug("Valid JWT", slog.Int("pts", 15))

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
	if expiry.After(time.Now()) {
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
