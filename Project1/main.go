package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

const (
	hostURL      = "http://127.0.0.1:8080"
	AuthEndpoint = "/auth"
	JWKSEndpoint = "/.well-known/jwks.json"
)

type Rubric struct {
	Authentication                  int
	ProperHTTPMethodsAndStatusCodes int
	ValidJWKFoundInJWKS             int
	ExpiredJWTIsExpired             int
	ExpiredJWKNotFoundInJWKS        int

	AwardedPoints int

	validJWT      *jwt.Token
	expiredJWT    *jwt.Token
	expiredJWTErr error
}

func (r Rubric) AvailablePoints() int {
	return r.Authentication +
		r.ProperHTTPMethodsAndStatusCodes +
		r.ValidJWKFoundInJWKS +
		r.ExpiredJWTIsExpired +
		r.ExpiredJWKNotFoundInJWKS
}

func main() {
	rubric := Rubric{
		Authentication:                  20,
		ProperHTTPMethodsAndStatusCodes: 10,
		ValidJWKFoundInJWKS:             20,
		ExpiredJWTIsExpired:             5,
		ExpiredJWKNotFoundInJWKS:        10,
	}
	var err error
	defer func() {
		fmt.Printf("Awarded %d/%d points.\n", rubric.AwardedPoints, rubric.AvailablePoints())
	}()
	for _, check := range []func(*Rubric) error{
		CheckAuthentication,
		CheckProperHTTPMethodsAndStatusCodes,
		CheckValidJWKFoundInJWKS,
		CheckExpiredJWTIsExpired,
		CheckExpiredJWKNotFoundInJWKS,
	} {
		if err = check(&rubric); err != nil {
			pathing := strings.Split(runtime.FuncForPC(reflect.ValueOf(check).Pointer()).Name(), ".")
			test := strings.TrimLeft(pathing[len(pathing)-1], "Check")
			fmt.Printf("error running test '%v': %v\n", test, err)
		}
	}
}

func CheckAuthentication(r *Rubric) error {
	var err error
	if r.validJWT, err = authentication(false); err != nil && !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		return err
	}
	r.AwardedPoints += 15
	fmt.Println("Valid JWT: +15")

	r.expiredJWT, r.expiredJWTErr = authentication(true)
	if r.expiredJWTErr == nil || r.expiredJWT.Valid {
		return fmt.Errorf("expected expired JWT, got nil")
	}
	r.AwardedPoints += 5
	fmt.Println("Expired JWT: +5")

	return nil
}

func CheckProperHTTPMethodsAndStatusCodes(r *Rubric) error {
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
			http.MethodHead,
		},
	}
	for endpoint, methods := range badMethods {
		for _, method := range methods {
			req, err := http.NewRequest(method, hostURL+endpoint, http.NoBody)
			if err != nil {
				continue
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				continue
			}
			if resp.StatusCode != http.StatusMethodNotAllowed {
				fmt.Printf("%v: expected status code %d for %v, got %d\n", endpoint, http.StatusMethodNotAllowed, method, resp.StatusCode)
				continue
			}
			r.AwardedPoints++
		}
	}
	if r.AwardedPoints > 0 {
		fmt.Printf("Proper HTTP Methods and Status Codes: +%d\n", r.AwardedPoints)
	}

	return nil
}

func CheckValidJWKFoundInJWKS(r *Rubric) error {
	if r.validJWT == nil {
		return fmt.Errorf("no valid JWT found")
	}

	jwks, err := keyfunc.Get(hostURL+JWKSEndpoint, keyfunc.Options{})
	if err != nil {
		return fmt.Errorf("JWKS: %w", err)
	}

	token, err := jwt.ParseWithClaims(r.validJWT.Raw, &jwt.RegisteredClaims{}, jwks.Keyfunc)
	if err != nil {
		return fmt.Errorf("failed to validate token: %w", err)
	}

	r.AwardedPoints += 20
	fmt.Println("Valid JWK found in JWKS: +20")
	printJWT("Valid", token)

	return nil
}

func CheckExpiredJWTIsExpired(r *Rubric) error {
	if r.expiredJWT == nil {
		return fmt.Errorf("no expired JWT found")
	}
	expiry, err := r.expiredJWT.Claims.GetExpirationTime()
	if err != nil {
		return fmt.Errorf("expected expired token to have an expiry")
	}
	if expiry.After(time.Now()) {
		return fmt.Errorf("expected expired token to have an expiry in the past")
	}
	r.AwardedPoints += 5
	fmt.Println("Expired JWT actually expired: +5")

	return nil
}

func CheckExpiredJWKNotFoundInJWKS(r *Rubric) error {
	if r.expiredJWT == nil {
		return fmt.Errorf("no expired JWT found")
	}

	jwks, err := keyfunc.Get(hostURL+JWKSEndpoint, keyfunc.Options{})
	if err != nil {
		return fmt.Errorf("JWKS error: %w", err)
	}

	token, err := jwt.ParseWithClaims(r.expiredJWT.Raw, &jwt.RegisteredClaims{}, jwks.Keyfunc)

	switch {
	case errors.Is(err, keyfunc.ErrKIDNotFound):
		// no-op because this is expected
	case err != nil:
		return fmt.Errorf("unexpected error: %w", err)
	default:
		return fmt.Errorf("expected KID to not be found: %w", err)
	}

	r.AwardedPoints += 10
	printJWT("Expired", token)
	fmt.Println("Expired JWT KID Not Found in JWKS: +15")

	return nil
}

func printJWT(name string, token *jwt.Token) {
	fmt.Printf("\t%v JWT valid: %v\n", name, token.Valid)
	fmt.Printf("\t%v JWT header: %v\n", name, token.Header)
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

func authentication(expired bool) (*jwt.Token, error) {
	req, err := http.NewRequest(http.MethodPost, hostURL+AuthEndpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	if expired {
		q := req.URL.Query()
		q.Add("expired", "true")
		req.URL.RawQuery = q.Encode()
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, fmt.Errorf("error authenticating: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return jwt.ParseWithClaims(string(body), &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return token, nil
	})
}
