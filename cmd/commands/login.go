package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

// NewLoginCmd returns a cmd used for login
func NewLoginCmd() *cobra.Command {

	var (
		a         app
		sso       bool
		issuerURL string
		listen    string
	)

	loginCmd := cobra.Command{
		Use:   "login",
		Short: "use this for login",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return errors.New("surplus arguments provided")
			}

			u, err := url.Parse(a.redirectURI)
			if err != nil {
				return fmt.Errorf("parse redirect-uri: %v", err)
			}
			listenURL, err := url.Parse(listen)
			if err != nil {
				return fmt.Errorf("parse listen address: %v", err)
			}

			if a.client == nil {
				a.client = http.DefaultClient
			}

			ctx := oidc.ClientContext(context.Background(), a.client)
			provider, err := oidc.NewProvider(ctx, issuerURL)
			if err != nil {
				return fmt.Errorf("failed to query provider %q: %v", issuerURL, err)
			}

			var s struct {
				// What scopes does a provider support?
				//
				// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
				ScopesSupported []string `json:"scopes_supported"`
			}
			if err := provider.Claims(&s); err != nil {
				return fmt.Errorf("failed to parse provider scopes_supported: %v", err)
			}

			if len(s.ScopesSupported) == 0 {
				// scopes_supported is a "RECOMMENDED" discovery claim, not a required
				// one. If missing, assume that the provider follows the spec and has
				// an "offline_access" scope.
				a.offlineAsScope = true
			} else {
				// See if scopes_supported has the "offline_access" scope.
				a.offlineAsScope = func() bool {
					for _, scope := range s.ScopesSupported {
						if scope == oidc.ScopeOfflineAccess {
							return true
						}
					}
					return false
				}()
			}

			a.provider = provider
			a.verifier = provider.Verifier(&oidc.Config{ClientID: a.clientID})

			authURL, err := a.authCodeURL()
			if err != nil {
				return err
			}

			fmt.Printf("\nOpen: %s\n\n", authURL)

			err = openbrowser(authURL)
			if err != nil {
				return err
			}

			a.errChan = make(chan error)

			http.HandleFunc(u.Path, a.handleCallback)
			go func() {
				log.Printf("listening on %s", listen)
				err := http.ListenAndServe(listenURL.Host, nil)
				if err != nil {
					log.Fatal(err)
				}
			}()

			err = <-a.errChan
			if err != nil {
				return err
			}

			return nil
		},
	}

	loginCmd.Flags().BoolVar(&sso, "sso", false, "If it is true, then use oauth2 flow to login")
	loginCmd.Flags().StringVar(&a.clientID, "client-id", "example-app", "OAuth2 client ID of this application.")
	loginCmd.Flags().StringVar(&a.clientSecret, "client-secret", "ZXhhbXBsZS1hcHAtc2VjcmV0", "OAuth2 client secret of this application.")
	loginCmd.Flags().StringVar(&a.redirectURI, "redirect-uri", "http://127.0.0.1:8085/callback", "Callback URL for OAuth2 responses.")
	loginCmd.Flags().StringArrayVar(&a.extraScopes, "scope", []string{}, "extra scopes for ouath2 url code request")
	loginCmd.Flags().BoolVar(&a.offlineAccess, "offline-access", true, "If it is true, token for offline access will be granted")
	loginCmd.Flags().StringVar(&issuerURL, "issuer", "http://127.0.0.1:5556/dex", "URL of the OpenID Connect issuer.")
	loginCmd.Flags().StringVar(&listen, "listen", "http://127.0.0.1:8085", "HTTP address to listen at.")

	return &loginCmd
}

func openbrowser(url string) error {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}

	return err
}

const appState = "I wish to wash my irish wristwatch"

type app struct {
	clientID     string
	clientSecret string
	redirectURI  string

	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider

	extraScopes []string

	// Does the provider use "offline_access" scope to request a refresh token
	// or does it use "access_type=offline" (e.g. Google)?
	offlineAsScope bool
	offlineAccess  bool

	client *http.Client

	errChan chan error
}

func (a *app) oauth2Config(scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		Endpoint:     a.provider.Endpoint(),
		Scopes:       scopes,
		RedirectURL:  a.redirectURI,
	}
}

func (a *app) authCodeURL() (string, error) {

	authCodeURL := ""
	scopes := append(a.extraScopes, "openid", "profile", "email")

	if !a.offlineAccess {
		authCodeURL = a.oauth2Config(scopes).AuthCodeURL(appState)
	} else if a.offlineAsScope {
		scopes = append(scopes, "offline_access")
		authCodeURL = a.oauth2Config(scopes).AuthCodeURL(appState)
	} else {
		authCodeURL = a.oauth2Config(scopes).AuthCodeURL(appState, oauth2.AccessTypeOffline)
	}

	return authCodeURL, nil
}

func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	var (
		err   error
		token *oauth2.Token
	)

	ctx := oidc.ClientContext(r.Context(), a.client)
	oauth2Config := a.oauth2Config(nil)
	switch r.Method {
	case http.MethodGet:
		// Authorization redirect callback from OAuth2 auth flow.
		if errMsg := r.FormValue("error"); errMsg != "" {
			http.Error(w, errMsg+": "+r.FormValue("error_description"), http.StatusBadRequest)
			a.errChan <- fmt.Errorf(r.FormValue("error_description"))
			return
		}
		code := r.FormValue("code")
		if code == "" {
			http.Error(w, fmt.Sprintf("no code in request: %q", r.Form), http.StatusBadRequest)
			a.errChan <- fmt.Errorf("no code in request: %q", r.Form)
			return
		}

		if state := r.FormValue("state"); state != appState {
			http.Error(w, fmt.Sprintf("expected state %q got %q", appState, state), http.StatusBadRequest)
			a.errChan <- fmt.Errorf("expected state %q got %q", appState, state)
			return
		}
		token, err = oauth2Config.Exchange(ctx, code)
	case http.MethodPost:
		// Form request from frontend to refresh a token.
		refresh := r.FormValue("refresh_token")
		if refresh == "" {
			http.Error(w, fmt.Sprintf("no refresh_token in request: %q", r.Form), http.StatusBadRequest)
			a.errChan <- fmt.Errorf("no refresh_token in request: %q", r.Form)
			return
		}
		t := &oauth2.Token{
			RefreshToken: refresh,
			Expiry:       time.Now().Add(-time.Hour),
		}
		token, err = oauth2Config.TokenSource(ctx, t).Token()
	default:
		http.Error(w, fmt.Sprintf("method not implemented: %s", r.Method), http.StatusBadRequest)
		a.errChan <- fmt.Errorf("method not implemented: %s", r.Method)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get token: %v", err), http.StatusInternalServerError)
		a.errChan <- fmt.Errorf("failed to get token: %v", err)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusInternalServerError)
		a.errChan <- fmt.Errorf("no id_token in token response")
		return
	}

	idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to verify ID token: %v", err), http.StatusInternalServerError)
		a.errChan <- fmt.Errorf("failed to verify ID token: %v", err)
		return
	}

	accessToken, ok := token.Extra("access_token").(string)
	if !ok {
		http.Error(w, "no access_token in token response", http.StatusInternalServerError)
		a.errChan <- fmt.Errorf("no access_token in token response")
		return
	}

	var claims json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, fmt.Sprintf("error decoding ID token claims: %v", err), http.StatusInternalServerError)
		a.errChan <- fmt.Errorf("error decoding ID token claims: %v", err)
		return
	}

	buff := new(bytes.Buffer)
	if err := json.Indent(buff, []byte(claims), "", "  "); err != nil {
		http.Error(w, fmt.Sprintf("error indenting ID token claims: %v", err), http.StatusInternalServerError)
		a.errChan <- fmt.Errorf("error indenting ID token claims: %v", err)
		return
	}

	fmt.Printf("redirect_url: %s \n\n", a.redirectURI)
	fmt.Printf("id_token: %s \n\n", rawIDToken)
	fmt.Printf("access_token: %s \n\n", accessToken)
	fmt.Printf("refresh_token: %s \n\n", token.RefreshToken)
	fmt.Printf("claims: %s \n\n", buff.String())

	renderToken(w, a.redirectURI, rawIDToken, accessToken, token.RefreshToken, buff.String())

	a.errChan <- nil
}
