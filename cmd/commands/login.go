package commands

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"

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
	)

	loginCmd := cobra.Command{
		Use:   "login",
		Short: "use this for login",
		RunE: func(cmd *cobra.Command, args []string) error {

			// u, err := url.Parse(a.redirectURI)
			// if err != nil {
			// 	return fmt.Errorf("parse redirect-uri: %v", err)
			// }

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

			err = openbrowser(authURL)
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
	loginCmd.Flags().BoolVar(&a.offlineAccess, "offline-access", true, "If it is true, token for offline access will be granted")
	loginCmd.Flags().StringVar(&issuerURL, "issuer", "http://127.0.0.1:5556/dex", "URL of the OpenID Connect issuer.")
	loginCmd.Flags().StringArrayVar(&a.extraScopes, "scope", []string{}, "extra scopes for ouath2 url code request")

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

	if a.offlineAccess {
		authCodeURL = a.oauth2Config(scopes).AuthCodeURL(appState)
	} else if a.offlineAsScope {
		scopes = append(scopes, "offline_access")
		authCodeURL = a.oauth2Config(scopes).AuthCodeURL(appState)
	} else {
		authCodeURL = a.oauth2Config(scopes).AuthCodeURL(appState, oauth2.AccessTypeOffline)
	}

	return authCodeURL, nil
}
