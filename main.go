package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/browser"
)

const TWITCH_CLIENT_ID string = "TWITCH_CLIENT_ID"
const TWITCH_CLIENT_SECRET string = "TWITCH_CLIENT_SECRET"
const TWITCH_AUTH_URL string = "https://id.twitch.tv/oauth2/authorize"
const TWITCH_TOKEN_URL string = "https://id.twitch.tv/oauth2/token"

type TokenExchangeResponse struct {
	AccessToken  string   `json:"access_token"`
	ExpiresIn    int64    `json:"expires_in"`
	RefreshToken string   `json:"refresh_token"`
	Scope        []string `json:"scope"`
	TokenType    string   `json:"token_type"`
}

func main() {
	CreateAuthExchange()

}

func createStateString() (string, error) {
	availableValues := "1234567890qwertyuioplkjhgfdsazxcvbnm"
	var sb strings.Builder
	for i := 0; i < 32; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(availableValues))))
		if err != nil {
			return "", err
		}
		sb.WriteString(string(availableValues[num.Int64()]))
	}
	return sb.String(), nil
}

func (ad *AuthData) startLocalAuthServer() {
	listener, err := net.Listen("tcp", ":7777")
	if err != nil {
		log.Fatalf("Listener could not be created : %s", err)
	}
	ad.Server = &http.Server{}
	http.HandleFunc("/", ad.recieveAuthorizationCodes)

	go func() {
		if err := ad.Server.Serve(listener); err != http.ErrServerClosed {
			log.Fatalf("Could not listen for authorization code %v", err)
		}
	}()
	ad.RedirectUri = fmt.Sprintf("http://localhost:%d", listener.Addr().(*net.TCPAddr).Port)
	fmt.Printf("LISTENING ON : %s\n", ad.RedirectUri)
}

func CreateAuthExchange() (*AuthData, error) {

	cid, ok := os.LookupEnv(TWITCH_CLIENT_ID)
	if !ok {
		return nil, fmt.Errorf("Env var %s not set", TWITCH_CLIENT_ID)
	}
	cs, ok := os.LookupEnv(TWITCH_CLIENT_SECRET)
	if !ok {
		return nil, fmt.Errorf("Env var %s not set", TWITCH_CLIENT_SECRET)
	}
	stateStr, err := createStateString()
	if err != nil {
		return nil, fmt.Errorf("Cannot generate state string")
	}
	ad := &AuthData{ClientId: cid, ClientSecret: cs, State: stateStr}
	ad.Waitgroup = &sync.WaitGroup{}
	ad.Waitgroup.Add(1)
	ad.startLocalAuthServer()
	ad.navigateToAuthURL()
	ad.Waitgroup.Wait()

	return ad, nil
}

type AuthData struct {
	Waitgroup    *sync.WaitGroup
	State        string
	RedirectUri  string
	ClientId     string
	ClientSecret string
	AuthCode     string
	Server       *http.Server
}

// navigates to an auth URL for twitch and then returns an auth code inside
// the AuthData struct
func (ad *AuthData) navigateToAuthURL() {
	scope := "" // Space delimited list of scopes

	url := fmt.Sprintf("%s?client_id=%s&response_type=code&redirect_uri=%s&scope=%s&state=%s", TWITCH_AUTH_URL, ad.ClientId, ad.RedirectUri, scope, ad.State)

	browser.OpenURL(url)
}

func (ad *AuthData) recieveAuthorizationCodes(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	queryParams := r.URL.Query()
	code := queryParams.Get("code")
	// scope := queryParams.Get("scope") // reserved for later use if needed
	state := queryParams.Get("state")
	error := queryParams.Get("error")
	error_description := queryParams.Get("error_description")
	ad.AuthCode = code
	msg := "Login successful!"
	if code == "" || error != "" || error_description != "" || ad.State != state {
		msg = fmt.Sprintf("Failed to match on state or got an error\nError: %s\nDesc: %s", error, error_description)
	}
	b := bytes.NewBufferString(msg)
	w.Write(b.Bytes())
	w.(http.Flusher).Flush()
	ad.Server.Shutdown(ctx)
	ad.Waitgroup.Done()

	//Once we have the auth code, shut down the server
}

func (ad *AuthData) exchangeForToken() (*TokenExchangeResponse, error) {
	data := &url.Values{}
	data.Set("client_id", ad.ClientId)
	data.Set("client_secret", ad.ClientSecret)
	data.Set("code", ad.AuthCode)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", ad.RedirectUri)

	req, err := http.NewRequest("POST", TWITCH_TOKEN_URL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("could not create a request : %v", err)
	}
	req.Header.Set("Content-Type", "x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not complete request to exchange the token : %v", err)
	}
	body := resp.Body
	defer body.Close()
	ter := &TokenExchangeResponse{}
	bb, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("could not read resp body into bytes : %v", err)
	}
	err = json.Unmarshal(bb, ter)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed of token exchange response: %v", err)
	}
	return ter, nil
}

//TODO: Refresh Tokens https://dev.twitch.tv/docs/authentication/refresh-tokens/
//TODO: Write the user token to the application cache. Maybe $HOME/.config/
//TODO: Refactor all of auth to a package inside this package
//TODO: Rename package to match the Git Repo
