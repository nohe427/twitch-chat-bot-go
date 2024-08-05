package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
	Status       int64    `json:"status"`
	Message      string   `json:"message"`
}

func main() {
	_, err := CreateAuthExchange()
	if err != nil {
		fmt.Printf("ERROR %v", err)
	}

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
	if ad.TokenExchangeResponse == nil {
		return nil, fmt.Errorf("Token exchange response failure")
	}
	err = WriteTokenToDisk(ad.TokenExchangeResponse)
	if err != nil {
		return nil, err
	}

	return ad, nil
}

func getTokenFile() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not find the home dir for the user")
	}
	configDir := filepath.Join(home, ".config", "nohedevtwitchbot")
	err = os.MkdirAll(configDir, fs.FileMode(0750))
	if err != nil {
		return "", fmt.Errorf("could not create the configuration directory for nohedevtwitchbot")
	}
	tokenFile := "token.json"
	return filepath.Join(configDir, tokenFile), nil
}

func WriteTokenToDisk(ter *TokenExchangeResponse) error {
	tokenFile, err := getTokenFile()
	if err != nil {
		return err
	}
	f, err := os.Create(tokenFile)
	defer f.Close()
	if err != nil {
		return fmt.Errorf("could not create the token.json file at location %s : %v", tokenFile, err)
	}
	b, err := json.Marshal(ter)
	if err != nil {
		return fmt.Errorf("could not marshal the json file to bytes : %v", err)
	}
	_, err = f.Write(b)

	return err
}

type AuthData struct {
	Waitgroup             *sync.WaitGroup
	State                 string
	RedirectUri           string
	ClientId              string
	ClientSecret          string
	AuthCode              string
	Server                *http.Server
	TokenExchangeResponse *TokenExchangeResponse
}

// navigates to an auth URL for twitch and then returns an auth code inside
// the AuthData struct
func (ad *AuthData) navigateToAuthURL() {
	scope := "user:manage:whispers" // Space delimited list of scopes

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
	_, err := ad.exchangeForToken(false)
	if err != nil {
		log.Fatalf("token exchange failed, giving up : %v", err)
	}
	ad.Server.Shutdown(ctx)
	ad.Waitgroup.Done()

	//Once we have the auth code, shut down the server
}

func getRefreshToken() (string, error) {
	tokenFile, err := getTokenFile()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("token file unable to be read %v", err)
	}
	ter := &TokenExchangeResponse{}
	err = json.Unmarshal(b, ter)
	return ter.RefreshToken, err
}

func (ad *AuthData) exchangeForToken(isRefresh bool) (*TokenExchangeResponse, error) {
	data := &url.Values{
		"client_id":     {ad.ClientId},
		"client_secret": {ad.ClientSecret},
		"code":          {ad.AuthCode},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {ad.RedirectUri},
	}
	if isRefresh {
		refreshToken, err := getRefreshToken()
		if err != nil {
			return nil, err
		}
		data = &url.Values{
			"client_id":     {ad.ClientId},
			"client_secret": {ad.ClientSecret},
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
		}
	}

	req, err := http.NewRequest("POST", TWITCH_TOKEN_URL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("could not create a request : %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
	if ter.Message != "" {
		fmt.Printf("Error Message %v", ter.Message)
	}
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed of token exchange response: %v", err)
	}
	ad.TokenExchangeResponse = ter
	return ter, nil
}

//TODO: Refactor all of auth to a package inside this package
//TODO: Rename package to match the Git Repo
