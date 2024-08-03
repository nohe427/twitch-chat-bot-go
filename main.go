package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
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
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatalf("Listener could not be created : %s", err)
	}
	ad.Server = &http.Server{}
	http.HandleFunc("/", ad.recieveAuthorizationCodes)

	go func() {
		defer ad.Waitgroup.Done()
		if err := ad.Server.Serve(listener); err != http.ErrServerClosed {
			log.Fatalf("Could not listen for authorization code %v", err)
		}
	}()
	ad.RedirectUri = fmt.Sprintf("http://%s", listener.Addr().String())
	fmt.Printf("LISTENING ON : %s\n", ad.RedirectUri)
}

func CreateAuthExchange() (*AuthData, error) {

	cid, ok := os.LookupEnv(TWITCH_CLIENT_ID)
	if !ok {
		// return nil, fmt.Errorf("Env var %s not set", TWITCH_CLIENT_ID)
	}
	cs, ok := os.LookupEnv(TWITCH_CLIENT_SECRET)
	if !ok {
		// return nil, fmt.Errorf("Env var %s not set", TWITCH_CLIENT_SECRET)
	}
	stateStr, err := createStateString()
	if err != nil {
		return nil, fmt.Errorf("Cannot generate state string")
	}
	ad := &AuthData{ClientId: cid, ClientSecret: cs, State: stateStr}
	ad.Waitgroup = &sync.WaitGroup{}
	ad.Waitgroup.Add(1)
	ad.startLocalAuthServer()
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
	defer ad.Server.Shutdown(ctx)

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
	ad.Waitgroup.Done()

	//Once we have the auth code, shut down the server
}

func (ad *AuthData) exchangeForToken() {
	// TWITCH_TOKEN_URL
}
