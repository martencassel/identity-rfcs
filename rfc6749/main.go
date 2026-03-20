package main

// gin
import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

/*
   GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
       &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
   Host: server.example.com
*/

type Client struct {
	ID           string
	RedirectURI  string
	ClientSecret string
}

var registeredClients = map[string]Client{
	"s6BhdRkqt3": {ID: "s6BhdRkqt3", RedirectURI: "http://localhost:8080/cb", ClientSecret: "secret123"},
}

var users = map[string]string{
	"alice": "password123",
	"bob":   "securepassword",
}

type AuthorizationCodeGrant struct {
	ClientID    string
	RedirectURI string
	Username    string
	IssuedAt    int64
	ExpiresAt   int64
}

func (g AuthorizationCodeGrant) IsExpired() bool {
	return time.Now().Unix() > g.ExpiresAt
}

var authorizationCodeGrants = map[string]AuthorizationCodeGrant{}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, n)
	for i := range result {
		result[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(result)
}

func main() {
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		// App home page with a link to the client app
		c.HTML(200, "index.html", nil)
	})

	r.GET("/client", func(c *gin.Context) {
		// Client App directs user to the authorization server's authorization endpoint, which then redirects to the login page
		// with the original parameters in the query string
		clientID := "s6BhdRkqt3"
		redirectClient := registeredClients[clientID]
		c.Redirect(302, redirectClient.RedirectURI)
	})

	//
	// Authorization Server: Authorization Endpoint
	//
	r.GET("/authorize", func(c *gin.Context) {
		responseType := c.Query("response_type")
		clientID := c.Query("client_id")
		state := c.Query("state")
		redirectURI := c.Query("redirect_uri")

		log.Infof("Received authorization request: response_type=%s, client_id=%s, state=%s, redirect_uri=%s",
			responseType, clientID, state, redirectURI)

		//  4.1.1: 1.13. Validate all required parameters are present and valid
		if responseType == "" || clientID == "" || state == "" || redirectURI == "" {
			c.JSON(400, gin.H{"error": "invalid_request", "error_description": "Missing required parameters"})
			return
		}
		// Redirect to login page with the original parameters as query parameters
		loginURL := "/login?response_type=" + responseType + "&client_id=" + clientID + "&state=" + state + "&redirect_uri=" + redirectURI
		log.Infof("Redirecting to login page: %s", loginURL)
		c.Redirect(302, loginURL)
	})

	//
	// Login Endpoint (for simplicity, we handle login here instead of a separate page)
	//
	r.GET("/login", func(c *gin.Context) {
		// Return login html page
		c.HTML(200, "login.html", nil)
	})

	// Handle login form submission
	//
	r.POST("/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")

		log.Infof("Received login request: username=%s", username)

		// 4.1.2: 1.14. Authenticate the resource owner
		if storedPassword, ok := users[username]; !ok || storedPassword != password {
			c.JSON(401, gin.H{"error": "invalid_credentials", "error_description": "Invalid username or password"})
			return
		}

		// Check the original parameters from the query string
		responseType := c.Query("response_type")
		clientID := c.Query("client_id")
		state := c.Query("state")
		redirectURI := c.Query("redirect_uri")

		// Validate them
		if responseType == "" || clientID == "" || state == "" || redirectURI == "" {
			c.JSON(400, gin.H{"error": "invalid_request", "error_description": "Missing required parameters"})
			return
		}
		// Generate an authorization code and store it
		code := randomString(16) // In a real implementation, generate a secure random code
		authorizationCodeGrants[code] = AuthorizationCodeGrant{
			ClientID:    clientID,
			RedirectURI: redirectURI,
			Username:    username,
			IssuedAt:    time.Now().Unix(),
			ExpiresAt:   time.Now().Add(5 * time.Minute).Unix(),
		}
		log.Infof("Generated authorization code for user %s: %s", username, code)

		// Redirect
		redirectURL := redirectURI + "?code=" + code + "&state=" + state
		log.Infof("Redirecting to: %s", redirectURL)
		c.Redirect(302, redirectURL)
	})

	// Token Endpoint
	r.POST("/token", func(c *gin.Context) {
		// Client exchanges the authorization code for an access token (not implemented here)

		// 0. Get parameters from the request body (grant_type, code, redirect_uri, client_id, client_secret)
		grant_type := c.PostForm("grant_type")
		code := c.PostForm("code")
		redirectURI := c.PostForm("redirect_uri")
		clientID := c.PostForm("client_id")
		clientSecret := c.PostForm("client_secret")

		// 1. Validate the authorization code and client credentials
		if grant_type != "authorization_code" {
			c.JSON(400, gin.H{"error": "unsupported_grant_type", "error_description": "Only authorization_code grant type is supported"})
			return
		}
		if _, ok := registeredClients[clientID]; !ok {
			c.JSON(401, gin.H{"error": "invalid_client", "error_description": "Invalid client_id"})
			return
		}
		if registeredClients[clientID].RedirectURI != redirectURI {
			c.JSON(400, gin.H{"error": "invalid_request", "error_description": "redirect_uri does not match registered client"})
			return
		}
		if registeredClients[clientID].ClientSecret != clientSecret {
			c.JSON(401, gin.H{"error": "invalid_client", "error_description": "Invalid client_secret"})
			return
		}
		grant, ok := authorizationCodeGrants[code]
		if !ok || grant.IsExpired() {
			c.JSON(400, gin.H{"error": "invalid_grant", "error_description": "Invalid or expired authorization code"})
			return
		}
		username := grant.Username

		log.Infof("Exchanging code for token: client_id=%s, code=%s, username=%s", clientID, code, username)

		// 2. Generate an access token (not implemented here)
		accessToken := randomString(32) // In a real implementation, generate a secure random token

		// 3. Return the access token in the response
		c.JSON(200, gin.H{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	// Client callback
	r.GET("/cb", func(c *gin.Context) {
		code := c.Query("code")
		state := c.Query("state")

		log.Infof("Received callback with code: %s and state: %s", code, state)

		req, err := http.NewRequest("POST", "http://localhost:8080/token", nil)
		if err != nil {
			log.Errorf("Failed to create token request: %v", err)
			c.JSON(500, gin.H{"error": "server_error", "error_description": "Failed to create token request"})
			return
		}
		req.PostForm = url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"http://localhost:8080/cb"},
			"client_id":     {"s6BhdRkqt3"},
			"client_secret": {"secret"}, // In a real implementation, use a secure client secret
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Errorf("Failed to exchange code for token: %v", err)
			c.JSON(500, gin.H{"error": "server_error", "error_description": "Failed to exchange code for token"})
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			log.Errorf("Token endpoint returned non-200 status: %d", resp.StatusCode)
			c.JSON(500, gin.H{"error": "server_error", "error_description": "Token endpoint returned non-200 status"})
			return
		}

		var tokenResponse map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
			log.Errorf("Failed to decode token response: %v", err)
			c.JSON(500, gin.H{"error": "server_error", "error_description": "Failed to decode token response"})
			return
		}

		log.Infof("Received token response: %v", tokenResponse)
		c.JSON(200, gin.H{
			"message": "Authorization successful",
			"token":   tokenResponse,
		})
	})

	r.Run() // listen and serve on 0.0.0.0:8080

}
