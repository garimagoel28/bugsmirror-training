package Common

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

// User represents a user in the system
type User struct {
	ID         string              `json:"id"`
	SecretCode string              `json:"secretCode"`
	Name       string              `json:"name"`
	Email      string              `json:"email"`
	Playlists  map[string]Playlist `json:"playlists"`
}

// Playlist represents a playlist for a user
type Playlist struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Songs map[string]Song `json:"songs"`
}

// Song represents a song in a playlist
type Song struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Composers string `json:"composers"`
	MusicURL  string `json:"musicURL"`
}

// request body struct for Login API
type LoginData struct {
	SecretCode string `json:"secretCode"`
}

// Mutex for concurrency safety
var Mu sync.Mutex

// Users map to store user data
var Users = make(map[string]User)

// findUserBySecretCode searches for a user by secret code
func FindUserBySecretCode(secretCode string) (User, bool) {
	Mu.Lock()
	defer Mu.Unlock()
	for _, user := range Users {
		if user.SecretCode == secretCode {
			return user, true
		}
	}
	return User{}, false
}

// generateUniqueID generates a unique ID for users and playlists
func GenerateUniqueID() string {
	id := make([]byte, 16)
	_, err := rand.Read(id)
	if err != nil {
		panic(err) // Handle error appropriately in a production environment
	}
	return hex.EncodeToString(id)
}

// generateUniqueSecretCode generates a unique secret code for users
func GenerateUniqueSecretCode() string {
	secretCode := make([]byte, 8)
	_, err := rand.Read(secretCode)
	if err != nil {
		panic(err) // Handle error appropriately in a production environment
	}
	return hex.EncodeToString(secretCode)
}
