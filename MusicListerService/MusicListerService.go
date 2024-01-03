package MusicListerService

import (
	"MusicListerAPI/Common"
	"encoding/json"
	"fmt"
	"net/http"
)

func Login(w http.ResponseWriter, r *http.Request) {
	//HTTP method validation (get, post)
	if r.Method != http.MethodPost {
		http.Error(w, Common.InvalidRequestMethodErrorMessage, http.StatusMethodNotAllowed)
		return
	}
	// Decode JSON directly from the request body
	var loginData Common.LoginData
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&loginData)
	if err != nil {
		http.Error(w, Common.ErrordecodingJSON, http.StatusBadRequest)
		return
	}
	// Extract secret code from request
	secretCode := loginData.SecretCode
	fmt.Println(secretCode)

	// Check if the user with the provided secret code exists
	user, found := Common.FindUserBySecretCode(secretCode)
	if !found {
		http.Error(w, Common.UserNotFound, http.StatusNotFound)
		return
	}
	fmt.Println(user)
	// Return user details
	w.Header().Set(Common.ContentType, Common.ApplicationJson)
	err = json.NewEncoder(w).Encode(user)
	if err != nil {
		return
	}
}

func Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	// Parse JSON request body to get user details
	var newUser Common.User
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Generate unique ID and Secret Code for the new user
	newUser.ID = Common.GenerateUniqueID()
	newUser.SecretCode = Common.GenerateUniqueSecretCode()

	// Add the new user to the users map
	Common.Mu.Lock()
	defer Common.Mu.Unlock()
	Common.Users[newUser.ID] = newUser

	// Return the details of the newly created user
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newUser)
}

func ViewProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	// Extract user ID from request
	userID := r.FormValue("userID")

	// Check if the user with the provided ID exists
	Common.Mu.Lock()
	defer Common.Mu.Unlock()
	user, found := Common.Users[userID]
	if !found {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Return user details
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(user)
	if err != nil {
		return
	}
}

func GetAllSongsOfPlaylist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	// Extract user ID and playlist ID from request
	userID := r.FormValue("userID")
	playlistID := r.FormValue("playlistID")

	// Check if the user with the provided ID exists
	Common.Mu.Lock()
	defer Common.Mu.Unlock()
	user, found := Common.Users[userID]
	if !found {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	playlist, found := user.Playlists[playlistID]
	if !found {
		http.Error(w, "Playlist not found", http.StatusNotFound)
		return
	}

	// Return songs in the playlist
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(playlist.Songs)
	if err != nil {
		return
	}
}

func CreatePlaylist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	// Extract user ID from request
	//url
	userID := r.FormValue("userID")

	// Check if the user with the provided ID exists
	Common.Mu.Lock()
	defer Common.Mu.Unlock()
	user, found := Common.Users[userID]
	if !found {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Parse JSON request body to get playlist details
	var newPlaylist Common.Playlist
	err := json.NewDecoder(r.Body).Decode(&newPlaylist)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Generate unique ID for the new playlist
	newPlaylist.ID = Common.GenerateUniqueID()

	// Add the new playlist to the user's playlists
	user.Playlists[newPlaylist.ID] = newPlaylist
	fmt.Println(user)
	Common.Users[userID] = user
	// Return the details of the newly created playlist
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user.Playlists)
}

func AddSongToPlaylist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	// Extract user ID and playlist ID from request
	userID := r.FormValue("userID")
	playlistID := r.FormValue("playlistID")
	fmt.Println(userID, playlistID)
	// Check if the user with the provided ID exists
	Common.Mu.Lock()
	defer Common.Mu.Unlock()
	user, found := Common.Users[userID]
	if !found {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	fmt.Println(user)
	// Find the playlist in the user's playlists
	playlist, found := user.Playlists[playlistID]
	if !found {
		http.Error(w, "Playlist not found", http.StatusNotFound)
		return
	}

	// Parse JSON request body to get song details
	var newSong Common.Song
	err := json.NewDecoder(r.Body).Decode(&newSong)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Generate unique ID for the new song
	newSong.ID = Common.GenerateUniqueID()

	// Add the new song to the playlist
	playlist.Songs[newSong.ID] = newSong
	Common.Users[userID] = user

	// Return the details of the newly created song
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(playlist.Songs)
}

func DeleteSongFromPlaylist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	// Extract user ID, playlist ID, and song ID from request
	userID := r.FormValue("userID")
	playlistID := r.FormValue("playlistID")
	songID := r.FormValue("songID")

	// Check if the user with the provided ID exists
	Common.Mu.Lock()
	defer Common.Mu.Unlock()
	user, found := Common.Users[userID]
	if !found {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	// Find the playlist in the user's playlists
	playlist, found := user.Playlists[playlistID]
	if !found {
		http.Error(w, "Playlist not found", http.StatusNotFound)
		return
	}
	// Find and remove the song from the playlist
	delete(playlist.Songs, songID)
	Common.Users[userID].Playlists[playlistID] = playlist
	w.WriteHeader(http.StatusNoContent)
	json.NewEncoder(w).Encode("Successfully deleted.")
}

func DeletePlaylist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	// Extract user ID and playlist ID from request
	userID := r.FormValue("userID")
	playlistID := r.FormValue("playlistID")

	// Check if the user with the provided ID exists
	Common.Mu.Lock()
	defer Common.Mu.Unlock()
	user, found := Common.Users[userID]
	if !found {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	// Find and remove the playlist from the user's playlists
	delete(user.Playlists, playlistID)
	Common.Users[userID] = user
	w.WriteHeader(http.StatusNoContent)
}

func GetSongDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	// Extract user ID, playlist ID, and song ID from request
	userID := r.FormValue("userID")
	playlistID := r.FormValue("playlistID")
	songID := r.FormValue("songID")

	// Check if the user with the provided ID exists
	Common.Mu.Lock()
	defer Common.Mu.Unlock()
	user, found := Common.Users[userID]
	if !found {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	// Find the playlist in the users
	playlist, found := user.Playlists[playlistID]
	if !found {
		http.Error(w, "Playlist not found", http.StatusNotFound)
		return
	}

	// Find the song in the playlist
	song, found := playlist.Songs[songID]
	if !found {
		http.Error(w, "Song not found", http.StatusNotFound)
		return
	}
	// Return details of the song
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(song)
}
