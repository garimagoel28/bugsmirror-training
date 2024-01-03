// main.go

package main

import (
	"MusicListerAPI/MusicListerService"
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/login", MusicListerService.Login)
	http.HandleFunc("/register", MusicListerService.Register)
	http.HandleFunc("/viewProfile", MusicListerService.ViewProfile)
	http.HandleFunc("/getAllSongsOfPlaylist", MusicListerService.GetAllSongsOfPlaylist)
	http.HandleFunc("/createPlaylist", MusicListerService.CreatePlaylist)
	http.HandleFunc("/addSongToPlaylist", MusicListerService.AddSongToPlaylist)
	http.HandleFunc("/deleteSongFromPlaylist", MusicListerService.DeleteSongFromPlaylist)
	http.HandleFunc("/deletePlaylist", MusicListerService.DeletePlaylist)
	http.HandleFunc("/getSongDetail", MusicListerService.GetSongDetail)

	// Start the server
	port := 8080
	fmt.Printf("Server running on :%d...\n", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}
