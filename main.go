package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

//go:embed index.html
var page []byte

const origin = "http://localhost:8080"

type demoUser struct {
	id          []byte
	credentials []webauthn.Credential
}

func (u *demoUser) WebAuthnID() []byte                         { return u.id }
func (u *demoUser) WebAuthnName() string                       { return "demo" }
func (u *demoUser) WebAuthnDisplayName() string                { return "Asterion Demo" }
func (u *demoUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

type ceremony struct {
	token   string
	kind    string
	expires time.Time
	session webauthn.SessionData
}

type demo struct {
	mu      sync.Mutex
	auth    *webauthn.WebAuthn
	user    demoUser
	pending ceremony
}

func main() {
	auth, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Asterion",
		RPID:          "localhost",
		RPOrigins:     []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.Platform,
			ResidentKey:             protocol.ResidentKeyRequirementRequired,
			UserVerification:        protocol.VerificationRequired,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	app := &demo{auth: auth, user: demoUser{id: []byte(rand.Text())}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	})
	mux.HandleFunc("POST /{kind}/begin", app.begin)
	mux.HandleFunc("POST /{kind}/finish", app.finish)

	server := &http.Server{
		Addr:         "127.0.0.1:8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		Handler:      mux,
	}
	log.Printf("Open %s", origin)
	log.Fatal(server.ListenAndServe())
}

func (d *demo) begin(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != origin {
		http.Error(w, "Invalid origin", http.StatusForbidden)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	kind := r.PathValue("kind")
	var options any
	var session *webauthn.SessionData
	var err error
	switch kind {
	case "register":
		if len(d.user.credentials) != 0 {
			http.Error(w, "This demo already has a Passkey", http.StatusConflict)
			return
		}
		options, session, err = d.auth.BeginRegistration(&d.user)
	case "login":
		if len(d.user.credentials) == 0 {
			http.Error(w, "Register a Passkey first", http.StatusConflict)
			return
		}
		options, session, err = d.auth.BeginLogin(&d.user, webauthn.WithUserVerification(protocol.VerificationRequired))
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("%s begin: %v", kind, err)
		http.Error(w, "Could not start verification", http.StatusInternalServerError)
		return
	}

	// This single-user demo allows one pending operation at a time.
	d.pending = ceremony{rand.Text(), kind, time.Now().Add(2 * time.Minute), *session}
	http.SetCookie(w, &http.Cookie{
		Name: "asterion_ceremony", Value: d.pending.token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 120,
	})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func (d *demo) finish(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != origin {
		http.Error(w, "Invalid origin", http.StatusForbidden)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	kind := r.PathValue("kind")
	cookie, err := r.Cookie("asterion_ceremony")
	pending := d.pending
	if err != nil || cookie.Value != pending.token || kind != pending.kind || !time.Now().Before(pending.expires) {
		http.Error(w, "Verification expired or missing. Please try again.", http.StatusBadRequest)
		return
	}
	// Consume the challenge before verification so it cannot be replayed.
	d.pending = ceremony{}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)

	var credential *webauthn.Credential
	switch kind {
	case "register":
		credential, err = d.auth.FinishRegistration(&d.user, pending.session, r)
	case "login":
		credential, err = d.auth.FinishLogin(&d.user, pending.session, r)
	}
	if err != nil {
		log.Printf("%s finish: %v", kind, err)
		http.Error(w, "Passkey verification failed", http.StatusBadRequest)
		return
	}

	d.user.credentials = []webauthn.Credential{*credential}
	w.WriteHeader(http.StatusNoContent)
}
