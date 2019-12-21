package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"

	"github.com/gorilla/websocket"
	. "github.com/hugbubby/tchatlib"
	"github.com/hugbubby/torgo"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

type remoteSendHandler struct {
	Config
	messenger chan<- Message
	contacts  map[string]ContactDetails
}

func (s remoteSendHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		w.WriteHeader(http.StatusNotFound)
	} else if err := req.ParseForm(); err != nil {
		http.Error(w, "Could not parse form", http.StatusBadRequest)
	} else if encodedMsg := req.FormValue("message"); encodedMsg == "" {
		http.Error(w, "Lack of message", http.StatusBadRequest)
	} else if msg_b, err := base64.RawStdEncoding.DecodeString(encodedMsg); err != nil {
		http.Error(w, errors.Wrap(err, "Could not decode message " + encodedMsg).Error(), http.StatusBadRequest)
	} else if encodedSig := req.FormValue("signature"); encodedSig == "" {
		http.Error(w, "Lack of signature", http.StatusBadRequest)
	} else if sig, err := base64.RawStdEncoding.DecodeString(encodedSig); err != nil {
		http.Error(w, errors.Wrap(err, "Could not decode signature " + encodedSig).Error(), http.StatusBadRequest)
	} else {
		var msg Message
		if err := json.Unmarshal(msg_b, &msg); err != nil {
			http.Error(w, "Could not parse message", http.StatusBadRequest)
		} else if contact, ok := s.contacts[msg.ServiceID]; !ok {
			http.Error(w, "Not in contacts list", http.StatusForbidden)
		} else if !ed25519.Verify(contact.PubKey, msg_b, sig) {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
		} else {
			s.messenger <- msg
		}
	}
}

func getPubKeyHandler(pubKey ed25519.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			fmt.Fprint(w, pubKey)
		} else {
			w.WriteHeader(404)
		}
	}
}

type localReadHandler struct {
	cookie string
	hub
}

func (r localReadHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024 * 64, //64KB
		WriteBufferSize: 1024 * 64, //64KB
	}
	if conn, err := upgrader.Upgrade(w, req, nil); err != nil {
		http.Error(w, "couldn't upgrade to websocket", http.StatusInternalServerError)
	} else {
		if mtype, p, err := conn.ReadMessage(); err != nil {
			log.Println("failed to read cookie from websocket conn at", conn.RemoteAddr(), ":", err)
			conn.Close()
		} else if mtype != websocket.TextMessage || !reflect.DeepEqual(p, []byte(r.cookie)) {
			conn.WriteMessage(websocket.TextMessage, []byte("denied"))
			conn.Close()
		} else {
			conn.WriteMessage(websocket.TextMessage, []byte("accepted"))
			r.hub.register(conn)
		}
	}
}

type localSendHandler struct {
	Config
	privKey ed25519.PrivateKey
	cookie  string
}

func (s localSendHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		w.WriteHeader(404)
	} else if req.Header.Get("Cookie") != s.cookie { //I don't know what a cookie actually is
		w.WriteHeader(http.StatusUnauthorized)
	} else if err := req.ParseForm(); err != nil {
		http.Error(w, errors.Wrap(err, "error parsing form").Error(), http.StatusBadRequest)
	} else if destination := req.FormValue("destination"); !torgo.IsValidHiddenServiceId(destination) {
		http.Error(w, "invalid onion id as destination "+destination, http.StatusBadRequest)
	} else if message := req.FormValue("message"); message == "" {
		http.Error(w, "no message included in request", http.StatusBadRequest)
	} else if c, err := torgo.NewClient(s.Tor.ProxyAddress); err != nil {
		http.Error(w, errors.Wrap(err, "error connecing to tor proxy client").Error(), http.StatusInternalServerError)
	} else {
		sig_b := ed25519.Sign(s.privKey, []byte(message))
		sig_enc := base64.StdEncoding.EncodeToString(sig_b)
		msg_enc := base64.StdEncoding.EncodeToString([]byte(message))
		if resp, err := c.PostForm("http://"+destination+".onion/send", map[string][]string{
			"signature": []string{sig_enc},
			"message":   []string{msg_enc},
		}); err != nil {
			http.Error(w, errors.Wrap(err, "error sending message to remote tchat server").Error(), http.StatusInternalServerError)
		} else if resp.StatusCode != 200 {
			if b, err := ioutil.ReadAll(resp.Body); err != nil {
				http.Error(w, fmt.Sprintf("recipient returned %d status code but we were unable to read the body",
					resp.StatusCode), http.StatusInternalServerError)
			} else {
				http.Error(w, fmt.Sprintf("recipient returned %d status code and: %s",
					resp.StatusCode, string(b)), http.StatusInternalServerError)
			}
		}
	}
}

type hub struct {
	messenger <-chan Message
	conns     []*websocket.Conn
}

func (h *hub) register(conn *websocket.Conn) {
	h.conns = append(h.conns, conn)
}

func (h *hub) routeMessages() {
	for {
		select {
		case msg := <-h.messenger:
			for _, v := range h.conns {
				err := v.WriteJSON(msg)
				if err != nil {
					log.Println(errors.Wrap(err, "error sending message to websocket "+v.RemoteAddr().String()))
				}
			}
		}
	}
}
