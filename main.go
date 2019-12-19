package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"syscall"

	"golang.org/x/crypto/ed25519"

	"github.com/gorilla/websocket"
	. "github.com/hugbubby/tchatlib"
	"github.com/hugbubby/torgo"
	"github.com/pkg/errors"
)

func main() {

	//Load configuration file from disk, or generate it if needed
	conf, err := func() (Config, error) {
		var config Config
		newCookie := func() error {
			b := make([]byte, 32)
			_, err := rand.Read(b)
			if err == nil {
				config.ReadCookie = base64.RawStdEncoding.EncodeToString(b)
				var b []byte
				b, err = json.Marshal(config)
				if err == nil {
					err = ioutil.WriteFile(ConfigPath("config.json"), b, 0600)
				}
			}
			return err
		}
		b, err := ioutil.ReadFile(ConfigPath("config.json"))
		if err == nil {
			err = json.Unmarshal(b, &config)
			if err == nil && config.ReadCookie == "" {
				err = newCookie()
			}
		} else if os.IsNotExist(err) {
			if err = os.MkdirAll(ConfigPath("."), 0755); err == nil {
				config.ServerAddress = "127.0.0.1:29965"
				config.Tor.ProxyAddress = "127.0.0.1:9050"
				config.Tor.ControllerAddress = "127.0.0.1:9051"
				err = newCookie()
			}
		}
		return config, err
	}()
	if err != nil {
		log.Fatal(errors.Wrap(err, "error loading torchatd config"))
	}

	//Load private key from disk
	_, privKey, err := GetKeys()
	if err != nil {
		log.Fatal(errors.Wrap(err, "error loading public and private key from disk"))
	}

	//Load contact list map from disk
	contacts, err := func() (map[string]Contact, error) {
		ret := make(map[string]Contact)
		b, err := ioutil.ReadFile(ConfigPath("contacts"))
		if err != nil {
			if os.IsNotExist(err) {
				b, err = json.Marshal(make([]Contact, 0))
				log.Println("Warning: Make sure you add some contacts with your client, or no one can speak to you.")
			}
		} else {
			var contact []Contact
			if err = json.Unmarshal(b, &contact); err != nil {
				return nil, err
			} else {
				for _, v := range contact {
					serviceID, err := torgo.ServiceIDFromEd25519(v.PubKey)
					if err != nil {
						return ret, err
					} else {
						ret[serviceID] = v
					}
				}
			}
		}
		return ret, err
	}()
	if err != nil {
		log.Fatal(errors.Wrap(err, "error loading public and private key from disk"))
	}

	//Spin up server
	messenger := make(chan Message, 100)
	http.Handle("/send", sendHandler{
		Config:    conf,
		messenger: messenger,
		contacts:  contacts,
	})
	hub := hub{
		messenger: messenger,
	}
	http.Handle("/read", readHandler{
		cookie: conf.ReadCookie,
		hub:    hub,
	})
	listener, err := net.Listen("tcp", conf.ServerAddress)
	if err != nil {
		log.Fatal(errors.Wrap(err, "error establish control of address "+conf.ServerAddress))
	}
	go http.Serve(listener, nil)

	//Make new onion controller object
	controller, err := torgo.NewController(conf.Tor.ControllerAddress)
	if err != nil {
		log.Fatal(errors.Wrap(err, "error creating tor controller"))
	}

	//Authenticate to the tor controller
	if err = controller.AuthenticateCookie(); err != nil {
		log.Fatal(errors.Wrap(err, "error authenticating to tor controller"))
	}

	//Create onion service from privKey & configure
	onion, err := torgo.OnionFromEd25519(privKey)
	if err != nil {
		log.Fatal(errors.Wrap(err, "error initializing tor hidden service"))
	}
    onion.Ports = map[int]string{80:conf.ServerAddress}

	log.Println("Starting up with service id ", onion.ServiceID)

	//Connect onion service
	controller.AddOnion(onion)

	// Wait here until CTRL-C or other term signal is received.
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt, os.Kill)
	<-sc

	controller.DeleteOnion(onion.ServiceID)
}

type sendHandler struct {
	Config
	messenger chan<- Message
	contacts  map[string]Contact
}

func (s sendHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		if err := req.ParseForm(); err != nil {
			http.Error(w, "Could not parse form", http.StatusBadRequest)
		} else {
			if encodedMsg := req.FormValue("message"); encodedMsg == "" {
				http.Error(w, "Lack of message", http.StatusBadRequest)
			} else {
				if msg_b, err := base64.RawStdEncoding.DecodeString(req.FormValue(encodedMsg)); err != nil {
					http.Error(w, "Could not decode message", http.StatusBadRequest)
				} else {
					if encodedSig := req.FormValue("signature"); encodedSig == "" {
						http.Error(w, "Lack of signature", http.StatusBadRequest)
					} else {
						if sig, err := base64.RawStdEncoding.DecodeString(req.FormValue("signature")); err != nil {
							http.Error(w, "Could not decode signature", http.StatusBadRequest)
						} else {
							var msg Message
							if err := json.Unmarshal(msg_b, &msg); err != nil {
								http.Error(w, "Could not parse message", http.StatusBadRequest)
							} else {
								if contact, ok := s.contacts[msg.ServiceID]; !ok {
									http.Error(w, "Not in contacts list", http.StatusForbidden)
								} else {
									if !ed25519.Verify(contact.PubKey, msg_b, sig) {
										http.Error(w, "Invalid signature", http.StatusUnauthorized)
									} else {
										s.messenger <- msg
									}
								}
							}
						}
					}
				}
			}
		}
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

type readHandler struct {
	cookie string
	hub
}

func (r readHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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
