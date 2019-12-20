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
	"syscall"

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
				config.PublicServerAddress = "127.0.0.1:29965"
				config.PrivateServerAddress = "127.0.0.1:35565"
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

	//Load private onion key from disk
	_, onionPrivKey, err := GetKeys("onion_id_ecc")
	if err != nil {
		log.Fatal(errors.Wrap(err, "error loading public and private key from disk"))
	}

	//Load contact list map from disk
	contacts, err := func() (map[string]ContactDetails, error) {
		ret := make(map[string]ContactDetails)
		b, err := ioutil.ReadFile(ConfigPath("contacts.json"))
		if os.IsNotExist(err) {
			var list = ContactList{
                Contacts: make(map[string]ContactDetails),
            }
            b, err = json.Marshal(&list)
            if err != nil {
                err = errors.Wrap(err, "No contacts file, so I attempted to marshal an empty one, but that also failed.")
            } else if err := ioutil.WriteFile(ConfigPath("contacts.json"), b, 0644); err != nil {
                err = errors.Wrap(err, "No contacts file, so I attempted to make an empty one, but that also failed.")
            }
		} else if err == nil {
			var list ContactList
			if err = json.Unmarshal(b, &list); err != nil {
				return nil, err
			} else {
				ret = list.Contacts
			}
		}
		return ret, err
	}()
	if err != nil {
		log.Fatal(errors.Wrap(err, "error loading contacts from disk"))
	}

	//Get tchat public key from disk
	tchatPubKey, tchatPrivKey, err := GetKeys("tchat_id_ecc")
	if err != nil {
		log.Fatal(errors.Wrap(err, "error loading tchat keys from disk"))
	}

	//Spin up onion server
	onionServer := http.NewServeMux()
	messenger := make(chan Message, 100)
	onionServer.Handle("/send", remoteSendHandler{
		Config:    conf,
		messenger: messenger,
		contacts:  contacts,
	})
	onionServer.HandleFunc("/key", getPubKeyHandler(tchatPubKey))
	listener, err := net.Listen("tcp", conf.PublicServerAddress)
	if err != nil {
		log.Fatal(errors.Wrap(err, "error establish control of address "+conf.PublicServerAddress))
	}
	go func() {
        panic(http.Serve(listener, onionServer))
    }()

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
	onion, err := torgo.OnionFromEd25519(onionPrivKey)
	if err != nil {
		log.Fatal(errors.Wrap(err, "error initializing tor hidden service"))
	}
	onion.Ports = map[int]string{80: conf.PublicServerAddress}

	log.Println("Starting up with service id", onion.ServiceID+ ".")

	//Connect onion service
	controller.AddOnion(onion)

	//Start local client service
	clientServer := http.NewServeMux()
	hub := hub{
		messenger: messenger,
	}
	clientServer.Handle("/read", localReadHandler{
		cookie: conf.ReadCookie,
		hub:    hub,
	})
	clientServer.Handle("/send", localSendHandler{
		Config:  conf,
		privKey: tchatPrivKey,
	})
	clientListener, err := net.Listen("tcp", conf.PrivateServerAddress)
    if err != nil {
		log.Fatal(errors.Wrap(err, "error establish control of address "+conf.PrivateServerAddress))
    }
	go func(){
        panic(http.Serve(clientListener, clientServer))
    }()
    log.Println("Began intialization of client daemon too.")

	// Wait here until CTRL-C or other term signal is received.
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt, os.Kill)
	<-sc

	controller.DeleteOnion(onion.ServiceID)
}
