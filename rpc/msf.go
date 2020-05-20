package msf

import (
	"bytes"
	"fmt"
	"net/http"

	"gopkg.in/vmihailenco/msgpack.v2"
)

// loginReq serializes data to likeable format mor msgpack
type loginReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Username string
	Password string
}

// Response for login request
type loginRes struct {
	Result       string `msgpack:"result"`
	Token        string `msgpack:"token"`
	Error        bool   `msgpack:"error"`
	ErrorClass   string `msgpack:"error_class"`
	ErrorMessage string `msgpack:"error_message"`
}

// struct for logout request
type logoutReq struct {
	_msgpack    struct{} `msgpack:",asArray"`
	Method      string
	Token       string
	LogoutToken string
}

type logoutRes struct {
	Result       string `msgpack:"result"`
	Error        string `msgpack:"error"`
	ErrorClass   string `msgpack:"error_class"`
	ErrorMessage string `msgpack:"error_message"`
}

// ListReq Struct to change data to MSGPack format
type ListReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

// ListRes struct to query response data from session.list method
type ListRes struct {
	ID          uint32 `msgpack:",omitempty"` // omit makes the data optional
	Type        string `msgpack:"type"`
	TunnelLocal string `msgpack:"tunnel_local"`
	TunnelPeer  string `msgpack:"tunnel_peer"`
	ViaExploit  string `msgpack:"via_exploit"`
	ViaPayload  string `msgpack:"via_payload"`
	Description string `msgpack:"Description"`
	Info        string `msgpack:"info"`
	Workspace   string `msgpack:"workspace"`
	TargetHost  string `msgpack:"target_host"`
	Username    string `msgpack:"username"`
	UUID        string `msgpack:"uuid"`
	ExploitUUID string `msgpack:"exploit_uuid"`
	Routes      string `msgpack:"routes"`
}

// ModuleInfo will serializes data into msgpack format.
type ModuleInfo struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	Type       string
	ModuleName string
}

// InfoRes holds response for Module Info method
type InfoRes struct {
	Name        string   `msgpack:"name"`
	Description string   `msgpack:"description"`
	License     string   `msgpack:"license"`
	Filepath    string   `msgpack:"filepath"`
	Version     string   `msgpack:"version"`
	Rank        int      `msgpack:"rank"`
	References  []string `msgpack:"references"`
	Authors     []string `msgpack:"authors"`
}

// Joblist serializes data into msgpack fmt
type Joblist struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
}

// JoblistRes returns active jobs
type JoblistRes struct {
	JLID string `msgpack:"jlid"`
}

// JobInfo serializes data into msgpack format
type JobInfo struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Token    string
	JobID    string
}

// JobRes holds responses for Job info method
type JobRes struct {
	JID                   int      `msgpack:"jid"`
	Name                  string   `msgpack:"name"`
	StartTime             uint64   `msgpack:"start_time"`
	URIPath               string   `msgpack:"uri_path"`
	DataStore             []string `msgpack:",omitempty"`
	EnableContextEncoding bool     `msgpack:"EnableContextEncoding"`
	DisablePayloadHandler bool     `msgpack:"DisablePayloadHandler"`
	SSL                   bool     `msgpack:"ssl"`
	SSLVersion            string   `msgpack:"SSLVersion"`
	SRVHost               string   `msgpack:"SRVHOST"`
	SRVPort               string   `msgpack:"SRVPORT"`
	PayLoad               string   `msgpack:"PAYLOAD"`
	LHost                 string   `msgpack:"LHOST"`
	LPort                 string   `msgpack:"LPORT"`
}

// MSPLOIT holds config/auth info
type MSPLOIT struct {
	host  string
	user  string
	pass  string
	token string
}

// New function to create new struct populating user/auth fields
func New(host, user, pass string) (*MSPLOIT, error) {
	msf := &MSPLOIT{
		host: host,
		user: user,
		pass: pass,
	}

	if err := msf.Login(); err != nil {
		return nil, err
	}
	return msf, nil
}

func (msf *MSPLOIT) send(req interface{}, res interface{}) error {
	buf := new(bytes.Buffer)
	msgpack.NewEncoder(buf).Encode(req)
	dest := fmt.Sprintf("http://%s/api", msf.host)
	rp, err := http.Post(dest, "binary/message-pack", buf)
	if err != nil {
		return err
	}
	defer rp.Body.Close()

	if err := msgpack.NewDecoder(rp.Body).Decode(&res); err != nil {
		return err
	}
	return nil

}

func (msf *MSPLOIT) Login() error {
	ctx := &loginReq{
		Method:   "auth.login",
		Username: msf.user,
		Password: msf.pass,
	}
	var res loginRes
	if err := msf.send(ctx, &res); err != nil {
		return err
	}
	msf.token = res.Token
	return nil
}

func (msf *MSPLOIT) Logout() error {
	ctx := logoutReq{
		Method:      "auth.logout",
		Token:       msf.token,
		LogoutToken: msf.token,
	}
	var res logoutRes
	if err := msf.send(ctx, &res); err != nil {
		return err
	}
	msf.token = ""
	return nil
}

func (msf *MSPLOIT) SessionList() (map[uint32]ListRes, error) {
	req := &ListReq{Method: "session.list", Token: msf.token}
	res := make(map[uint32]ListRes)
	if err := msf.send(req, &res); err != nil {
		return nil, err
	}
	for id, session := range res {
		session.ID = id
		res[id] = session
	}
	return res, nil
}
