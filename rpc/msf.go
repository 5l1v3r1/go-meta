package msf

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

// Struct to change data to MSGPack format
type listReq struct {
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
