package sse

// Posting stores one encrypted handle entry for a keyword token.
type Posting struct {
	Counter    uint64 `json:"counter"`
	Ciphertext []byte `json:"ciphertext"`
}

// EncryptedDocument stores encrypted document payload.
type EncryptedDocument struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// State is serializable server-side storage state.
type State struct {
	Index     map[string][]Posting         `json:"index"`
	Documents map[string]EncryptedDocument `json:"documents"`
}

// Backend exposes only server operations needed by the client protocol.
type Backend interface {
	AddPosting(token string, posting Posting)
	Postings(token string) []Posting
	PutDocument(handle string, doc EncryptedDocument)
	GetDocument(handle string) (EncryptedDocument, bool)
}

// Snapshotter is a backend that can export full state for persistence.
type Snapshotter interface {
	Backend
	State() State
}
