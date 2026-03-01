package store

import "searchable-encryption-go/server/sse"

// InMemory is a stateful in-memory implementation of server backend.
type InMemory struct {
	state sse.State
}

// NewInMemory creates an empty server backend.
func NewInMemory() *InMemory {
	return &InMemory{
		state: sse.State{
			Index:     make(map[string][]sse.Posting),
			Documents: make(map[string]sse.EncryptedDocument),
		},
	}
}

// NewInMemoryFromState restores backend from persisted state.
func NewInMemoryFromState(state sse.State) *InMemory {
	backend := NewInMemory()
	backend.state = cloneState(state)
	if backend.state.Index == nil {
		backend.state.Index = make(map[string][]sse.Posting)
	}
	if backend.state.Documents == nil {
		backend.state.Documents = make(map[string]sse.EncryptedDocument)
	}
	return backend
}

func (m *InMemory) AddPosting(token string, posting sse.Posting) {
	m.state.Index[token] = append(m.state.Index[token], sse.Posting{
		Counter:    posting.Counter,
		Ciphertext: append([]byte(nil), posting.Ciphertext...),
	})
}

func (m *InMemory) Postings(token string) []sse.Posting {
	src := m.state.Index[token]
	dst := make([]sse.Posting, len(src))
	for i, posting := range src {
		dst[i] = sse.Posting{
			Counter:    posting.Counter,
			Ciphertext: append([]byte(nil), posting.Ciphertext...),
		}
	}
	return dst
}

func (m *InMemory) PutDocument(handle string, doc sse.EncryptedDocument) {
	m.state.Documents[handle] = sse.EncryptedDocument{
		Nonce:      append([]byte(nil), doc.Nonce...),
		Ciphertext: append([]byte(nil), doc.Ciphertext...),
	}
}

func (m *InMemory) GetDocument(handle string) (sse.EncryptedDocument, bool) {
	doc, ok := m.state.Documents[handle]
	if !ok {
		return sse.EncryptedDocument{}, false
	}
	return sse.EncryptedDocument{
		Nonce:      append([]byte(nil), doc.Nonce...),
		Ciphertext: append([]byte(nil), doc.Ciphertext...),
	}, true
}

// State exports deep-copied server state for persistence.
func (m *InMemory) State() sse.State {
	return cloneState(m.state)
}

func cloneState(src sse.State) sse.State {
	out := sse.State{
		Index:     make(map[string][]sse.Posting, len(src.Index)),
		Documents: make(map[string]sse.EncryptedDocument, len(src.Documents)),
	}
	for token, postings := range src.Index {
		copied := make([]sse.Posting, len(postings))
		for i, posting := range postings {
			copied[i] = sse.Posting{
				Counter:    posting.Counter,
				Ciphertext: append([]byte(nil), posting.Ciphertext...),
			}
		}
		out.Index[token] = copied
	}
	for handle, doc := range src.Documents {
		out.Documents[handle] = sse.EncryptedDocument{
			Nonce:      append([]byte(nil), doc.Nonce...),
			Ciphertext: append([]byte(nil), doc.Ciphertext...),
		}
	}
	return out
}
