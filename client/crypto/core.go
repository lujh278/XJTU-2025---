package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"searchable-encryption-go/server/sse"
)

const keySize = 32

var (
	textKeywordPattern   = regexp.MustCompile(`[a-z0-9]+`)
	singleKeywordPattern = regexp.MustCompile(`^[a-z0-9]+$`)
)

// MasterKey contains all symmetric keys required by this SSE prototype.
type MasterKey struct {
	TokenKey []byte `json:"token_key"`
	RefKey   []byte `json:"ref_key"`
	DocKey   []byte `json:"doc_key"`
}

// NewMasterKey generates a new random key set.
func NewMasterKey() (MasterKey, error) {
	key := MasterKey{
		TokenKey: make([]byte, keySize),
		RefKey:   make([]byte, keySize),
		DocKey:   make([]byte, keySize),
	}
	if _, err := rand.Read(key.TokenKey); err != nil {
		return MasterKey{}, fmt.Errorf("generate token key: %w", err)
	}
	if _, err := rand.Read(key.RefKey); err != nil {
		return MasterKey{}, fmt.Errorf("generate ref key: %w", err)
	}
	if _, err := rand.Read(key.DocKey); err != nil {
		return MasterKey{}, fmt.Errorf("generate doc key: %w", err)
	}
	return key, nil
}

// Validate ensures key lengths are correct.
func (k MasterKey) Validate() error {
	switch {
	case len(k.TokenKey) != keySize:
		return fmt.Errorf("invalid token key length: %d", len(k.TokenKey))
	case len(k.RefKey) != keySize:
		return fmt.Errorf("invalid ref key length: %d", len(k.RefKey))
	case len(k.DocKey) != keySize:
		return fmt.Errorf("invalid doc key length: %d", len(k.DocKey))
	default:
		return nil
	}
}

// ClientState stores local metadata needed for updates.
type ClientState struct {
	KeywordCounters map[string]uint64 `json:"keyword_counters"`
}

// NewClientState creates a default client state.
func NewClientState() ClientState {
	return ClientState{KeywordCounters: make(map[string]uint64)}
}

// SearchResult is a decrypted matching document.
type SearchResult struct {
	ID   string `json:"id"`
	Body string `json:"body"`
}

type plainDocument struct {
	ID   string `json:"id"`
	Body string `json:"body"`
}

// Client performs all crypto operations and talks to an abstract server backend.
type Client struct {
	key    MasterKey
	state  ClientState
	server sse.Backend
}

// NewClient builds an SSE client over a given server backend.
func NewClient(key MasterKey, state ClientState, server sse.Backend) (*Client, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	if server == nil {
		return nil, errors.New("server backend is nil")
	}
	if state.KeywordCounters == nil {
		state.KeywordCounters = make(map[string]uint64)
	}
	return &Client{key: key, state: state, server: server}, nil
}

// State returns a copy of client state for persistence.
func (c *Client) State() ClientState {
	stateCopy := ClientState{KeywordCounters: make(map[string]uint64, len(c.state.KeywordCounters))}
	for keyword, count := range c.state.KeywordCounters {
		stateCopy.KeywordCounters[keyword] = count
	}
	return stateCopy
}

// AddDocument encrypts a document and updates the encrypted index.
func (c *Client) AddDocument(id, body string) (int, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return 0, errors.New("document id is empty")
	}
	if body == "" {
		return 0, errors.New("document body is empty")
	}

	handle, err := randomHandle()
	if err != nil {
		return 0, err
	}

	payload, err := json.Marshal(plainDocument{ID: id, Body: body})
	if err != nil {
		return 0, fmt.Errorf("marshal document: %w", err)
	}
	encryptedDoc, err := encryptDocument(c.key.DocKey, payload)
	if err != nil {
		return 0, err
	}
	c.server.PutDocument(handle, encryptedDoc)

	keywords := extractKeywords(body)
	for _, keyword := range keywords {
		counter := c.state.KeywordCounters[keyword]
		tokenBytes := deriveToken(c.key.TokenKey, keyword)
		tokenHex := hex.EncodeToString(tokenBytes)
		maskedHandle := maskReference(c.key.RefKey, tokenBytes, counter, []byte(handle))
		c.server.AddPosting(tokenHex, sse.Posting{Counter: counter, Ciphertext: maskedHandle})
		c.state.KeywordCounters[keyword] = counter + 1
	}

	return len(keywords), nil
}

// SearchAND searches with AND semantics over all given keywords.
func (c *Client) SearchAND(keywords []string) ([]SearchResult, error) {
	if len(keywords) == 0 {
		return nil, errors.New("no keywords provided")
	}

	normalized := make([]string, 0, len(keywords))
	for _, keyword := range keywords {
		k, err := normalizeKeyword(keyword)
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, k)
	}

	var matchedHandles map[string]struct{}
	for i, keyword := range normalized {
		tokenBytes := deriveToken(c.key.TokenKey, keyword)
		tokenHex := hex.EncodeToString(tokenBytes)
		postings := c.server.Postings(tokenHex)
		if len(postings) == 0 {
			return []SearchResult{}, nil
		}

		current := make(map[string]struct{}, len(postings))
		for _, posting := range postings {
			handle := string(maskReference(c.key.RefKey, tokenBytes, posting.Counter, posting.Ciphertext))
			current[handle] = struct{}{}
		}

		if i == 0 {
			matchedHandles = current
			continue
		}
		for handle := range matchedHandles {
			if _, ok := current[handle]; !ok {
				delete(matchedHandles, handle)
			}
		}
		if len(matchedHandles) == 0 {
			return []SearchResult{}, nil
		}
	}

	results := make([]SearchResult, 0, len(matchedHandles))
	for handle := range matchedHandles {
		encryptedDoc, ok := c.server.GetDocument(handle)
		if !ok {
			continue
		}
		plaintext, err := decryptDocument(c.key.DocKey, encryptedDoc)
		if err != nil {
			continue
		}
		var document plainDocument
		if err := json.Unmarshal(plaintext, &document); err != nil {
			continue
		}
		results = append(results, SearchResult{ID: document.ID, Body: document.Body})
	}

	sort.Slice(results, func(i, j int) bool { return results[i].ID < results[j].ID })
	return results, nil
}

func normalizeKeyword(input string) (string, error) {
	token := strings.ToLower(strings.TrimSpace(input))
	if token == "" {
		return "", errors.New("keyword is empty")
	}
	if !singleKeywordPattern.MatchString(token) {
		return "", fmt.Errorf("invalid keyword %q: only [a-z0-9] is allowed", input)
	}
	return token, nil
}

func extractKeywords(input string) []string {
	matches := textKeywordPattern.FindAllString(strings.ToLower(input), -1)
	unique := make(map[string]struct{}, len(matches))
	for _, word := range matches {
		unique[word] = struct{}{}
	}
	out := make([]string, 0, len(unique))
	for keyword := range unique {
		out = append(out, keyword)
	}
	sort.Strings(out)
	return out
}

func deriveToken(tokenKey []byte, keyword string) []byte {
	mac := hmac.New(sha256.New, tokenKey)
	mac.Write([]byte(keyword))
	return mac.Sum(nil)
}

func maskReference(refKey, token []byte, counter uint64, value []byte) []byte {
	stream := make([]byte, len(value))
	var block uint64
	for offset := 0; offset < len(stream); {
		mac := hmac.New(sha256.New, refKey)
		mac.Write(token)
		var buf [16]byte
		binary.BigEndian.PutUint64(buf[:8], counter)
		binary.BigEndian.PutUint64(buf[8:], block)
		mac.Write(buf[:])
		maskBlock := mac.Sum(nil)
		offset += copy(stream[offset:], maskBlock)
		block++
	}
	masked := make([]byte, len(value))
	for i := range value {
		masked[i] = value[i] ^ stream[i]
	}
	return masked
}

func randomHandle() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate handle: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func encryptDocument(docKey, plaintext []byte) (sse.EncryptedDocument, error) {
	block, err := aes.NewCipher(docKey)
	if err != nil {
		return sse.EncryptedDocument{}, fmt.Errorf("create aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return sse.EncryptedDocument{}, fmt.Errorf("create gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return sse.EncryptedDocument{}, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return sse.EncryptedDocument{Nonce: nonce, Ciphertext: ciphertext}, nil
}

func decryptDocument(docKey []byte, encrypted sse.EncryptedDocument) ([]byte, error) {
	block, err := aes.NewCipher(docKey)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, encrypted.Nonce, encrypted.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt document: %w", err)
	}
	return plaintext, nil
}
