package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"searchable-encryption-go/client/crypto"
	"searchable-encryption-go/server/store"
)

type systemPaths struct {
	ClientDir       string
	ServerDir       string
	KeyPath         string
	ClientStatePath string
	ServerStatePath string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("=== SSE Terminal UI (Single User / Single Server) ===")
	fmt.Print("Client state dir (default ./client/data): ")
	clientInput, err := readLine(reader)
	if err != nil {
		return err
	}
	clientDir := strings.TrimSpace(clientInput)
	if clientDir == "" {
		clientDir = "client/data"
	}

	fmt.Print("Server state dir (default ./server/data): ")
	serverInput, err := readLine(reader)
	if err != nil {
		return err
	}
	serverDir := strings.TrimSpace(serverInput)
	if serverDir == "" {
		serverDir = "server/data"
	}

	paths := newSystemPaths(clientDir, serverDir)

	for {
		fmt.Println()
		fmt.Println("Select action:")
		fmt.Println("1) Initialize")
		fmt.Println("2) Add document")
		fmt.Println("3) Search documents (AND)")
		fmt.Println("4) Exit")
		fmt.Print("Choice: ")

		choice, err := readLine(reader)
		if err != nil {
			return err
		}
		switch strings.TrimSpace(choice) {
		case "1":
			if err := actionInit(reader, paths); err != nil {
				fmt.Printf("Init failed: %v\n", err)
			}
		case "2":
			if err := actionAdd(reader, paths); err != nil {
				fmt.Printf("Add failed: %v\n", err)
			}
		case "3":
			if err := actionSearch(reader, paths); err != nil {
				fmt.Printf("Search failed: %v\n", err)
			}
		case "4":
			fmt.Println("Bye.")
			return nil
		default:
			fmt.Println("Invalid choice.")
		}
	}
}

func actionInit(reader *bufio.Reader, paths systemPaths) error {
	fmt.Print("Force overwrite existing state? (y/N): ")
	forceInput, err := readLine(reader)
	if err != nil {
		return err
	}
	force := strings.EqualFold(strings.TrimSpace(forceInput), "y")

	if !force {
		if _, err := os.Stat(paths.KeyPath); err == nil {
			return fmt.Errorf("client state already exists in %s (choose force to overwrite)", paths.ClientDir)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if _, err := os.Stat(paths.ServerStatePath); err == nil {
			return fmt.Errorf("server state already exists in %s (choose force to overwrite)", paths.ServerDir)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	key, err := crypto.NewMasterKey()
	if err != nil {
		return err
	}
	backend := store.NewInMemory()
	clientState := crypto.NewClientState()

	if err := crypto.SaveMasterKey(paths.KeyPath, key); err != nil {
		return err
	}
	if err := crypto.SaveClientState(paths.ClientStatePath, clientState); err != nil {
		return err
	}
	if err := store.SaveState(paths.ServerStatePath, backend); err != nil {
		return err
	}

	fmt.Printf("Initialized. client=%s server=%s\n", paths.ClientDir, paths.ServerDir)
	return nil
}

func actionAdd(reader *bufio.Reader, paths systemPaths) error {
	client, backend, err := loadSystem(paths)
	if err != nil {
		return err
	}

	fmt.Println("Add mode:")
	fmt.Println("1) Manual input (ID + text)")
	fmt.Println("2) File path import (path, optional ID)")
	fmt.Print("Choice (1/2): ")
	mode, err := readLine(reader)
	if err != nil {
		return err
	}
	mode = strings.TrimSpace(mode)

	var id string
	var body string

	switch mode {
	case "1":
		fmt.Print("Document ID: ")
		id, err = readLine(reader)
		if err != nil {
			return err
		}
		fmt.Print("Document text: ")
		body, err = readLine(reader)
		if err != nil {
			return err
		}
	case "2":
		fmt.Print("Document path (supports .docx/.txt): ")
		docPath, err := readLine(reader)
		if err != nil {
			return err
		}
		docPath = strings.TrimSpace(docPath)
		if docPath == "" {
			return errors.New("document path is empty")
		}

		body, err = crypto.LoadDocumentTextFromPath(docPath)
		if err != nil {
			return err
		}

		fmt.Print("Document ID (optional, empty to use file name): ")
		id, err = readLine(reader)
		if err != nil {
			return err
		}
		id = strings.TrimSpace(id)
		if id == "" {
			id = crypto.DefaultDocumentIDFromPath(docPath)
		}
		fmt.Printf("Extracted %d chars from file\n", len(body))
	default:
		return errors.New("invalid add mode, choose 1 or 2")
	}

	id = strings.TrimSpace(id)
	body = strings.TrimSpace(body)
	if id == "" {
		return errors.New("document id is empty")
	}
	if body == "" {
		return errors.New("document body is empty")
	}

	count, err := client.AddDocument(id, body)
	if err != nil {
		return err
	}
	if err := store.SaveState(paths.ServerStatePath, backend); err != nil {
		return err
	}
	if err := crypto.SaveClientState(paths.ClientStatePath, client.State()); err != nil {
		return err
	}

	fmt.Printf("Added successfully, indexed keywords: %d\n", count)
	return nil
}

func actionSearch(reader *bufio.Reader, paths systemPaths) error {
	client, _, err := loadSystem(paths)
	if err != nil {
		return err
	}

	fmt.Print("Keywords (comma separated, AND): ")
	line, err := readLine(reader)
	if err != nil {
		return err
	}
	keywords := splitKeywords(line)
	if len(keywords) == 0 {
		return errors.New("keywords are empty")
	}

	results, err := client.SearchAND(keywords)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		fmt.Println("No matching documents.")
		return nil
	}

	fmt.Printf("Matched %d docs:\n", len(results))
	for i, item := range results {
		fmt.Printf("%d. %s\n", i+1, item.ID)
		fmt.Printf("   %s\n", item.Body)
	}
	return nil
}

func loadSystem(paths systemPaths) (*crypto.Client, *store.InMemory, error) {
	key, err := crypto.LoadMasterKey(paths.KeyPath)
	if err != nil {
		return nil, nil, err
	}
	backend, err := store.LoadState(paths.ServerStatePath)
	if err != nil {
		return nil, nil, err
	}
	state, err := crypto.LoadClientState(paths.ClientStatePath)
	if err != nil {
		return nil, nil, err
	}
	client, err := crypto.NewClient(key, state, backend)
	if err != nil {
		return nil, nil, err
	}
	return client, backend, nil
}

func splitKeywords(input string) []string {
	parts := strings.Split(input, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		item := strings.TrimSpace(p)
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		if errors.Is(err, os.ErrClosed) {
			return "", err
		}
		if len(line) == 0 {
			return "", err
		}
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func newSystemPaths(clientDir, serverDir string) systemPaths {
	return systemPaths{
		ClientDir:       clientDir,
		ServerDir:       serverDir,
		KeyPath:         filepath.Join(clientDir, "master_key.json"),
		ClientStatePath: filepath.Join(clientDir, "client_state.json"),
		ServerStatePath: filepath.Join(serverDir, "server_state.json"),
	}
}
