package main

import (
	"errors"
	"flag"
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
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}

	switch args[0] {
	case "init":
		return runInit(args[1:])
	case "add":
		return runAdd(args[1:])
	case "search":
		return runSearch(args[1:])
	default:
		return usageError()
	}
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	clientDir := fs.String("client-dir", "client/data", "client private state directory")
	serverDir := fs.String("server-dir", "server/data", "server state directory")
	force := fs.Bool("force", false, "overwrite existing state files")
	if err := fs.Parse(args); err != nil {
		return err
	}

	paths := newSystemPaths(*clientDir, *serverDir)
	if !*force {
		if _, err := os.Stat(paths.KeyPath); err == nil {
			return fmt.Errorf("client state already initialized in %s (use --force to overwrite)", paths.ClientDir)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if _, err := os.Stat(paths.ServerStatePath); err == nil {
			return fmt.Errorf("server state already initialized in %s (use --force to overwrite)", paths.ServerDir)
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

	fmt.Printf("initialized single-user SSE model\n")
	fmt.Printf("client state: %s\n", paths.ClientDir)
	fmt.Printf("server state: %s\n", paths.ServerDir)
	return nil
}

func runAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	clientDir := fs.String("client-dir", "client/data", "client private state directory")
	serverDir := fs.String("server-dir", "server/data", "server state directory")
	id := fs.String("id", "", "document id")
	text := fs.String("text", "", "document plaintext")
	path := fs.String("path", "", "path to document file (.pdf/.docx/.txt)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	idValue := strings.TrimSpace(*id)
	textValue := strings.TrimSpace(*text)
	pathValue := strings.TrimSpace(*path)

	if textValue != "" && pathValue != "" {
		return errors.New("use either --text or --path, not both")
	}

	if pathValue != "" {
		loadedText, err := crypto.LoadDocumentTextFromPath(pathValue)
		if err != nil {
			return fmt.Errorf("load document from --path: %w", err)
		}
		textValue = loadedText
		if idValue == "" {
			idValue = crypto.DefaultDocumentIDFromPath(pathValue)
		}
	}

	if idValue == "" {
		return errors.New("missing --id (or provide --path to auto-use filename)")
	}
	if textValue == "" {
		return errors.New("missing content: provide --text or --path")
	}

	paths := newSystemPaths(*clientDir, *serverDir)
	client, backend, err := loadSystem(paths)
	if err != nil {
		return err
	}

	keywordCount, err := client.AddDocument(idValue, textValue)
	if err != nil {
		return err
	}

	if err := store.SaveState(paths.ServerStatePath, backend); err != nil {
		return err
	}
	if err := crypto.SaveClientState(paths.ClientStatePath, client.State()); err != nil {
		return err
	}

	fmt.Printf("added %q with %d indexed keywords\n", idValue, keywordCount)
	if pathValue != "" {
		fmt.Printf("source file: %s\n", pathValue)
	}
	return nil
}

func runSearch(args []string) error {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	clientDir := fs.String("client-dir", "client/data", "client private state directory")
	serverDir := fs.String("server-dir", "server/data", "server state directory")
	keywordsArg := fs.String("keywords", "", "comma-separated keywords, e.g. cloud,storage")
	if err := fs.Parse(args); err != nil {
		return err
	}

	keywords := splitKeywords(*keywordsArg)
	if len(keywords) == 0 {
		return errors.New("missing --keywords")
	}

	paths := newSystemPaths(*clientDir, *serverDir)
	client, _, err := loadSystem(paths)
	if err != nil {
		return err
	}

	results, err := client.SearchAND(keywords)
	if err != nil {
		return err
	}

	if len(results) == 0 {
		fmt.Println("no matching documents")
		return nil
	}
	for i, result := range results {
		fmt.Printf("%d. %s\n", i+1, result.ID)
		fmt.Printf("   %s\n", result.Body)
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

func newSystemPaths(clientDir, serverDir string) systemPaths {
	return systemPaths{
		ClientDir:       clientDir,
		ServerDir:       serverDir,
		KeyPath:         filepath.Join(clientDir, "master_key.json"),
		ClientStatePath: filepath.Join(clientDir, "client_state.json"),
		ServerStatePath: filepath.Join(serverDir, "server_state.json"),
	}
}

func splitKeywords(input string) []string {
	raw := strings.Split(input, ",")
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func usageError() error {
	return errors.New(
		"usage:\n" +
			"  sse-cli init [--client-dir client/data] [--server-dir server/data] [--force]\n" +
			"  sse-cli add [--client-dir client/data] [--server-dir server/data] [--id <doc-id>] [--text <plaintext>] [--path <file.pdf|file.docx|file.txt>]\n" +
			"  sse-cli search [--client-dir client/data] [--server-dir server/data] --keywords <k1,k2,...>",
	)
}
