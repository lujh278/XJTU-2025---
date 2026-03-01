package crypto

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	pdfTjPattern      = regexp.MustCompile(`\((?:\\.|[^\\()])*\)\s*Tj`)
	pdfTJPattern      = regexp.MustCompile(`(?s)\[(.*?)\]\s*TJ`)
	pdfLiteralPattern = regexp.MustCompile(`\((?:\\.|[^\\()])*\)`)
)

// LoadDocumentTextFromPath extracts plaintext content from a document file.
// Supported formats: .pdf, .docx, .txt.
func LoadDocumentTextFromPath(path string) (string, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".pdf":
		return loadPDFText(path)
	case ".docx":
		return loadDOCXText(path)
	case ".txt":
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read txt file: %w", err)
		}
		text := normalizeExtractedText(string(data))
		if text == "" {
			return "", errors.New("empty text extracted from txt")
		}
		return text, nil
	default:
		return "", fmt.Errorf("unsupported file extension %q, only .pdf and .docx are required", ext)
	}
}

// DefaultDocumentIDFromPath derives a stable ID from file name.
// To reduce collisions for same basename with different extensions,
// extension suffix is appended (e.g. report_pdf, report_docx).
func DefaultDocumentIDFromPath(path string) string {
	name := strings.TrimSpace(filepath.Base(path))
	if name == "" {
		return "doc"
	}
	base := strings.TrimSpace(strings.TrimSuffix(name, filepath.Ext(name)))
	if base == "" {
		base = "doc"
	}
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
	if ext == "" {
		return base
	}
	return fmt.Sprintf("%s_%s", base, ext)
}

func loadDOCXText(path string) (string, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return "", fmt.Errorf("open docx: %w", err)
	}
	defer zr.Close()

	parts := make(map[string][]byte)
	for _, f := range zr.File {
		name := strings.ToLower(strings.ReplaceAll(f.Name, "\\", "/"))
		isDocument := strings.HasSuffix(name, "word/document.xml")
		isHeader := strings.Contains(name, "/word/header") && strings.HasSuffix(name, ".xml")
		isFooter := strings.Contains(name, "/word/footer") && strings.HasSuffix(name, ".xml")
		if !(isDocument || isHeader || isFooter) {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return "", fmt.Errorf("open docx part %s: %w", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return "", fmt.Errorf("read docx part %s: %w", f.Name, err)
		}
		parts[name] = data
	}

	if len(parts) == 0 {
		return "", errors.New("docx missing word/document.xml")
	}

	names := make([]string, 0, len(parts))
	for name := range parts {
		names = append(names, name)
	}
	sort.Strings(names)

	var builder strings.Builder
	for _, name := range names {
		text := extractTextFromXML(parts[name])
		if text != "" {
			if builder.Len() > 0 {
				builder.WriteByte('\n')
			}
			builder.WriteString(text)
		}
	}

	result := normalizeExtractedText(builder.String())
	if result == "" {
		return "", errors.New("empty text extracted from docx")
	}
	return result, nil
}

func loadPDFText(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read pdf file: %w", err)
	}

	streams := collectPDFStreams(data)
	if len(streams) == 0 {
		return "", errors.New("pdf has no readable streams")
	}

	fragments := make([]string, 0, len(streams))
	for _, stream := range streams {
		decoded := decodePDFStream(stream)
		text := extractTextFromPDFContent(decoded)
		if text != "" {
			fragments = append(fragments, text)
		}
	}

	result := normalizeExtractedText(strings.Join(fragments, "\n"))
	if result == "" {
		return "", errors.New("empty text extracted from pdf (possibly scanned image PDF)")
	}
	return result, nil
}

func extractTextFromXML(data []byte) string {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var builder strings.Builder

	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			break
		}

		switch tok := token.(type) {
		case xml.StartElement:
			switch strings.ToLower(tok.Name.Local) {
			case "p", "tr", "br":
				builder.WriteByte('\n')
			case "tab":
				builder.WriteByte(' ')
			}
		case xml.CharData:
			builder.WriteString(string(tok))
		}
	}

	return normalizeExtractedText(builder.String())
}

func collectPDFStreams(data []byte) [][]byte {
	streams := make([][]byte, 0)
	cursor := 0
	for {
		idx := bytes.Index(data[cursor:], []byte("stream"))
		if idx < 0 {
			break
		}
		start := cursor + idx + len("stream")
		if start < len(data) && data[start] == '\r' {
			start++
			if start < len(data) && data[start] == '\n' {
				start++
			}
		} else if start < len(data) && data[start] == '\n' {
			start++
		}

		endRel := bytes.Index(data[start:], []byte("endstream"))
		if endRel < 0 {
			break
		}
		end := start + endRel
		chunk := bytes.TrimRight(data[start:end], "\r\n")
		streams = append(streams, append([]byte(nil), chunk...))
		cursor = end + len("endstream")
	}
	return streams
}

func decodePDFStream(stream []byte) []byte {
	reader := flate.NewReader(bytes.NewReader(stream))
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil || len(decoded) == 0 {
		return stream
	}
	return decoded
}

func extractTextFromPDFContent(content []byte) string {
	fragments := make([]string, 0)

	for _, match := range pdfTjPattern.FindAll(content, -1) {
		lit := pdfLiteralPattern.Find(match)
		if len(lit) == 0 {
			continue
		}
		text := strings.TrimSpace(decodePDFLiteral(lit))
		if text != "" {
			fragments = append(fragments, text)
		}
	}

	for _, arr := range pdfTJPattern.FindAll(content, -1) {
		lits := pdfLiteralPattern.FindAll(arr, -1)
		if len(lits) == 0 {
			continue
		}
		parts := make([]string, 0, len(lits))
		for _, lit := range lits {
			text := strings.TrimSpace(decodePDFLiteral(lit))
			if text != "" {
				parts = append(parts, text)
			}
		}
		if len(parts) > 0 {
			fragments = append(fragments, strings.Join(parts, ""))
		}
	}

	return normalizeExtractedText(strings.Join(fragments, "\n"))
}

func decodePDFLiteral(literal []byte) string {
	if len(literal) >= 2 && literal[0] == '(' && literal[len(literal)-1] == ')' {
		literal = literal[1 : len(literal)-1]
	}

	out := make([]byte, 0, len(literal))
	for i := 0; i < len(literal); i++ {
		ch := literal[i]
		if ch != '\\' {
			out = append(out, ch)
			continue
		}
		i++
		if i >= len(literal) {
			break
		}
		esc := literal[i]
		switch esc {
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case '(', ')', '\\':
			out = append(out, esc)
		case '\n':
			// line continuation
		case '\r':
			if i+1 < len(literal) && literal[i+1] == '\n' {
				i++
			}
			// line continuation
		default:
			if esc >= '0' && esc <= '7' {
				octal := []byte{esc}
				for j := 0; j < 2 && i+1 < len(literal) && literal[i+1] >= '0' && literal[i+1] <= '7'; j++ {
					i++
					octal = append(octal, literal[i])
				}
				value, err := strconv.ParseInt(string(octal), 8, 32)
				if err == nil {
					out = append(out, byte(value))
				}
			} else {
				out = append(out, esc)
			}
		}
	}

	if len(out) >= 2 && out[0] == 0xFE && out[1] == 0xFF {
		u16 := make([]uint16, 0, (len(out)-2)/2)
		for i := 2; i+1 < len(out); i += 2 {
			u16 = append(u16, uint16(out[i])<<8|uint16(out[i+1]))
		}
		return string(utf16.Decode(u16))
	}

	if utf8.Valid(out) {
		return string(out)
	}

	runes := make([]rune, len(out))
	for i, b := range out {
		runes[i] = rune(b)
	}
	return string(runes)
}

func normalizeExtractedText(input string) string {
	input = strings.ReplaceAll(input, "\u0000", "")
	input = strings.ReplaceAll(input, "\uFEFF", "")
	input = strings.ReplaceAll(input, "\r", "\n")

	lines := strings.Split(input, "\n")
	clean := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.Join(strings.Fields(line), " ")
		if line != "" {
			clean = append(clean, line)
		}
	}
	return strings.TrimSpace(strings.Join(clean, "\n"))
}
