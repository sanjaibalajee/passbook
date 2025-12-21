package age

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const (
	armorHeader = "-----BEGIN AGE ENCRYPTED FILE-----"
	armorFooter = "-----END AGE ENCRYPTED FILE-----"
	lineLength  = 64
)

// ArmorWriter wraps a writer to produce ASCII-armored output
type ArmorWriter struct {
	w       io.Writer
	buf     bytes.Buffer
	started bool
	closed  bool
}

// NewArmorWriter creates a new armor writer
func NewArmorWriter(w io.Writer) *ArmorWriter {
	return &ArmorWriter{w: w}
}

// Write implements io.Writer
func (a *ArmorWriter) Write(p []byte) (int, error) {
	if a.closed {
		return 0, io.ErrClosedPipe
	}

	if !a.started {
		if _, err := fmt.Fprintln(a.w, armorHeader); err != nil {
			return 0, err
		}
		a.started = true
	}

	// Buffer the raw data
	return a.buf.Write(p)
}

// Close finishes the armored output
func (a *ArmorWriter) Close() error {
	if a.closed {
		return nil
	}
	a.closed = true

	if !a.started {
		if _, err := fmt.Fprintln(a.w, armorHeader); err != nil {
			return err
		}
	}

	// Encode and write in lines
	encoded := base64.StdEncoding.EncodeToString(a.buf.Bytes())

	for i := 0; i < len(encoded); i += lineLength {
		end := i + lineLength
		if end > len(encoded) {
			end = len(encoded)
		}
		if _, err := fmt.Fprintln(a.w, encoded[i:end]); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintln(a.w, armorFooter)
	return err
}

// ArmorReader reads ASCII-armored age files
type ArmorReader struct {
	r    io.Reader
	buf  *bytes.Reader
	done bool
}

// NewArmorReader creates a new armor reader
func NewArmorReader(r io.Reader) *ArmorReader {
	return &ArmorReader{r: r}
}

// Read implements io.Reader
func (a *ArmorReader) Read(p []byte) (int, error) {
	if a.buf == nil {
		if err := a.parseArmor(); err != nil {
			return 0, err
		}
	}

	return a.buf.Read(p)
}

// parseArmor parses the ASCII armor and decodes the content
func (a *ArmorReader) parseArmor() error {
	scanner := bufio.NewScanner(a.r)
	var inBlock bool
	var encodedLines []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == armorHeader {
			inBlock = true
			continue
		}

		if line == armorFooter {
			break
		}

		if inBlock && line != "" {
			encodedLines = append(encodedLines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// Join and decode
	encoded := strings.Join(encodedLines, "")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("failed to decode armor: %w", err)
	}

	a.buf = bytes.NewReader(decoded)
	return nil
}

// IsArmored checks if data is ASCII-armored
func IsArmored(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(data), []byte(armorHeader))
}
