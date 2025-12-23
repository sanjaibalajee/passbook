package age

import (
	"bytes"
	"io"

	"filippo.io/age/armor"
)

// ArmorWriter wraps age's built-in armor writer
// Deprecated: Use armor.NewWriter from filippo.io/age/armor directly
type ArmorWriter struct {
	w      io.WriteCloser
	closed bool
}

// NewArmorWriter creates a new armor writer using age's built-in armor
// Deprecated: Use armor.NewWriter from filippo.io/age/armor directly
func NewArmorWriter(w io.Writer) *ArmorWriter {
	return &ArmorWriter{w: armor.NewWriter(w)}
}

// Write implements io.Writer
func (a *ArmorWriter) Write(p []byte) (int, error) {
	return a.w.Write(p)
}

// Close finishes the armored output
func (a *ArmorWriter) Close() error {
	if a.closed {
		return nil
	}
	a.closed = true
	return a.w.Close()
}

// ArmorReader wraps age's built-in armor reader
// Deprecated: Use armor.NewReader from filippo.io/age/armor directly
type ArmorReader struct {
	r io.Reader
}

// NewArmorReader creates a new armor reader using age's built-in armor
// Deprecated: Use armor.NewReader from filippo.io/age/armor directly
func NewArmorReader(r io.Reader) *ArmorReader {
	return &ArmorReader{r: armor.NewReader(r)}
}

// Read implements io.Reader
func (a *ArmorReader) Read(p []byte) (int, error) {
	return a.r.Read(p)
}

// IsArmoredLegacy checks if data is ASCII-armored
// Deprecated: Use IsArmored from the age package instead
func IsArmoredLegacy(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN AGE ENCRYPTED FILE-----"))
}
