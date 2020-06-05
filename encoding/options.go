package encoding

import "github.com/pkg/errors"

// EncodeOptions ...
type EncodeOptions struct {
	// NoPadding, for encodings that can disable padding (base64, base32).
	NoPadding bool
	// Lowercase, for encodings that can be upper or lower case, use lowercase (base32).
	Lowercase bool
}

// EncodeOption ...
type EncodeOption struct {
	Apply     func(*EncodeOptions)
	Encodings []Encoding
	Name      string
}

func newEncodeOptions(opts []EncodeOption, encoding Encoding) (EncodeOptions, error) {
	var options EncodeOptions
	for _, o := range opts {
		if !containsEncoding(o.Encodings, encoding) {
			return options, errors.Errorf("invalid option: %s", o.Name)
		}
		o.Apply(&options)
	}
	return options, nil
}

// NoPadding ...
func NoPadding() EncodeOption {
	apply := func(o *EncodeOptions) {
		o.NoPadding = true
	}
	return EncodeOption{
		Apply:     apply,
		Encodings: []Encoding{Base64, Base32},
		Name:      "no-padding",
	}
}

// Lowercase ...
func Lowercase() EncodeOption {
	apply := func(o *EncodeOptions) {
		o.Lowercase = true
	}
	return EncodeOption{
		Apply:     apply,
		Encodings: []Encoding{Base32},
		Name:      "lowercase",
	}
}

func containsEncoding(encs []Encoding, enc Encoding) bool {
	for _, e := range encs {
		if e == enc {
			return true
		}
	}
	return false
}
