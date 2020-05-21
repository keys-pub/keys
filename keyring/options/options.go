package options

// List options.
type List struct {
	Types []string
}

// IDs options.
type IDs struct {
	Prefix       string
	ShowHidden   bool
	ShowReserved bool
}
