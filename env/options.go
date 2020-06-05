package env

// PathOptions ...
type PathOptions struct {
	Dirs  []string
	File  string
	MkDir bool
}

// PathOption ...
type PathOption func(*PathOptions) error

func newOptions(opts ...PathOption) (PathOptions, error) {
	var options PathOptions
	for _, o := range opts {
		if err := o(&options); err != nil {
			return options, err
		}
	}
	return options, nil
}

// Dir ...
func Dir(dirs ...string) PathOption {
	return func(o *PathOptions) error {
		o.Dirs = dirs
		return nil
	}
}

// File ...
func File(file string) PathOption {
	return func(o *PathOptions) error {
		o.File = file
		return nil
	}
}

// MkDir ...
func MkDir() PathOption {
	return func(o *PathOptions) error {
		o.MkDir = true
		return nil
	}
}
