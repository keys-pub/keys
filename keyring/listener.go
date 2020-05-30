package keyring

// Listener for keyring events.
type Listener interface {
	Locked()
	Unlocked(*Provision)
}

// AddListener adds listener.
func (k *Keyring) AddListener(ln Listener) {
	k.lns = append(k.lns, ln)
}

// RemoveListener removes listener.
func (k *Keyring) RemoveListener(ln Listener) {
	panic("not implemented")
}

func (k *Keyring) notifyUnlocked(p *Provision) {
	for _, ln := range k.lns {
		ln.Unlocked(p)
	}
}

func (k *Keyring) notifyLocked() {
	for _, ln := range k.lns {
		ln.Locked()
	}
}
