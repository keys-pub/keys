package util

// RetryE will retry the fn (error) if the error is temporary (such as a temporary net.Error)
func RetryE(fn func() error) error {
	err := fn()
	if err != nil {
		if IsTemporaryError(err) {
			logger.Warningf("Temporary error (will attempt a retry): %+v", err)
			// Retry
			return fn()
		}
		return err
	}
	return nil
}

// RetrySE will retry the fn (string, error) if the error is temporary (such as a temporary net.Error)
func RetrySE(fn func() (string, error)) (string, error) {
	s, err := fn()
	if err != nil {
		if IsTemporaryError(err) {
			logger.Warningf("Temporary error (will attempt a retry): %+v", err)
			// Retry
			return fn()
		}
		return s, err
	}
	return s, nil
}
