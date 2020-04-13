package ds

// Watch for changes at path.
type Watch interface {
	Watch(path string, ln WatchLn) error
	StopWatching(path string)
	StopWatchingAll()
}

// WatchStatus is status for watch.
type WatchStatus string

const (
	// WatchStatusNone is an known status
	WatchStatusNone WatchStatus = ""
	// WatchStatusStarting is a status for when watch is starting
	WatchStatusStarting WatchStatus = "starting"
	// WatchStatusStopping is a status for when watch is stopping
	WatchStatusStopping WatchStatus = "stopping"
	// WatchStatusData is a status for when data has changed
	WatchStatusData WatchStatus = "data"
)

// WatchEvent gives updates to watch status and version.
type WatchEvent struct {
	Status WatchStatus
	Path   string
}

// WatchLn is a listener that receives WatchEvent.
type WatchLn func(*WatchEvent)
