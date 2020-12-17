package user_test

import (
	"os"

	"github.com/keys-pub/keys/link"
	"github.com/keys-pub/keys/user"
)

func init() {
	user.AddService(link.NewTwitter(os.Getenv("TWITTER_BEARER_TOKEN")))
	user.AddService(link.NewGithub())
	user.AddService(link.NewEcho())
	user.AddService(link.NewHTTPS())
	user.AddService(link.NewReddit())
}
