package user_test

import (
	"os"

	"github.com/keys-pub/keys/user/services"
	"github.com/keys-pub/keys/user"
)

func init() {
	user.AddService(services.NewTwitter(os.Getenv("TWITTER_BEARER_TOKEN")))
	user.AddService(services.NewGithub())
	user.AddService(services.NewEcho())
	user.AddService(services.NewHTTPS())
	user.AddService(services.NewReddit())
}
