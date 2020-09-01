package user

import (
	"context"

	"github.com/keys-pub/keys"
)

func (u *Users) UpdateForTestingCompatibility(ctx context.Context, kid keys.ID) (*Result, error) {
	return u.updateForTestingCompatibility(ctx, kid)
}
