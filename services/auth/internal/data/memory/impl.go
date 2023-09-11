package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/ramyadmz/goauth/internal/data"
)

// compile time check for interface satisfaction.
var _ data.AuthProvider = new(MemoryProvider)

type MemoryProvider struct {
	mu    sync.Mutex
	users map[string]*data.User
}

func (dp *MemoryProvider) CreateUser(ctx context.Context, params data.CreateUseParams) (*data.User, error) {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	user := &data.User{
		ID:       uuid.NewString(),
		Username: params.Username,
		Password: params.Password,
		Email:    params.Email,
	}

	dp.users[user.ID] = user

	return user, nil
}

func (dp *MemoryProvider) GetUserByID(ctx context.Context, userID string) (*data.User, error) {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	user, exist := dp.users[userID]
	if !exist {
		return nil, fmt.Errorf("user doesn't exist")
	}

	return user, nil
}
