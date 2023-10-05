package auth

import (
	"context"
	"testing"

	"github.com/go-playground/assert/v2"
	"github.com/ramyadmz/goauth/internal/data"
	"github.com/ramyadmz/goauth/internal/service/auth"
	"github.com/ramyadmz/goauth/pkg/pb"
	"github.com/stretchr/testify/mock"
)

func TestRegisterClient_HappyPath(t *testing.T) {
	mockDAL := &MockDAL{}
	mockDAL.On("CreateClient", mock.Anything, mock.Anything).Return(&data.Client{ID: 100, Name: "testName", HashedSecret: []byte("veryHashedSecret")}, nil)

	authService := auth.NewClientAuthService(mockDAL, &MockTokenHandler{})
	rsp, err := authService.RegisterClient(context.Background(), &pb.RegisterClientRequest{Name: "testName", Website: "testURL", Scope: "testScope"})
	assert.Equal(t, err, nil)
	assert.Equal(t, rsp.ClientId, int64(100))

}
