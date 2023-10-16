package integration

import (
	"context"
	"fmt"

	"github.com/go-pg/pg/v11"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/ramyadmz/goauth/internal/config"
	"github.com/ramyadmz/goauth/internal/data/postgres"
	"github.com/ramyadmz/goauth/internal/service/auth"
	"github.com/ramyadmz/goauth/internal/service/credentials/jwt"
	"github.com/ramyadmz/goauth/internal/service/credentials/session"
	"github.com/ramyadmz/goauth/pkg/pb"
)

var ClientID, UserID int64
var ClientName, ClientSecret, Website, Scope, AuthCode, Token, RefreshToken string
var Username, SessionID, Email, Password string

var _ = Describe("Oauth Test Suite", func() {
	var (
		ctx        context.Context
		dal        *postgres.PostgresProvider
		userAuth   *auth.UserAuthService
		clientAuth *auth.ClientAuthService
	)

	BeforeEach(func() {
		ctx = context.Background()
		jwtConfig, err := config.NewJWTConfig()
		Expect(err).NotTo(HaveOccurred())
		tokenHandler := jwt.NewJWTHandler(jwtConfig)

		pgConfig, err := config.NewPostgresConfig()
		Expect(err).NotTo(HaveOccurred())

		options := &pg.Options{
			Addr:     fmt.Sprintf("%s:%d", pgConfig.GetHost(), pgConfig.GetPort()), // Ensure dbHost is used here
			User:     pgConfig.GetUser(),
			Password: pgConfig.GetPassword(),
			Database: pgConfig.GetDatabase(),
		}

		db := pg.Connect(options)
		dal = postgres.NewPostgresProvider(db)
		sessionHandler := session.NewSessionHandler(dal)

		// reuse dal to avoid unnecessary overhead in opening and closing multiple database connections.
		userAuth = auth.NewUserAuthService(dal, sessionHandler)
		clientAuth = auth.NewClientAuthService(dal, tokenHandler)
	})

	Context("when registering a new user", func() {
		It("should successfully register and store the user", func() {
			Username, Password, Email = uuid.NewString(), uuid.NewString(), uuid.NewString()
			_, err := userAuth.RegisterUser(ctx, &pb.RegisterUserRequest{
				Username: Username,
				Password: Password,
				Email:    Email,
			})
			Expect(err).To(BeNil(), "Expected no error during registration")

			By("checking the inserted user data in database")
			user, err := dal.GetUserByUsername(ctx, Username)
			Expect(err).To(BeNil(), "Expected to find the user in the database")
			UserID = user.ID

			Expect(user.Username).To(Equal(Username))
			Expect(user.HashedPassword).ToNot(BeEmpty())
			Expect(user.Email).To(Equal(Email))
		})
	})

	Context("when registering a new client", func() {
		ClientName, Website, Scope = uuid.NewString(), uuid.NewString(), "admin"
		It("should successfully register and store the client", func() {
			rsp, err := clientAuth.RegisterClient(ctx, &pb.RegisterClientRequest{
				Name:    ClientName,
				Website: Website,
				Scope:   Scope,
			})
			Expect(err).To(BeNil(), "Expected no error during registration")
			ClientID = rsp.ClientId

			By("checking the inserted client data in database")
			client, err := dal.GetClientByID(ctx, rsp.ClientId)
			Expect(err).To(BeNil(), "Expected to find the user in the database")
			Expect(client.Name).To(Equal(ClientName))
			Expect(client.Website).To(Equal(Website))
			Expect(client.Scope).To(Equal(Scope))
			Expect(client.HashedSecret).ToNot(BeEmpty())
		})
	})

	Context("when loging in a user", func() {
		It("should successfully login the user", func() {
			rsp, err := userAuth.LoginUser(ctx, &pb.UserLoginRequest{
				Username: Username,
				Password: Password,
			})
			Expect(err).To(BeNil(), "Expected no error during registration")

			By("checking the inserted user data in database")
			session, err := dal.GetSessionByID(ctx, rsp.SessionId)
			Expect(err).To(BeNil(), "Expected to find the session in the database")
			SessionID = session.ID

			user, err := dal.GetUserByID(ctx, session.UserID)
			Expect(err).To(BeNil(), "Expected to find the user in the database")

			Expect(session.UserID).To(Equal(user.ID))
			Expect(user.Username).To(Equal(Username))
		})
	})

	Context("when user consenting", func() {
		It("should successfully consent", func() {
			_, err := userAuth.ConsentUser(ctx, &pb.UserConsentRequest{
				ClientId:  ClientID,
				SessionId: SessionID,
			})
			Expect(err).To(BeNil(), "Expected no error during consent")

			By("checking the inserted auth record in database")
			auth, err := dal.GetAuthorizationCodeByUserIDAndClientID(ctx, UserID, ClientID)
			Expect(err).To(BeNil(), "Expected to find the session in the database")

			Expect(auth.AuthCode).NotTo(Equal(""))
		})

	})
})
