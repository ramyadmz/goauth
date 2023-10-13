package integration

import (
	"context"
	"fmt"

	"github.com/go-pg/pg/v11"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/ramyadmz/goauth/internal/config"
	"github.com/ramyadmz/goauth/internal/data/postgres"
	"github.com/ramyadmz/goauth/internal/service/auth"
	"github.com/ramyadmz/goauth/internal/service/credentials/jwt"
	"github.com/ramyadmz/goauth/internal/service/credentials/session"
	"github.com/ramyadmz/goauth/pkg/pb"
)

var (
	Username = "testUsername"
	Password = "testPassword"
	Email    = "test1@test.com"

	Website = "test.com"
	Name    = "client"
	Scope   = "admin"
)

var _ = Describe("CreateUser", func() {
	var (
		ctx        context.Context
		dal        *postgres.PostgresProvider
		userAuth   *auth.UserAuthService
		clientAuth *auth.ClientAuthService
	)

	BeforeEach(func() {
		ctx = context.Background()

		// uncomment it for local test
		//SetUpLocalTestEnvs()
		//defer UnSetLocalTestEnvs()

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
			_, err := userAuth.RegisterUser(ctx, &pb.RegisterUserRequest{
				Username: Username,
				Password: Password,
				Email:    Email,
			})
			Expect(err).To(BeNil(), "Expected no error during registration")

			By("checking the inserted user data in database")
			user, err := dal.GetUserByUsername(ctx, Username)
			Expect(err).To(BeNil(), "Expected to find the user in the database")
			Expect(user.Username).To(Equal(Username))
			Expect(user.HashedPassword).ToNot(BeEmpty())
			Expect(user.Email).To(Equal(Email))
		})
	})

	Context("when registering a new client", func() {
		It("should successfully register and store the client", func() {
			rsp, err := clientAuth.RegisterClient(ctx, &pb.RegisterClientRequest{
				Name:    Name,
				Website: Website,
				Scope:   Scope,
			})
			Expect(err).To(BeNil(), "Expected no error during registration")

			By("checking the inserted user data in database")
			client, err := dal.GetClientByID(ctx, rsp.ClientId)
			Expect(err).To(BeNil(), "Expected to find the user in the database")
			Expect(client.Name).To(Equal(Name))
			Expect(client.Website).To(Equal(Website))
			Expect(client.Scope).To(Equal(Scope))
			Expect(client.HashedSecret).ToNot(BeEmpty())
		})
	})
})
