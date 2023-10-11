package integration

import (
	"context"

	"github.com/go-pg/pg/v11"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/ramyadmz/goauth/internal/data/postgres"
	"github.com/ramyadmz/goauth/internal/service/auth"
	"github.com/ramyadmz/goauth/internal/service/credentials/session"
	"github.com/ramyadmz/goauth/pkg/pb"
)

var (
	Username = "testUsername"
	Password = "testPassword"
	Email    = "test1@test.com"
)

var _ = Describe("CreateUser", func() {
	var (
		dal      *postgres.PostgresProvider
		userAuth *auth.UserAuthService
		ctx      context.Context
	)

	BeforeEach(func() {
		// Initialize database connection
		db := pg.Connect(&pg.Options{
			Addr:     "127.0.0.1:5432", // adjust as necessary
			User:     "postgres",
			Password: "123",
			Database: "postgres",
		})
		ctx = context.Background()
		dal = postgres.NewPostgresProvider(db)
		sessionHandler := session.NewSessionHandler(dal)
		userAuth = auth.NewUserAuthService(dal, sessionHandler)

		// TODO: Add any database setup here, like creating tables
	})

	AfterEach(func() {
		// Clean up the database
		// TODO: Remove any data that was inserted into the database
	})
	Context("when registering a new user", func() {
		It("should successfully register and store the user", func() {
			// Test logic remains mostly the same
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
})
