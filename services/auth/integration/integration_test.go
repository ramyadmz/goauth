package integration

import (
	"context"
	"fmt"
	"os"

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
		ctx = context.Background()
		dbUser := os.Getenv("AUTH_POSTGRES_USER")
		dbPassword := os.Getenv("AUTH_POSTGRES_PASSWORD")
		dbName := os.Getenv("AUTH_POSTGRES_DB")

		dbHost := os.Getenv("AUTH_POSTGRES_HOST")
		options := &pg.Options{
			Addr:     fmt.Sprintf("%s:5432", dbHost), // Ensure dbHost is used here
			User:     dbUser,
			Password: dbPassword,
			Database: dbName,
		}
		db := pg.Connect(options)
		dal = postgres.NewPostgresProvider(db)
		sessionHandler := session.NewSessionHandler(dal)
		userAuth = auth.NewUserAuthService(dal, sessionHandler)
	})

	AfterEach(func() {
		// Clean up the database
		// TODO: Remove any data that was inserted into the database
	})
	Context("when registering a new user", func() {
		fmt.Println(".................................................")
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
