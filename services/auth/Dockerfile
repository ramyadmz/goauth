FROM golang:1.21

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . /app/
RUN go install github.com/onsi/ginkgo/ginkgo
RUN go install github.com/onsi/gomega/...
RUN go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest