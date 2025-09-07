package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"os"

	"github.com/danielcosme/go-todo/database/gen/models"
	"github.com/stephenafamo/bob"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func main() {
	args := os.Args[1:]
	if len(args) < 1 {
		slog.Info("usage: go run main.go <command> <args>")
	}
	command := args[0]

	slog.Info("command: " + command)
	switch command {
	case "create-user":
		username := args[1]
		password := args[2]
		if username == "" || password == "" {
			slog.Error("username and password are required")
			os.Exit(1)
		}

		db, err := sql.Open("sqlite", "./tmp/todo.db")
		exitIfErr(err)
		err = db.Ping()
		exitIfErr(err)
		bobDB := bob.NewDB(db)

		u, err := models.Users.Query(models.SelectWhere.Users.Username.EQ(username)).One(context.Background(), bobDB)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			slog.Error(err.Error())
			os.Exit(1)
		}
		if u == nil {
			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			exitIfErr(err)
			_, err = models.Users.Insert(&models.UserSetter{
				Username:       ref(username),
				PasswordDigest: ref(string(hash)),
			}).One(context.TODO(), bobDB)
			exitIfErr(err)
		}
	default:
		slog.Info("unknown command: " + command)
		os.Exit(1)
	}
}

func exitIfErr(err error) {
	if err != nil {
		panic(err)
	}
}

func ref[T any](p T) *T {
	return &p
}
