package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/a-h/templ"
	"github.com/alexedwards/scs/sqlite3store"
	"github.com/alexedwards/scs/v2"
	"github.com/danielcosme/go-todo/database/gen/models"
	"github.com/danielcosme/go-todo/database/migrations"
	"github.com/golang-migrate/migrate/v4"
	migrate_sqlite "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lmittmann/tint"
	"github.com/stephenafamo/bob"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// TODO: Implement Authentication.
//   Sessions with Alex Edwards library.

// TODO: Deploy.
//   Single Binary. Systemd Service.

// NOTE: Remember that request with the header "Datastar-Request: true"
// 		 are actions generated in the front-end (@get, @post, @put, etc...)

const ctxKeyAuthenticatedUserID = "authenticated_user_id"
const ctxKeyIsAuthenticated = "is_authenticated"
const ctxUser = "user"

var version string

func main() {
	logHandler := tint.NewHandler(os.Stdout, &tint.Options{
		AddSource:   false,
		Level:       slog.LevelDebug,
		ReplaceAttr: nil,
		TimeFormat:  time.RFC822,
		NoColor:     false,
	})
	logger := slog.New(logHandler)
	slog.SetDefault(logger)

	port := 3001
	version = Version()
	slog.Info("Version: " + version)

	db, err := sql.Open("sqlite", "./tmp/todo.db")
	exitIfErr(err)
	err = db.Ping()
	exitIfErr(err)
	bobDB := bob.NewDB(db)

	migrationsFS, err := iofs.New(migrations.MigrationsFS, "sqlite")
	exitIfErr(err)
	migrationDriver, err := migrate_sqlite.WithInstance(db, &migrate_sqlite.Config{})
	exitIfErr(err)
	m, err := migrate.NewWithInstance(
		"iofs",
		migrationsFS,
		"file://./tmp/todo.db",
		migrationDriver)
	exitIfErr(err)
	m.Log = NewMigrateLogger(logger, false)
	slog.Info("migrations: loaded")
	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			slog.Info("migrations: no change")
		} else {
			slog.Error(err.Error())
			os.Exit(1)
		}
	}

	sessionManager := scs.New()
	sessionManager.Lifetime = 24 * time.Hour * 15
	sessionManager.Store = sqlite3store.New(db)
	sessionManager.Cookie.SameSite = http.SameSiteStrictMode
	sessionManager.Cookie.Name = "go-todo-session"

	pSetter := &models.ProjectSetter{Name: ref("life")}
	models.Projects.Insert(pSetter).One(context.Background(), bobDB)

	e := echo.New()
	api := &API{
		db:      bobDB,
		scs:     sessionManager,
		version: version,
	}
	routes(e, api)

	slog.Info("starting HTTP Server", "port", port)
	err = e.Start(fmt.Sprintf(":%d", port))
	exitIfErr(err)
}

func Authenticate(db bob.Executor, username string, password string) (int64, error) {
	user, err := models.Users.Query(
		models.SelectWhere.Users.Username.EQ(username),
	).One(context.TODO(), db)
	if err != nil {
		return 0, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordDigest), []byte(password))
	if err != nil {
		return 0, err
	}
	return user.ID, nil
}

func parseID(i string) int64 {
	id, err := strconv.ParseInt(i, 10, 64)
	exitIfErr(err)
	return id
}

func renderOK(c echo.Context, co templ.Component) error {
	return render(c, http.StatusOK, co)
}

func render(c echo.Context, status int, co templ.Component) error {
	buf := templ.GetBuffer()
	defer templ.ReleaseBuffer(buf)
	err := co.Render(ctx(c), buf)
	if err != nil {
		return err
	}
	return c.HTMLBlob(status, buf.Bytes())
}

func midSecureHeaders(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		h := c.Response().Header()
		h.Set(echo.HeaderContentSecurityPolicyReportOnly,
			"default-src 'self;"+
				"style-src 'self';"+
				"script-src 'self' cdn.jsdelivr.net;"+
				"object-src 'self'")

		return next(c)
	}
}

func midSlogConfig() middleware.RequestLoggerConfig {
	return middleware.RequestLoggerConfig{
		LogMethod:   true,
		LogStatus:   true,
		LogURI:      true,
		LogError:    true,
		HandleError: false, // forwards error to the global error handler, so it can decide appropriate status code
		LogRemoteIP: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			attrs := []slog.Attr{
				slog.String("uri", v.URI),
				slog.Int("status", v.Status),
				slog.String("IP", v.RemoteIP),
				slog.String("Duration",
					fmt.Sprintf("%d ms", time.Since(v.StartTime).Milliseconds())),
			}
			if v.Error == nil {
				slog.Default().LogAttrs(ctx(c), slog.LevelInfo, v.Method, attrs...)
			} else {
				slog.Default().LogAttrs(ctx(c), slog.LevelError, v.Method,
					append(attrs, slog.String("err", v.Error.Error()))...,
				)
			}
			return nil
		},
	}
}

func (a *API) midLoadAndSaveCookie(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Add("Vary", "Cookie")
		ctx := c.Request().Context()

		var token string
		cookie, err := c.Cookie(a.scs.Cookie.Name)
		if err == nil {
			token = cookie.Value
		}
		ctx, err = a.scs.Load(ctx, token)
		if err != nil {
			return err
		}
		c.SetRequest(c.Request().WithContext(ctx))

		c.Response().Before(func() {
			switch a.scs.Status(ctx) {
			case scs.Modified:
				token, expiry, err := a.scs.Commit(ctx)
				if err != nil {
					panic(err)
				}
				a.scs.WriteSessionCookie(ctx, c.Response().Writer, token, expiry)
			case scs.Destroyed:
				a.scs.WriteSessionCookie(ctx, c.Response().Writer, "", time.Time{})
			}
		})

		return next(c)
	}
}

func (a *API) midAuthenticateFromSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		id := a.scs.GetInt64(c.Request().Context(), ctxKeyAuthenticatedUserID)
		if id == 0 {
			slog.Info("no authenticated user")
			return next(c)
		}

		usr, err := models.FindUser(ctx(c), a.db, int64(id))
		if err != nil {
			return err
		}
		if usr != nil {
			slog.Info("user is authenticated")
			ctx := context.WithValue(c.Request().Context(), ctxKeyIsAuthenticated, true)
			ctx = context.WithValue(ctx, ctxUser, usr)
			c.SetRequest(c.Request().WithContext(ctx))
		}
		return next(c)
	}
}

func (a *API) midRequireAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		isAuthenticated, ok := ctx(c).Value(ctxKeyIsAuthenticated).(bool)
		if !ok {
			return c.Redirect(http.StatusSeeOther, "/login")
		}
		if !isAuthenticated {
			return c.Redirect(http.StatusSeeOther, "/login")
		}

		// Set the "Cache-Control: no-store" header so that pages require
		// authentication are not stored in the users browser cache (or
		// other intermediary cache).
		c.Response().Header().Add("Cache-Control", "no-store")
		return next(c)
	}
}

func Version() string {
	hash := "unknown"
	bi, ok := debug.ReadBuildInfo()
	if ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				hash = s.Value[:7]
			}
		}
	}
	return fmt.Sprintf("%s-%s", version, hash)
}

func ctx(c echo.Context) context.Context {
	return c.Request().Context()
}

func exitIfErr(err error) {
	if err != nil {
		panic(err)
	}
}

func ref[T any](p T) *T {
	return &p
}

type MigrateLogger struct {
	logger  *slog.Logger
	verbose bool
}

func NewMigrateLogger(logger *slog.Logger, v bool) *MigrateLogger {
	return &MigrateLogger{logger: logger, verbose: v}
}

func (l *MigrateLogger) Printf(format string, v ...interface{}) {
	slog.Info(fmt.Sprintf(format, v...))
}
func (l *MigrateLogger) Verbose() bool {
	return l.verbose
}
