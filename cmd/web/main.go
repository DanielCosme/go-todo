package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/a-h/templ"
	"github.com/danielcosme/go-todo/database/gen/models"
	"github.com/danielcosme/go-todo/views"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lmittmann/tint"
	"github.com/stephenafamo/bob"
	"github.com/stephenafamo/bob/dialect/sqlite/sm"
	_ "modernc.org/sqlite"
)

// TODO: Implement Authentication.
// TODO: Deploy.

// NOTE: Remember that request with the header "Datastar-Request: true"
// 		 are actions generated in the front-end (@get, @post, @put, etc...)

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

	e := echo.New()
	e.Use(middleware.RequestLoggerWithConfig(midSlogConfig()))
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())
	e.Use(midSecureHeaders)
	e.StaticFS("/static", echo.MustSubFS(views.StaticFS, "static"))

	pSetter := &models.ProjectSetter{Name: ref("life")}
	models.Projects.Insert(pSetter).One(context.Background(), bobDB)

	e.GET("/", func(c echo.Context) error {
		s := views.State{Version: version}
		tds, err := models.Todos.
			Query(
				models.SelectWhere.Todos.Done.EQ(false),
				sm.OrderBy(models.Todos.Columns.ID).Desc()).
			All(ctx(c), bobDB)
		if err != nil {
			return err
		}
		tds2, err := models.Todos.
			Query(
				models.SelectWhere.Todos.Done.EQ(true),
				sm.OrderBy(models.Todos.Columns.ID).Desc(),
				sm.Limit(20)).
			All(ctx(c), bobDB)
		if err != nil {
			return err
		}

		return renderOK(c, views.Todos(s, append(tds, tds2...)))
	})

	type PostTodo struct {
		Item string `json:"input"`
	}
	e.POST("/todo", func(c echo.Context) error {
		data := new(PostTodo)
		if err := c.Bind(data); err != nil {
			slog.Error(err.Error())
			return c.NoContent(http.StatusInternalServerError)
		}
		if len(data.Item) <= 3 {
			return c.NoContent(http.StatusBadRequest)
		}
		todoS := models.TodoSetter{
			ProjectID: ref(int64(1)),
			Title:     ref(data.Item),
		}
		todo, err := models.Todos.Insert(&todoS).One(ctx(c), bobDB)
		if err != nil {
			return err
		}
		h := c.Response().Header()
		h.Set(echo.HeaderContentType, echo.MIMETextHTML)
		h.Set("datastar-selector", "#todo-list")
		h.Set("datastar-mode", "prepend")
		return render(c, http.StatusCreated, views.Todo(todo))
	})

	e.PUT("/todo/:id", func(c echo.Context) error {
		id := c.Param("id")
		todo, err := models.FindTodo(ctx(c), bobDB, parseID(id))
		if err != nil {
			return c.NoContent(http.StatusNotFound)
		}
		todo.Update(ctx(c), bobDB, &models.TodoSetter{Done: ref(!todo.Done)})
		if err != nil {
			return c.NoContent(http.StatusInternalServerError)
		}
		return c.Redirect(http.StatusSeeOther, "/")
	})

	slog.Info("starting HTTP Server", "port", port)
	err = e.Start(fmt.Sprintf(":%d", port))
	exitIfErr(err)
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
