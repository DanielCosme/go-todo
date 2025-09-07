package main

import (
	"log/slog"
	"net/http"

	"github.com/alexedwards/scs/v2"
	"github.com/danielcosme/go-todo/database/gen/models"
	"github.com/danielcosme/go-todo/views"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/stephenafamo/bob"
	"github.com/stephenafamo/bob/dialect/sqlite/sm"
)

type API struct {
	db      bob.DB
	scs     *scs.SessionManager
	version string
}

func routes(e *echo.Echo, api *API) {
	e.Use(middleware.RequestLoggerWithConfig(midSlogConfig()))
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())
	e.StaticFS("/static", echo.MustSubFS(views.StaticFS, "static"))

	e.Use(api.midLoadAndSaveCookie)
	e.Use(api.midAuthenticateFromSession)
	e.GET("/login", api.GetLogin)
	e.POST("/login", api.PostLogin)

	g := e.Group("/")
	{
		g.Use(api.midRequireAuth)
		g.GET("", api.Index)
		g.POST("todo", api.PostTodo)
		g.PUT("todo/:id", api.PutTodo)
	}
}

func (a *API) Index(c echo.Context) error {
	s := views.State{Version: a.version}
	tds, err := models.Todos.
		Query(
			models.SelectWhere.Todos.Done.EQ(false),
			sm.OrderBy(models.Todos.Columns.ID).Desc()).
		All(ctx(c), a.db)
	if err != nil {
		return err
	}
	tds2, err := models.Todos.
		Query(
			models.SelectWhere.Todos.Done.EQ(true),
			sm.OrderBy(models.Todos.Columns.ID).Desc(),
			sm.Limit(20)).
		All(ctx(c), a.db)
	if err != nil {
		return err
	}
	return renderOK(c, views.Todos(s, append(tds, tds2...)))
}

type PostTodo struct {
	Item string `json:"input"`
}

func (a *API) PostTodo(c echo.Context) error {
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
	todo, err := models.Todos.Insert(&todoS).One(ctx(c), a.db)
	if err != nil {
		return err
	}
	h := c.Response().Header()
	h.Set(echo.HeaderContentType, echo.MIMETextHTML)
	h.Set("datastar-selector", "#todo-list")
	h.Set("datastar-mode", "prepend")
	return render(c, http.StatusCreated, views.Todo(todo))
}

func (a *API) PutTodo(c echo.Context) error {
	id := c.Param("id")
	todo, err := models.FindTodo(ctx(c), a.db, parseID(id))
	if err != nil {
		return c.NoContent(http.StatusNotFound)
	}
	err = todo.Update(ctx(c), a.db, &models.TodoSetter{Done: ref(!todo.Done)})
	if err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}
	return c.Redirect(http.StatusSeeOther, "/")
}

func (a *API) GetLogin(c echo.Context) error {
	isAuthenticated, ok := ctx(c).Value(ctxKeyIsAuthenticated).(bool)
	if ok && isAuthenticated {
		return c.Redirect(http.StatusSeeOther, "/")
	}
	s := views.State{Version: version}
	return renderOK(c, views.Login(s))
}

func (a *API) PostLogin(c echo.Context) error {
	userID, err := Authenticate(a.db,
		c.FormValue("username"),
		c.FormValue("password"))
	if err != nil {
		return err
	}
	slog.Info("user authenticated", "ID", userID)
	err = a.scs.RenewToken(c.Request().Context())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	a.scs.Put(c.Request().Context(), string(ctxKeyAuthenticatedUserID), userID)
	return c.Redirect(http.StatusFound, "/")
}
