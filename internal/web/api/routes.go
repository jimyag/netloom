package api

import (
	"io/fs"
	"mime"
	"net/http"
	pathpkg "path"
	"strings"

	"github.com/gin-gonic/gin"
)

func registerRoutes(router *gin.Engine) {
	apiRoutes := router.Group("/api")
	apiRoutes.GET("/items", listItems)
	apiRoutes.GET("/items/:id", getItem)

	router.NoRoute(spaFallbackHandler())
}

func spaFallbackHandler() gin.HandlerFunc {
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}

	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			return
		}

		cleanPath := strings.TrimPrefix(pathpkg.Clean("/"+c.Request.URL.Path), "/")
		if cleanPath == "." || cleanPath == "" || !strings.Contains(pathpkg.Base(cleanPath), ".") {
			serveEmbeddedFile(c, staticFS, "index.html")
			return
		}

		serveEmbeddedFile(c, staticFS, cleanPath)
	}
}

func serveEmbeddedFile(c *gin.Context, staticFS fs.FS, name string) {
	file, err := fs.ReadFile(staticFS, name)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}

	contentType := mime.TypeByExtension(pathpkg.Ext(name))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	c.Data(http.StatusOK, contentType, file)
}
