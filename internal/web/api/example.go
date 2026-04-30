package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Item struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

var exampleItems = []Item{
	{ID: "alpha", Name: "Alpha", Description: "The first example item."},
	{ID: "beta", Name: "Beta", Description: "The second example item."},
	{ID: "gamma", Name: "Gamma", Description: "The third example item."},
}

func listItems(c *gin.Context) {
	c.JSON(http.StatusOK, exampleItems)
}

func getItem(c *gin.Context) {
	id := c.Param("id")
	for _, item := range exampleItems {
		if item.ID == id {
			c.JSON(http.StatusOK, item)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "item not found"})
}
