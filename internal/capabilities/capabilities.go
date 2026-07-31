package capabilities

import "github.com/Lmarkussen/CinderPath/internal/models"

func Available(items []models.Capability, name string) bool {
	for _, item := range items {
		if item.Name == name && item.Available {
			return true
		}
	}
	return false
}
