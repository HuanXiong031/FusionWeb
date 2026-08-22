package api

import (
	"FusionWeb/backend/service"
	"context"
)

func (a *App) ListSpaceEngineKeys(userID int) ([]service.SpaceEngineKey, error) {
	return a.spaceService.ListEngineKeys(userID)
}

func (a *App) SaveSpaceEngineKey(item service.SpaceEngineKey, userID int) (service.SpaceEngineKey, error) {
	return a.spaceService.SaveEngineKey(item, userID)
}

func (a *App) DeleteSpaceEngineKey(id int64, userID int) error {
	return a.spaceService.DeleteEngineKey(id, userID)
}

func (a *App) TestSpaceEngineKey(id int64, userID int) (service.SpaceEngineTestResult, error) {
	return a.spaceService.TestEngineKey(id, userID)
}

func (a *App) SearchSpace(ctx context.Context, req service.SpaceSearchRequest, userID int) (service.SpaceSearchResponse, error) {
	return a.spaceService.Search(ctx, req, userID)
}
