// Package gen contains generated client + types for the Zypheron Desktop
// Control API. The canonical contract lives in schema/control-api.yaml at
// the repo root; regenerate with `make generate-bridge`.
//
//go:generate go tool oapi-codegen -config oapi-config.yaml ../../../../schema/control-api.yaml
package gen
