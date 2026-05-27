// cobragen reads schema/control-api.yaml, scans for operations carrying the
// `x-cli` extension, and emits one Cobra command per matching operation
// plus a single `register.go` that wires the tree into the parent bridge
// command. Generated code is deterministic; CI fails if regen produces a
// diff (see Makefile target `check-cli-drift`).
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// XCLI matches the `x-cli` extension shape in control-api.yaml.
type XCLI struct {
	Command []string   `yaml:"command"`
	Flags   []FlagSpec `yaml:"flags,omitempty"`
	Output  string     `yaml:"output,omitempty"`
}

// FlagSpec models a single CLI flag (also used inline in the YAML).
type FlagSpec struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	Default any    `yaml:"default,omitempty"`
	Help    string `yaml:"help,omitempty"`
}

// Parameter is one OpenAPI operation parameter we project into Cobra flags.
type Parameter struct {
	Name     string
	In       string // path | query
	Required bool
	GoType   string
	FlagName string
	FlagType string // string | int | bool
	Help     string
}

// Operation is the fully-resolved descriptor handed to the template.
type Operation struct {
	OpID         string
	Method       string
	Path         string
	Summary      string
	XCLI         XCLI
	Parameters   []Parameter
	HasBody      bool
	BodySchema   string
	HasResponse  bool
	ResponseType string
	IsList       bool
	OutputMode   string
	FuncName     string
	HasPathParam bool // true when any Parameter.In == "path"
}

// Top-level YAML shape — we only need the bits that drive code emission.
// `Paths` is decoded as map[string]map[string]any so we can dispatch on
// key (a method name like "get" / "post" vs. the path-level "parameters"
// array) without yaml.v3 rejecting the mixed shape.
type rawSpec struct {
	Paths map[string]map[string]any `yaml:"paths"`
}

type rawOperation struct {
	OperationID string                 `yaml:"operationId"`
	Summary     string                 `yaml:"summary"`
	XCLI        *XCLI                  `yaml:"x-cli"`
	Parameters  []rawParameter         `yaml:"parameters"`
	RequestBody map[string]any         `yaml:"requestBody,omitempty"`
	Responses   map[string]rawResponse `yaml:"responses"`
}

type rawParameter struct {
	Name     string                 `yaml:"name"`
	In       string                 `yaml:"in"`
	Required bool                   `yaml:"required"`
	Schema   map[string]any         `yaml:"schema"`
	Other    map[string]any         `yaml:",inline"`
}

type rawResponse struct {
	Description string         `yaml:"description"`
	Content     map[string]any `yaml:"content"`
}

func main() {
	schemaPath := flag.String("schema", "", "Path to the canonical OpenAPI YAML (schema/control-api.yaml).")
	outDir := flag.String("out", "", "Directory to write generated Go files.")
	flag.Parse()

	if *schemaPath == "" || *outDir == "" {
		fmt.Fprintln(os.Stderr, "usage: cobragen --schema PATH --out DIR")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*schemaPath)
	if err != nil {
		exit("read schema: %v", err)
	}
	var spec rawSpec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		exit("parse schema: %v", err)
	}

	ops := collectOperations(spec)
	if len(ops) == 0 {
		fmt.Fprintln(os.Stderr, "no x-cli operations found; nothing to generate")
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		exit("mkdir out: %v", err)
	}

	for _, op := range ops {
		if err := emitCommand(op, *outDir); err != nil {
			exit("emit %s: %v", op.OpID, err)
		}
	}
	if err := emitRegister(ops, *outDir); err != nil {
		exit("emit register: %v", err)
	}
	if err := emitDoc(*outDir); err != nil {
		exit("emit doc: %v", err)
	}

	fmt.Fprintf(os.Stderr, "✓ cobragen wrote %d command(s) to %s\n", len(ops), *outDir)
}

func exit(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cobragen: "+format+"\n", args...)
	os.Exit(1)
}

func collectOperations(spec rawSpec) []Operation {
	var ops []Operation
	paths := make([]string, 0, len(spec.Paths))
	for p := range spec.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, path := range paths {
		methods := spec.Paths[path]
		var pathLevelParams []rawParameter
		if raw, ok := methods["parameters"]; ok {
			b, _ := yaml.Marshal(raw)
			_ = yaml.Unmarshal(b, &pathLevelParams)
		}

		for _, m := range []string{"get", "post", "put", "patch", "delete"} {
			rawOp, ok := methods[m]
			if !ok {
				continue
			}
			ro, ok := decodeOperation(rawOp)
			if !ok || ro.XCLI == nil {
				continue
			}
			ops = append(ops, buildOperation(strings.ToUpper(m), path, ro, pathLevelParams))
		}
	}
	return ops
}

// decodeOperation re-decodes a single operation node from its `any` shape
// produced by the loose top-level paths map.
func decodeOperation(node any) (rawOperation, bool) {
	b, err := yaml.Marshal(node)
	if err != nil {
		return rawOperation{}, false
	}
	var op rawOperation
	if err := yaml.Unmarshal(b, &op); err != nil {
		return rawOperation{}, false
	}
	return op, true
}

func buildOperation(method, path string, ro rawOperation, pathParams []rawParameter) Operation {
	op := Operation{
		OpID:       ro.OperationID,
		Method:     method,
		Path:       path,
		Summary:    ro.Summary,
		XCLI:       *ro.XCLI,
		FuncName:   exportName(ro.OperationID) + "Cmd",
		OutputMode: ro.XCLI.Output,
	}
	if op.OutputMode == "" {
		op.OutputMode = "table_or_json"
	}
	// Walk path + operation parameters, projecting each into a Cobra flag.
	for _, p := range append(append([]rawParameter{}, pathParams...), ro.Parameters...) {
		if p.Name == "" {
			continue
		}
		param := projectParam(p)
		if param.In == "path" {
			op.HasPathParam = true
		}
		op.Parameters = append(op.Parameters, param)
	}
	// Detect request body (presence indicates we need a --body flag).
	if len(ro.RequestBody) > 0 {
		op.HasBody = true
	}
	// Default to ListXxx returning []T for GET-list endpoints; otherwise
	// the generated command just dumps the raw decoded JSON.
	op.HasResponse = true
	op.ResponseType = "json.RawMessage"
	op.IsList = method == "GET" && !strings.Contains(path, "{")
	return op
}

func projectParam(p rawParameter) Parameter {
	flagType := "string"
	goType := "string"
	if schemaType, ok := p.Schema["type"].(string); ok {
		switch schemaType {
		case "integer":
			flagType = "int"
			goType = "int"
		case "boolean":
			flagType = "bool"
			goType = "bool"
		}
	}
	return Parameter{
		Name:     p.Name,
		In:       p.In,
		Required: p.Required,
		GoType:   goType,
		FlagName: strings.ReplaceAll(p.Name, "_", "-"),
		FlagType: flagType,
		Help:     fmt.Sprintf("%s parameter (%s)", p.Name, p.In),
	}
}

func exportName(opID string) string {
	parts := strings.FieldsFunc(opID, func(r rune) bool { return r == '_' || r == '-' })
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]))
		b.WriteString(p[1:])
	}
	return b.String()
}

// titleCase capitalizes the first byte of an ASCII identifier. The OpenAPI
// names we project are always ASCII so we don't need golang.org/x/text/cases.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func filenameFor(op Operation) string {
	parts := slices.Clone(op.XCLI.Command)
	return strings.Join(parts, "_") + ".gen.go"
}

func emitCommand(op Operation, outDir string) error {
	t, err := template.New("command").Funcs(template.FuncMap{
		"title": titleCase,
		"last": func(parts []string) string {
			if len(parts) == 0 {
				return ""
			}
			return parts[len(parts)-1]
		},
	}).Parse(commandTmpl)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, op); err != nil {
		return err
	}
	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return fmt.Errorf("gofmt %s: %w\n%s", op.OpID, err, buf.String())
	}
	return os.WriteFile(filepath.Join(outDir, filenameFor(op)), formatted, 0o644)
}

func emitRegister(ops []Operation, outDir string) error {
	groups := map[string][]Operation{}
	for _, op := range ops {
		root := op.XCLI.Command[0]
		groups[root] = append(groups[root], op)
	}
	roots := make([]string, 0, len(groups))
	for r := range groups {
		roots = append(roots, r)
	}
	sort.Strings(roots)
	for _, r := range roots {
		sort.Slice(groups[r], func(i, j int) bool {
			return strings.Join(groups[r][i].XCLI.Command, " ") < strings.Join(groups[r][j].XCLI.Command, " ")
		})
	}

	data := struct {
		Groups map[string][]Operation
		Roots  []string
	}{groups, roots}

	t, err := template.New("register").Parse(registerTmpl)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return err
	}
	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return fmt.Errorf("gofmt register: %w\n%s", err, buf.String())
	}
	return os.WriteFile(filepath.Join(outDir, "register.gen.go"), formatted, 0o644)
}

func emitDoc(outDir string) error {
	const doc = `// Package generated holds Cobra commands codegenned from schema/control-api.yaml.
// DO NOT EDIT — regenerate with ` + "`make generate-cli`" + ` after schema changes.
package generated
`
	return os.WriteFile(filepath.Join(outDir, "doc.go"), []byte(doc), 0o644)
}

const commandTmpl = `// Code generated by cobragen; DO NOT EDIT.
// Source operation: {{.OpID}} ({{.Method}} {{.Path}})

package generated

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
{{if .HasPathParam}}	"strings"
{{end}}	"time"

	"github.com/spf13/cobra"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/desktopbridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
)

// {{.FuncName}} {{.Summary}}
func {{.FuncName}}() *cobra.Command {
	cmd := &cobra.Command{
		Use:   {{printf "%q" (last .XCLI.Command)}},
		Short: {{printf "%q" .Summary}},
	}
{{range .Parameters}}{{if eq .FlagType "string"}}	var flag{{title .Name}} string
	cmd.Flags().StringVar(&flag{{title .Name}}, {{printf "%q" .FlagName}}, "", {{printf "%q" .Help}})
{{else if eq .FlagType "int"}}	var flag{{title .Name}} int
	cmd.Flags().IntVar(&flag{{title .Name}}, {{printf "%q" .FlagName}}, 0, {{printf "%q" .Help}})
{{else if eq .FlagType "bool"}}	var flag{{title .Name}} bool
	cmd.Flags().BoolVar(&flag{{title .Name}}, {{printf "%q" .FlagName}}, false, {{printf "%q" .Help}})
{{end}}{{end}}	jsonOut := false
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON instead of a table.")

	cmd.RunE = func(c *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(c.Context(), 30*time.Second)
		defer cancel()

		ep, err := desktopbridge.LoadEndpoint()
		if err != nil {
			return fmt.Errorf("desktop endpoint: %w", err)
		}
		if _, err := desktopbridge.Handshake(ctx, ep); err != nil {
			return fmt.Errorf("handshake: %w", err)
		}
		client, err := desktopbridge.NewClient(ep)
		if err != nil {
			if errors.Is(err, desktopbridge.ErrNoCredentials) {
				fmt.Println(ui.WarningMsg("Not paired. Run ` + "`zypheron login`" + ` first."))
			}
			return err
		}

		path := {{printf "%q" .Path}}
{{range .Parameters}}{{if eq .In "path"}}		path = strings.Replace(path, "{"+{{printf "%q" .Name}}+"}", url.PathEscape({{if eq .FlagType "string"}}flag{{title .Name}}{{else}}fmt.Sprintf("%v", flag{{title .Name}}){{end}}), 1)
{{end}}{{end}}		q := url.Values{}
{{range .Parameters}}{{if eq .In "query"}}{{if eq .FlagType "string"}}		if flag{{title .Name}} != "" { q.Set({{printf "%q" .Name}}, flag{{title .Name}}) }
{{else if eq .FlagType "int"}}		if flag{{title .Name}} != 0 { q.Set({{printf "%q" .Name}}, fmt.Sprintf("%d", flag{{title .Name}})) }
{{else if eq .FlagType "bool"}}		if flag{{title .Name}} { q.Set({{printf "%q" .Name}}, "true") }
{{end}}{{end}}{{end}}		if encoded := q.Encode(); encoded != "" {
			path = path + "?" + encoded
		}
		_ = ctx
		_ = client
		_ = jsonOut

		resp, err := client.Do(ctx, {{printf "%q" .Method}}, path, nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var body json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		pretty, _ := json.MarshalIndent(body, "", "  ")
		fmt.Println(string(pretty))
		return nil
	}
	return cmd
}
`

const registerTmpl = `// Code generated by cobragen; DO NOT EDIT.

package generated

import "github.com/spf13/cobra"

// RegisterGenerated mounts every cobragen-emitted command under the supplied
// parent (typically rootCmd). Sibling subtrees are merged on root names — for
// instance every command whose x-cli.command starts with ["scope"] mounts as
// a child of the same "scope" Cobra group.
func RegisterGenerated(parent *cobra.Command) {
{{range .Roots}}{{$root := .}}	{{.}}Group := &cobra.Command{Use: {{printf "%q" .}}, Short: "{{.}} commands"}
{{range index $.Groups .}}	{{$root}}Group.AddCommand({{.FuncName}}())
{{end}}	parent.AddCommand({{.}}Group)
{{end}}}
`
