package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func main() {
	var baseURL string
	var token string

	root := &cobra.Command{
		Use:   "argus",
		Short: "Argus operational CLI",
	}
	root.PersistentFlags().StringVar(&baseURL, "base-url", getenv("ARGUS_API_BASE_URL", "http://localhost:8080"), "Argus API base URL")
	root.PersistentFlags().StringVar(&token, "token", getenv("ARGUS_API_TOKEN", "local-admin-token"), "Bearer token for Argus API")

	root.AddCommand(
		incidentCmd(&baseURL, &token),
		remediationCmd(&baseURL, &token),
		scenarioCmd(&baseURL, &token),
		runbookCmd(&baseURL, &token),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func incidentCmd(baseURL, token *string) *cobra.Command {
	cmd := &cobra.Command{Use: "incident"}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List incidents",
			RunE: func(cmd *cobra.Command, args []string) error {
				return printRequest(http.MethodGet, *baseURL+"/v1/incidents", nil, *token)
			},
		},
		&cobra.Command{
			Use:   "get <incident_id>",
			Short: "Get incident details",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return printRequest(http.MethodGet, *baseURL+"/v1/incidents/"+args[0], nil, *token)
			},
		},
		&cobra.Command{
			Use:   "rca <incident_id>",
			Short: "Get latest RCA report",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return printRequest(http.MethodGet, *baseURL+"/v1/incidents/"+args[0]+"/rca", nil, *token)
			},
		},
	)
	return cmd
}

func remediationCmd(baseURL, token *string) *cobra.Command {
	cmd := &cobra.Command{Use: "remediation"}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "list <incident_id>",
			Short: "List remediations for an incident",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return printRequest(http.MethodGet, *baseURL+"/v1/incidents/"+args[0]+"/remediations", nil, *token)
			},
		},
		&cobra.Command{
			Use:   "approve <remediation_id>",
			Short: "Approve a remediation",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				body := map[string]any{"reason": "Approved from CLI"}
				return printRequest(http.MethodPost, *baseURL+"/v1/remediations/"+args[0]+"/approve", body, *token)
			},
		},
		func() *cobra.Command {
			var dryRun bool
			sub := &cobra.Command{
				Use:   "execute <remediation_id>",
				Short: "Execute a remediation",
				Args:  cobra.ExactArgs(1),
				RunE: func(cmd *cobra.Command, args []string) error {
					body := map[string]any{"dry_run": dryRun}
					return printRequest(http.MethodPost, *baseURL+"/v1/remediations/"+args[0]+"/execute", body, *token)
				},
			}
			sub.Flags().BoolVar(&dryRun, "dry-run", true, "Execute in dry-run mode")
			return sub
		}(),
	)

	return cmd
}

func scenarioCmd(baseURL, token *string) *cobra.Command {
	cmd := &cobra.Command{Use: "scenario"}
	cmd.AddCommand(&cobra.Command{
		Use:   "run <name>",
		Short: "Run a demo scenario via the API helper",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{"scenario": args[0]}
			return printRequest(http.MethodPost, *baseURL+"/v1/signals/manual", body, *token)
		},
	})
	return cmd
}

func runbookCmd(baseURL, token *string) *cobra.Command {
	cmd := &cobra.Command{Use: "runbook"}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "index",
			Short: "Queue runbook indexing",
			RunE: func(cmd *cobra.Command, args []string) error {
				return printRequest(http.MethodPost, *baseURL+"/v1/runbooks/reindex", map[string]any{}, *token)
			},
		},
	)
	return cmd
}

func printRequest(method, url string, body any, token string) error {
	var reader io.Reader
	if body != nil {
		payload, _ := json.Marshal(body)
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	fmt.Println(strings.TrimSpace(string(data)))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("request failed: %s", resp.Status)
	}
	return nil
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
