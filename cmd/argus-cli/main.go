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
	root.PersistentFlags().StringVar(&token, "token", getenv("ARGUS_API_TOKEN", ""), "OIDC JWT access token for Argus API")

	root.AddCommand(
		incidentCmd(&baseURL, &token),
		remediationCmd(&baseURL, &token),
		scenarioCmd(&baseURL, &token),
		runbookCmd(&baseURL, &token),
		auditCmd(&baseURL, &token),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func auditCmd(baseURL, token *string) *cobra.Command {
	cmd := &cobra.Command{Use: "audit"}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List append-only audit ledger entries",
			RunE: func(cmd *cobra.Command, args []string) error {
				return printRequest(http.MethodGet, *baseURL+"/v1/audit", nil, *token)
			},
		},
		&cobra.Command{
			Use:   "verify",
			Short: "Verify the complete tamper-evident audit hash chain",
			RunE: func(cmd *cobra.Command, args []string) error {
				return printRequest(http.MethodGet, *baseURL+"/v1/audit/verify", nil, *token)
			},
		},
	)
	return cmd
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
	approve := decisionCommand("approve", "Approve a remediation", baseURL, token)
	deny := decisionCommand("deny", "Deny a remediation", baseURL, token)

	cmd.AddCommand(
		&cobra.Command{
			Use:   "list <incident_id>",
			Short: "List remediations for an incident",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return printRequest(http.MethodGet, *baseURL+"/v1/incidents/"+args[0]+"/remediations", nil, *token)
			},
		},
		approve,
		deny,
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

func decisionCommand(decision, description string, baseURL, token *string) *cobra.Command {
	var reason string
	route := decision
	if decision == "deny" {
		route = "reject"
	}
	cmd := &cobra.Command{
		Use:   decision + " <remediation_id>",
		Short: description,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(reason) == "" {
				return fmt.Errorf("--reason is required")
			}
			body := map[string]any{"reason": reason}
			return printRequest(http.MethodPost, *baseURL+"/v1/remediations/"+args[0]+"/"+route, body, *token)
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "Why this remediation should be approved or denied")
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
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("OIDC access token is required; set ARGUS_API_TOKEN or use --token")
	}
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
