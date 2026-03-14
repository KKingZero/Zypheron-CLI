package commands

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/licensing"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/utils"
)

// TeamCmd returns the team management command
func TeamCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "team",
		Short: "Team management (Enterprise)",
		Long: `Manage your team for Enterprise subscriptions.

Team management allows you to:
  • Create and manage teams
  • Invite and remove team members
  • Assign roles (owner, admin, member)
  • Allocate tokens to team members
  • View team audit logs

REQUIRES: Enterprise subscription

Examples:
  zypheron team                    # Show team overview
  zypheron team members            # List team members
  zypheron team invite user@co.com # Invite a new member
  zypheron team audit-log          # View audit log`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check for enterprise license
			if err := licensing.RequireTeams(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			return runTeamOverview()
		},
	}

	cmd.AddCommand(teamMembersCmd())
	cmd.AddCommand(teamInviteCmd())
	cmd.AddCommand(teamRemoveCmd())
	cmd.AddCommand(teamAuditLogCmd())
	cmd.AddCommand(teamTokensCmd())
	cmd.AddCommand(teamCreateCmd())

	return cmd
}

// runTeamOverview displays team information
func runTeamOverview() error {
	manager := licensing.GetManager()
	license := manager.License()

	fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
	fmt.Println(ui.Primary.Sprint("║              TEAM MANAGEMENT                            ║"))
	fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

	if license.TeamID == "" {
		fmt.Println(ui.WarningMsg("You are not part of a team"))
		fmt.Println()
		fmt.Println(ui.InfoMsg("Create a new team:"))
		fmt.Println(ui.Muted.Sprint("  zypheron team create \"My Team\""))
		fmt.Println()
		fmt.Println(ui.InfoMsg("Or join an existing team:"))
		fmt.Println(ui.Muted.Sprint("  Accept an invitation link from a team admin"))
		fmt.Println()
		return nil
	}

	// Display team info
	fmt.Println(ui.InfoMsg("Team Information"))
	fmt.Printf("  Team ID:   %s\n", ui.Accent.Sprint(license.TeamID))
	fmt.Printf("  Your Role: %s\n", ui.Success.Sprint(utils.Capitalize(license.TeamRole)))
	fmt.Println()

	// Display token pool (would fetch from API in production)
	fmt.Println(ui.InfoMsg("Token Pool"))
	fmt.Printf("  Pool Total:     %s\n", formatTokens(15000000))
	fmt.Printf("  Pool Used:      %s\n", formatTokens(license.TokensUsed))
	fmt.Printf("  Pool Remaining: %s\n", ui.Success.Sprint(formatTokens(license.TokensRemaining)))
	fmt.Println()

	// Quick actions
	fmt.Println(ui.InfoMsg("Quick Actions"))
	fmt.Println(ui.Muted.Sprint("  zypheron team members     List team members"))
	fmt.Println(ui.Muted.Sprint("  zypheron team invite      Invite new member"))
	fmt.Println(ui.Muted.Sprint("  zypheron team tokens      View token allocations"))
	fmt.Println(ui.Muted.Sprint("  zypheron team audit-log   View audit log"))
	fmt.Println()

	return nil
}

// teamMembersCmd lists team members
func teamMembersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "members",
		Short: "List team members",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := licensing.RequireTeams(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			manager := licensing.GetManager()
			license := manager.License()

			if license.TeamID == "" {
				fmt.Println(ui.WarningMsg("You are not part of a team"))
				return nil
			}

			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║              TEAM MEMBERS                               ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

			// In production, this would fetch from API
			fmt.Println(ui.InfoMsg("Team members would be fetched from API"))
			fmt.Println()
			fmt.Println(ui.Muted.Sprint("This feature requires API connection."))
			fmt.Println(ui.Muted.Sprint("View members in web dashboard: https://zypheron.io/team"))
			fmt.Println()

			return nil
		},
	}
}

// teamInviteCmd invites a new team member
func teamInviteCmd() *cobra.Command {
	var role string

	cmd := &cobra.Command{
		Use:   "invite [email]",
		Short: "Invite a new team member",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := licensing.RequireTeams(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			manager := licensing.GetManager()
			license := manager.License()

			// Check if user is admin or owner
			if license.TeamRole != "owner" && license.TeamRole != "admin" {
				fmt.Println(ui.Error("Only team owners and admins can invite members"))
				return nil
			}

			var email string
			if len(args) > 0 {
				email = args[0]
			} else {
				prompt := &survey.Input{
					Message: "Enter email address to invite:",
				}
				if err := survey.AskOne(prompt, &email, survey.WithValidator(survey.Required)); err != nil {
					return err
				}
			}

			// Select role if not provided
			if role == "" {
				rolePrompt := &survey.Select{
					Message: "Select role for new member:",
					Options: []string{"member", "admin"},
					Default: "member",
				}
				if err := survey.AskOne(rolePrompt, &role); err != nil {
					return err
				}
			}

			fmt.Println()
			fmt.Println(ui.InfoMsg(fmt.Sprintf("Inviting %s as %s...", email, role)))
			fmt.Println()

			// In production, this would call the API
			fmt.Println(ui.WarningMsg("API connection required for invitation"))
			fmt.Println(ui.Muted.Sprint("Invite via web dashboard: https://zypheron.io/team/invite"))
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().StringVarP(&role, "role", "r", "", "Role for new member (member, admin)")

	return cmd
}

// teamRemoveCmd removes a team member
func teamRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove [email or user-id]",
		Short: "Remove a team member",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := licensing.RequireTeams(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			manager := licensing.GetManager()
			license := manager.License()

			// Check if user is admin or owner
			if license.TeamRole != "owner" && license.TeamRole != "admin" {
				fmt.Println(ui.Error("Only team owners and admins can remove members"))
				return nil
			}

			userRef := args[0]

			// Confirm removal
			confirm := false
			prompt := &survey.Confirm{
				Message: fmt.Sprintf("Are you sure you want to remove %s from the team?", userRef),
				Default: false,
			}
			if err := survey.AskOne(prompt, &confirm); err != nil {
				return err
			}

			if !confirm {
				fmt.Println(ui.InfoMsg("Removal cancelled"))
				return nil
			}

			fmt.Println()
			fmt.Println(ui.InfoMsg(fmt.Sprintf("Removing %s from team...", userRef)))
			fmt.Println()

			// In production, this would call the API
			fmt.Println(ui.WarningMsg("API connection required for member removal"))
			fmt.Println(ui.Muted.Sprint("Manage via web dashboard: https://zypheron.io/team"))
			fmt.Println()

			return nil
		},
	}
}

// teamAuditLogCmd displays audit log
func teamAuditLogCmd() *cobra.Command {
	var limit int
	var action string

	cmd := &cobra.Command{
		Use:     "audit-log",
		Aliases: []string{"audit", "logs"},
		Short:   "View team audit log",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := licensing.RequireAuditLogs(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			manager := licensing.GetManager()
			license := manager.License()

			// Check if user is admin or owner
			if license.TeamRole != "owner" && license.TeamRole != "admin" {
				fmt.Println(ui.Error("Only team owners and admins can view audit logs"))
				return nil
			}

			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║              TEAM AUDIT LOG                             ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

			fmt.Println(ui.InfoMsg(fmt.Sprintf("Showing last %d entries", limit)))
			if action != "" {
				fmt.Printf("  Filtered by action: %s\n", ui.Accent.Sprint(action))
			}
			fmt.Println()

			// In production, this would fetch from API
			fmt.Println(ui.Muted.Sprint("Audit log entries would be fetched from API"))
			fmt.Println()
			fmt.Println(ui.InfoMsg("Sample audit log format:"))
			fmt.Println(ui.Muted.Sprint("  2025-01-15 10:30:00  user@company.com  member_invited  {email: new@co.com}"))
			fmt.Println(ui.Muted.Sprint("  2025-01-15 09:15:00  admin@company.com scan_executed   {target: 192.168.1.1}"))
			fmt.Println(ui.Muted.Sprint("  2025-01-14 16:45:00  user@company.com  exploit_run     {target: vulnerable.com}"))
			fmt.Println()
			fmt.Println(ui.Muted.Sprint("Full audit log: https://zypheron.io/team/audit"))
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().IntVarP(&limit, "limit", "n", 50, "Number of entries to show")
	cmd.Flags().StringVarP(&action, "action", "a", "", "Filter by action type")

	return cmd
}

// teamTokensCmd manages token allocation
func teamTokensCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tokens",
		Short: "View and manage token allocations",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := licensing.RequireTeams(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║              TOKEN ALLOCATIONS                          ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

			// In production, this would fetch from API
			fmt.Println(ui.InfoMsg("Team Token Pool"))
			fmt.Printf("  Total:       %s\n", formatTokens(15000000))
			fmt.Printf("  Allocated:   %s\n", formatTokens(10000000))
			fmt.Printf("  Unallocated: %s\n", ui.Success.Sprint(formatTokens(5000000)))
			fmt.Println()

			fmt.Println(ui.InfoMsg("Member Allocations (sample)"))
			fmt.Println(ui.Muted.Sprint("  owner@company.com    5M tokens   (2.1M used)"))
			fmt.Println(ui.Muted.Sprint("  admin@company.com    3M tokens   (1.5M used)"))
			fmt.Println(ui.Muted.Sprint("  user@company.com     2M tokens   (800K used)"))
			fmt.Println()

			fmt.Println(ui.InfoMsg("Allocate tokens:"))
			fmt.Println(ui.Muted.Sprint("  zypheron team tokens allocate user@company.com 1000000"))
			fmt.Println()

			return nil
		},
	}

	cmd.AddCommand(teamTokensAllocateCmd())

	return cmd
}

// teamTokensAllocateCmd allocates tokens to a member
func teamTokensAllocateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "allocate [email] [tokens]",
		Short: "Allocate tokens to a team member",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := licensing.RequireTeams(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			manager := licensing.GetManager()
			license := manager.License()

			// Check if user is admin or owner
			if license.TeamRole != "owner" && license.TeamRole != "admin" {
				fmt.Println(ui.Error("Only team owners and admins can allocate tokens"))
				return nil
			}

			email := args[0]
			tokens := args[1]

			fmt.Println()
			fmt.Println(ui.InfoMsg(fmt.Sprintf("Allocating %s tokens to %s...", tokens, email)))
			fmt.Println()

			// In production, this would call the API
			fmt.Println(ui.WarningMsg("API connection required for token allocation"))
			fmt.Println(ui.Muted.Sprint("Manage via web dashboard: https://zypheron.io/team/tokens"))
			fmt.Println()

			return nil
		},
	}
}

// teamCreateCmd creates a new team
func teamCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create [name]",
		Short: "Create a new team",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := licensing.RequireTeams(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			manager := licensing.GetManager()
			license := manager.License()

			if license.TeamID != "" {
				fmt.Println(ui.WarningMsg("You are already part of a team"))
				fmt.Println(ui.Muted.Sprint("Leave your current team first or manage it:"))
				fmt.Println(ui.Muted.Sprint("  zypheron team"))
				return nil
			}

			var teamName string
			if len(args) > 0 {
				teamName = args[0]
			} else {
				prompt := &survey.Input{
					Message: "Enter team name:",
				}
				if err := survey.AskOne(prompt, &teamName, survey.WithValidator(survey.Required)); err != nil {
					return err
				}
			}

			fmt.Println()
			fmt.Println(ui.InfoMsg(fmt.Sprintf("Creating team: %s...", teamName)))
			fmt.Println()

			// In production, this would call the API
			fmt.Println(ui.WarningMsg("API connection required for team creation"))
			fmt.Println(ui.Muted.Sprint("Create via web dashboard: https://zypheron.io/team/create"))
			fmt.Println()

			return nil
		},
	}
}
