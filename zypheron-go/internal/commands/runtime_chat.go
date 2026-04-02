package commands

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
)

func runRuntimeChatTurn(
	bridge *aibridge.AIBridge,
	messages []aibridge.Message,
	provider string,
	model string,
	temperature float64,
	maxTokens int,
	sessionID string,
	allowInteractiveApproval bool,
) (*aibridge.ChatResponse, error) {
	currentSessionID := sessionID
	for {
		resp, err := bridge.ChatDetailed(messages, provider, model, temperature, maxTokens, currentSessionID)
		if err != nil {
			return nil, err
		}
		if resp.SessionID != "" {
			currentSessionID = resp.SessionID
		}
		if resp.ApprovalRequest == nil {
			return resp, nil
		}
		if !allowInteractiveApproval {
			toolName, _ := resp.ApprovalRequest["tool_name"].(string)
			return nil, fmt.Errorf("runtime approval required for %s (task %s)", toolName, resp.TaskID)
		}

		requestID, _ := resp.ApprovalRequest["request_id"].(string)
		if strings.TrimSpace(requestID) == "" || strings.TrimSpace(resp.TaskID) == "" {
			return nil, fmt.Errorf("runtime approval request is missing task metadata")
		}
		decision, err := promptRuntimeApproval(resp.ApprovalRequest)
		if err != nil {
			return nil, err
		}
		approved, err := bridge.SubmitTaskApproval(resp.TaskID, requestID, decision)
		if err != nil {
			return nil, err
		}
		if approved.SessionID != "" {
			currentSessionID = approved.SessionID
		}
		if approved.ApprovalRequest == nil {
			return &aibridge.ChatResponse{
				Content:         approved.Content,
				SessionID:       approved.SessionID,
				TaskID:          approved.TaskID,
				TaskStatus:      approved.TaskStatus,
				ProgressEvents:  approved.ProgressEvents,
				ApprovalRequest: approved.ApprovalRequest,
			}, nil
		}
	}
}

func promptRuntimeApproval(request map[string]interface{}) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	toolName, _ := request["tool_name"].(string)
	reason, _ := request["reason"].(string)
	riskCategory, _ := request["risk_category"].(string)

	fmt.Println()
	fmt.Printf("Approval required for `%s` [%s]\n", toolName, riskCategory)
	if strings.TrimSpace(reason) != "" {
		fmt.Printf("Reason: %s\n", reason)
	}
	fmt.Println("Options: [1] approve once  [2] allow for session  [3] deny")

	for {
		fmt.Print("Your choice [1-3]: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		switch strings.TrimSpace(strings.ToLower(input)) {
		case "1", "approve", "approve once":
			return "approve_once", nil
		case "2", "session", "allow for session":
			return "approve_session", nil
		case "3", "deny", "no":
			return "deny", nil
		}
		fmt.Println("Invalid choice. Enter 1, 2, or 3.")
	}
}
