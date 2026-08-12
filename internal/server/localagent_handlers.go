package server

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// These handlers back the "Local Agent" panel on the dashboard
// (templates/local_agent.html): a one-click way to run a real
// agent.Agent against the machine the server itself is on, without a
// separate `breachharbor agent run` / `agent enroll` round trip. Every
// handler re-renders the same fragment so HTMX can swap it in place
// (hx-target="#local-agent-panel" hx-swap="outerHTML" on every button
// in that template).
//
// Every mutating route here sits behind WebAuthMiddleware (login
// required) same as the rest of /api/web, but that alone isn't enough
// — see LocalAgentManager's ErrLocalAgentDisabled/ErrLocalAgentNotOwner
// doc comments for why the manager itself also gates on an explicit
// operator opt-in and per-starter ownership, not just "logged in."

func (s *Server) handleLocalAgentStatus(c *gin.Context) {
	s.renderLocalAgentPanel(c, http.StatusOK)
}

func (s *Server) handleLocalAgentStart(c *gin.Context) {
	userID, ok := c.Get("user_id")
	if !ok {
		c.Redirect(http.StatusTemporaryRedirect, "/login")
		return
	}
	err := s.localAgent.Start(userID.(uint))
	s.renderLocalAgentPanel(c, localAgentStatusCode(err))
}

func (s *Server) handleLocalAgentStop(c *gin.Context) {
	userID, ok := c.Get("user_id")
	if !ok {
		c.Redirect(http.StatusTemporaryRedirect, "/login")
		return
	}
	err := s.localAgent.Stop(userID.(uint))
	s.renderLocalAgentPanel(c, localAgentStatusCode(err))
}

func (s *Server) handleLocalAgentEnforce(c *gin.Context) {
	userID, ok := c.Get("user_id")
	if !ok {
		c.Redirect(http.StatusTemporaryRedirect, "/login")
		return
	}
	on, _ := strconv.ParseBool(c.PostForm("on"))
	err := s.localAgent.SetEnforce(userID.(uint), on)
	s.renderLocalAgentPanel(c, localAgentStatusCode(err))
}

// localAgentStatusCode maps a LocalAgentManager error to the HTTP
// status the re-rendered fragment is returned with — the fragment
// itself (via .status.LastError) carries the human-readable reason
// either way, this just keeps the status code honest for anything
// inspecting the response (curl, htmx's own error handling, logs).
func localAgentStatusCode(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrLocalAgentNotOwner):
		return http.StatusForbidden
	case errors.Is(err, ErrLocalAgentDisabled):
		return http.StatusForbidden
	default:
		return http.StatusOK // already-running/not-running etc. are normal UI states, not failures
	}
}

func (s *Server) renderLocalAgentPanel(c *gin.Context, code int) {
	c.HTML(code, "local_agent.html", gin.H{"status": s.localAgent.Status()})
}
