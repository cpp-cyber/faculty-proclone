package handlers

import (
	"fmt"
	"log"
	"net/http"

	"github.com/cpp-cyber/proclone/internal/api/auth"
	"github.com/cpp-cyber/proclone/internal/ldap"
	"github.com/cpp-cyber/proclone/internal/proxmox"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// =================================================
// Login / Logout / Session Handlers
// =================================================

// NewAuthHandler creates a new authentication handler
func NewAuthHandler() (*AuthHandler, error) {
	proxmoxServiceInterface, err := proxmox.NewService()
	if err != nil {
		return nil, fmt.Errorf("failed to create proxmox service: %w", err)
	}

	// Type assert to get concrete type for auth service
	proxmoxService, ok := proxmoxServiceInterface.(*proxmox.ProxmoxService)
	if !ok {
		return nil, fmt.Errorf("failed to convert proxmox service to concrete type")
	}

	authService, err := auth.NewAuthService(proxmoxService)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth service: %w", err)
	}

	ldapService, err := ldap.NewLDAPService()
	if err != nil {
		return nil, fmt.Errorf("failed to create LDAP service: %w", err)
	}

	log.Println("Auth handler initialized")

	return &AuthHandler{
		authService:    authService,
		ldapService:    ldapService,
		proxmoxService: proxmoxServiceInterface,
	}, nil
}

// GetAuthService returns the auth service for use in middleware
func (h *AuthHandler) GetAuthService() auth.Service {
	return h.authService
}

// LoginHandler handles the login POST request
func (h *AuthHandler) LoginHandler(c *gin.Context) {
	var req UsernamePasswordRequest
	if !validateAndBind(c, &req) {
		return
	}

	// Authenticate user
	valid, err := h.authService.Authenticate(req.Username, req.Password)
	if err != nil {
		log.Printf("Authentication failed for user %s: %v", req.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Authentication failed"})
		return
	}

	if !valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Create session
	session := sessions.Default(c)
	session.Set("id", req.Username)

	// Check if user is admin
	isAdmin, err := h.authService.IsAdmin(req.Username)
	if err != nil {
		log.Printf("Error checking admin status for user %s: %v", req.Username, err)
		isAdmin = false
	}
	session.Set("isAdmin", isAdmin)

	// Check if user is creator
	isCreator, err := h.authService.IsCreator(req.Username)
	if err != nil {
		log.Printf("Error checking creator status for user %s: %v", req.Username, err)
		isCreator = false
	}
	session.Set("isCreator", isCreator)

	if err := session.Save(); err != nil {
		log.Printf("Failed to save session for user %s: %v", req.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Login successful",
		"isAdmin":   isAdmin,
		"isCreator": isCreator,
	})
}

// LogoutHandler handles user logout
func (h *AuthHandler) LogoutHandler(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()

	if err := session.Save(); err != nil {
		log.Printf("Failed to clear session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}

// SessionHandler returns current session information for authenticated users
func (h *AuthHandler) SessionHandler(c *gin.Context) {
	session := sessions.Default(c)

	// Since this is under private routes, AuthRequired middleware ensures session exists
	id := session.Get("id")
	isAdmin := session.Get("isAdmin")
	isCreator := session.Get("isCreator")

	// Convert to bool, defaulting to false if not set
	adminStatus := false
	if isAdmin != nil {
		adminStatus = isAdmin.(bool)
	}

	creatorStatus := false
	if isCreator != nil {
		creatorStatus = isCreator.(bool)
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"username":      id.(string),
		"isAdmin":       adminStatus,
		"isCreator":     creatorStatus,
	})
}
