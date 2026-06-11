package query

import (
	"context"
	"encoding/json"
	coreerror "sc/core/error"
	corejwt "sc/core/jwt"
	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"
	"testing"
	"time"
)

// ── mock JWTSvc ───────────────────────────────────────────────────────────

type mockJwtService struct {
	accessToken        string
	refreshToken       string
	accessErr          error
	refreshErr         error
	idTokenErr         error
	parseClaims        *corejwt.Claims
	parseErr           error
	parseIDTokenClaims *corejwt.IDTokenClaims
	parseIDTokenErr    error
	issuer             string
	// captured call arguments
	capturedAccessUserID     string
	capturedAccessScope      string
	capturedAccessExpireSecs int
}

func (m *mockJwtService) GenAccessToken(userID, scope string, expireSecs int) (string, error) {
	m.capturedAccessUserID = userID
	m.capturedAccessScope = scope
	m.capturedAccessExpireSecs = expireSecs
	return m.accessToken, m.accessErr
}

func (m *mockJwtService) GenRefreshToken(_ string) (string, error) {
	return m.refreshToken, m.refreshErr
}

func (m *mockJwtService) GenIDToken(_ port.IDTokenArgs) (string, error) {
	return "mock-id-token", m.idTokenErr
}

func (m *mockJwtService) GetJWKS() map[string][]corejwt.JWK {
	return map[string][]corejwt.JWK{"keys": {{Kid: "test-kid", Kty: "RSA"}}}
}

func (m *mockJwtService) ParseJWT(_ string) (*corejwt.Claims, error) {
	return m.parseClaims, m.parseErr
}

func (m *mockJwtService) ParseIDToken(_ string) (*corejwt.IDTokenClaims, error) {
	return m.parseIDTokenClaims, m.parseIDTokenErr
}

func (m *mockJwtService) GetIssuer() string { return m.issuer }

// ── mock UserRepository ───────────────────────────────────────────────────────

type mockUserRepo struct {
	users       map[string]*entity.User
	saveErr     error
	findByIDErr error
}

func newMockRepo(users ...*entity.User) *mockUserRepo {
	m := &mockUserRepo{users: make(map[string]*entity.User)}
	for _, u := range users {
		m.users[string(u.ID)] = u
	}
	return m
}

func (m *mockUserRepo) CreateUser(_ context.Context, user *entity.User) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.users[string(user.ID)] = user
	return nil
}

func (m *mockUserRepo) FindByEmail(_ context.Context, email string) (*entity.User, error) {
	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, coreerror.ErrNotFound
}

func (m *mockUserRepo) FindByID(_ context.Context, id entity.UserID) (*entity.User, error) {
	if m.findByIDErr != nil {
		return nil, m.findByIDErr
	}
	if u, ok := m.users[string(id)]; ok {
		return u, nil
	}
	return nil, coreerror.ErrNotFound
}

func (m *mockUserRepo) FindByPasswordResetTokenHash(_ context.Context, tokenHash string) (*entity.User, error) {
	for _, u := range m.users {
		if u.PasswordResetTokenHash != nil && *u.PasswordResetTokenHash == tokenHash {
			return u, nil
		}
	}
	return nil, coreerror.ErrNotFound
}

func (m *mockUserRepo) Save(_ context.Context, user *entity.User) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.users[string(user.ID)] = user
	return nil
}

func (m *mockUserRepo) UpdateByPasswordResetTokenHash(_ context.Context, tokenHash string, update func(*entity.User) error) error {
	for _, u := range m.users {
		if u.PasswordResetTokenHash != nil && *u.PasswordResetTokenHash == tokenHash {
			cp := *u
			if err := update(&cp); err != nil {
				return err
			}
			m.users[string(cp.ID)] = &cp
			return nil
		}
	}
	return coreerror.ErrNotFound
}

// ── mock Cache ────────────────────────────────────────────────────────────────

type mockCache struct {
	items  map[string]any
	setErr error
	getErr error
}

func newMockCache() *mockCache {
	return &mockCache{items: make(map[string]any)}
}

func (m *mockCache) seed(key string, value any) *mockCache {
	m.items[key] = value
	return m
}

func (m *mockCache) Set(_ context.Context, key string, value any, _ *time.Duration) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.items[key] = value
	return nil
}
func (m *mockCache) Get(_ context.Context, key string, dest any) bool {
	v, ok := m.items[key]
	if !ok || dest == nil {
		return ok
	}
	b, err := json.Marshal(v)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, dest) == nil
}
func (m *mockCache) GetAndDelete(_ context.Context, key string, dest any) bool {
	v, ok := m.items[key]
	if !ok {
		return false
	}
	delete(m.items, key)
	if dest == nil {
		return true
	}
	b, err := json.Marshal(v)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, dest) == nil
}
func (m *mockCache) GetErr(_ context.Context, key string, dest any) (bool, error) {
	if m.getErr != nil {
		return false, m.getErr
	}
	return m.Get(context.TODO(), key, dest), nil
}
func (m *mockCache) Delete(_ context.Context, key string)                      { delete(m.items, key) }
func (m *mockCache) Incr(_ context.Context, _ string) (int64, error)           { return 0, nil }
func (m *mockCache) Expire(_ context.Context, _ string, _ time.Duration) error { return nil }

// ── mock RefreshTokenRepository ───────────────────────────────────────────────

type mockRefreshTokenRepo struct {
	tokens  map[string]*entity.RefreshToken
	saveErr error
}

func newMockRefreshTokenRepo(tokens ...*entity.RefreshToken) *mockRefreshTokenRepo {
	m := &mockRefreshTokenRepo{tokens: make(map[string]*entity.RefreshToken)}
	for _, rt := range tokens {
		m.tokens[rt.TokenHash] = rt
	}
	return m
}

func (m *mockRefreshTokenRepo) Save(_ context.Context, rt *entity.RefreshToken) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.tokens[rt.TokenHash] = rt
	return nil
}

func (m *mockRefreshTokenRepo) FindByTokenHash(_ context.Context, tokenHash string) (*entity.RefreshToken, error) {
	if rt, ok := m.tokens[tokenHash]; ok {
		return rt, nil
	}
	return nil, coreerror.ErrNotFound
}

func (m *mockRefreshTokenRepo) RevokeByTokenHash(_ context.Context, tokenHash string) error {
	if rt, ok := m.tokens[tokenHash]; ok {
		rt.RevokedAt = new(time.Now())
	}
	return nil
}

func (m *mockRefreshTokenRepo) RevokeAllForUser(_ context.Context, userID entity.UserID) error {
	for _, rt := range m.tokens {
		if rt.UserID == userID {
			rt.RevokedAt = new(time.Now())
		}
	}
	return nil
}

// ── mock ClientRegistry ───────────────────────────────────────────────────────

type mockClientRegistry struct {
	clients map[entity.ClientID]*entity.Client
	findErr error
}

func newMockClientRegistry(t *testing.T, clientID, redirectURI string) *mockClientRegistry {
	t.Helper()
	client, err := entity.NewClient(entity.ClientArgs{
		ID:            clientID,
		AuthMethod:    entity.ClientAuthNone,
		RedirectURIs:  []string{redirectURI},
		AllowedGrants: []entity.GrantType{entity.GrantAuthorizationCode, entity.GrantRefreshToken},
	})
	if err != nil {
		t.Fatalf("newMockClientRegistry: %v", err)
	}
	return &mockClientRegistry{clients: map[entity.ClientID]*entity.Client{client.ID: client}}
}

func (m *mockClientRegistry) FindByID(_ context.Context, _ entity.TenantID, id entity.ClientID) (*entity.Client, error) {
	if m.findErr != nil {
		return nil, m.findErr
	}
	return m.clients[id], nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func newTestUser() *entity.User {
	u, err := entity.NewUser(entity.UserArgs{
		Username:      "testuser",
		Nickname:      "testnick",
		Password:      "Password1!",
		Email:         "test@example.com",
		EmailVerified: true,
	})
	if err != nil {
		panic(err)
	}
	u.ID = "user-1"
	return u
}
