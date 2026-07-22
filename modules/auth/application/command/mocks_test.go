package command

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	coreerror "sc/core/error"
	corejwt "sc/core/jwt"
	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"
)

// ── mock JWTSvc ───────────────────────────────────────────────────────────

type mockJwtService struct {
	mu                 sync.Mutex
	accessToken        string
	refreshToken       string
	accessErr          error
	refreshErr         error
	idTokenErr         error
	parseClaims        *corejwt.Claims
	parseErr           error
	parseIDTokenClaims *corejwt.IDTokenClaims
	parseIDTokenErr    error
	// captured call arguments — guarded by mu
	capturedAccessUserID     string
	capturedAccessScope      string
	capturedAccessExpireSecs int
	capturedIDTokenClientID  string
	capturedIDTokenNonce     string
}

func (m *mockJwtService) GenAccessToken(userID, scope string, expireSecs int) (string, error) {
	m.mu.Lock()
	m.capturedAccessUserID = userID
	m.capturedAccessScope = scope
	m.capturedAccessExpireSecs = expireSecs
	m.mu.Unlock()
	return m.accessToken, m.accessErr
}

func (m *mockJwtService) GenRefreshToken(_ string) (string, error) {
	return m.refreshToken, m.refreshErr
}

func (m *mockJwtService) GenIDToken(args port.IDTokenArgs) (string, error) {
	m.mu.Lock()
	m.capturedIDTokenClientID = args.ClientID
	m.capturedIDTokenNonce = args.Nonce
	m.mu.Unlock()
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

func (m *mockJwtService) GetIssuer() string { return "" }

// ── mock UserRepository ───────────────────────────────────────────────────────

type mockUserRepo struct {
	mu                   sync.Mutex
	users                map[string]*entity.User // keyed by ID
	saveErr              error
	findByEmailErr       error
	findByIDErr          error
	updateByTokenHashErr error
}

func newMockRepo(users ...*entity.User) *mockUserRepo {
	m := &mockUserRepo{users: make(map[string]*entity.User)}
	for _, u := range users {
		m.users[string(u.ID)] = u
	}
	return m
}

func (m *mockUserRepo) CreateUser(_ context.Context, user *entity.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.Email == user.Email {
			return coreerror.ErrConflict
		}
	}
	if m.saveErr != nil {
		return m.saveErr
	}
	m.users[string(user.ID)] = user
	return nil
}

func (m *mockUserRepo) FindByEmail(_ context.Context, tenantID entity.TenantID, email string) (*entity.User, error) {
	if m.findByEmailErr != nil {
		return nil, m.findByEmailErr
	}
	for _, u := range m.users {
		if u.Email == email && u.TenantID == tenantID {
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

func (m *mockUserRepo) UpdateByPasswordResetTokenHash(_ context.Context, tokenHash string, update func(*entity.User) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateByTokenHashErr != nil {
		return m.updateByTokenHashErr
	}
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

func (m *mockUserRepo) Save(_ context.Context, user *entity.User) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.users[string(user.ID)] = user
	return nil
}

// ── mock Cache ────────────────────────────────────────────────────────────────

type mockCache struct {
	items   map[string]any
	counts  map[string]int64
	setErr  error
	incrErr error
}

func newMockCache() *mockCache {
	return &mockCache{items: make(map[string]any), counts: make(map[string]int64)}
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
	return m.Get(context.TODO(), key, dest), nil
}
func (m *mockCache) Delete(_ context.Context, key string) { delete(m.items, key) }
func (m *mockCache) IncrWindow(_ context.Context, key string, _ time.Duration) (int64, error) {
	if m.incrErr != nil {
		return 0, m.incrErr
	}
	m.counts[key]++
	return m.counts[key], nil
}

// ── mock EmailSender ──────────────────────────────────────────────────────────

type mockEmailSender struct {
	sentTo         string
	sentToken      string
	attemptedTo    string
	attemptedToken string
	sendErr        error
}

func (m *mockEmailSender) SendPasswordResetEmail(_ context.Context, toEmail, rawToken string) error {
	m.attemptedTo = toEmail
	m.attemptedToken = rawToken
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sentTo = toEmail
	m.sentToken = rawToken
	return nil
}

// ── mock RefreshTokenRepository ───────────────────────────────────────────────

type mockRefreshTokenRepo struct {
	mu                 sync.Mutex
	tokens             map[string]*entity.RefreshToken
	saveErr            error
	revokeAllErr       error
	revokeByHashErr    error
	findByTokenHashErr error
}

func newMockRefreshTokenRepo(tokens ...*entity.RefreshToken) *mockRefreshTokenRepo {
	m := &mockRefreshTokenRepo{tokens: make(map[string]*entity.RefreshToken)}
	for _, rt := range tokens {
		m.tokens[rt.TokenHash] = rt
	}
	return m
}

func (m *mockRefreshTokenRepo) Save(_ context.Context, rt *entity.RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.tokens[rt.TokenHash] = rt
	return nil
}

func (m *mockRefreshTokenRepo) FindByTokenHash(_ context.Context, tokenHash string) (*entity.RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.findByTokenHashErr != nil {
		return nil, m.findByTokenHashErr
	}
	if rt, ok := m.tokens[tokenHash]; ok {
		cp := *rt
		return &cp, nil
	}
	return nil, coreerror.ErrNotFound
}

// RevokeByTokenHash mirrors real repository semantics: only revokes active, non-expired tokens.
func (m *mockRefreshTokenRepo) RevokeByTokenHash(_ context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revokeByHashErr != nil {
		return m.revokeByHashErr
	}
	rt, ok := m.tokens[tokenHash]
	if !ok || rt.RevokedAt != nil || rt.ExpiresAt.Before(time.Now()) {
		return coreerror.ErrNotFound
	}
	rt.RevokedAt = new(time.Now())
	return nil
}

func (m *mockRefreshTokenRepo) RevokeAllForUser(_ context.Context, userID entity.UserID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revokeAllErr != nil {
		return m.revokeAllErr
	}
	for _, rt := range m.tokens {
		if rt.UserID == userID {
			rt.RevokedAt = new(time.Now())
		}
	}
	return nil
}

func (m *mockRefreshTokenRepo) findAllForUser(userID string) ([]*entity.RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	uid := entity.UserID(userID)
	var result []*entity.RefreshToken
	for _, rt := range m.tokens {
		if rt.UserID == uid {
			result = append(result, rt)
		}
	}
	return result, nil
}

// ── mock ClientRegistry ───────────────────────────────────────────────────────

const testClientSecret = "test-secret-1"

type mockClientRegistry struct {
	clients map[entity.ClientID]*entity.Client
}

func newMockClientRegistry(clients ...*entity.Client) *mockClientRegistry {
	m := &mockClientRegistry{clients: make(map[entity.ClientID]*entity.Client)}
	for _, c := range clients {
		m.clients[c.ID] = c
	}
	return m
}

func (m *mockClientRegistry) FindByID(_ context.Context, _ entity.TenantID, id entity.ClientID) (*entity.Client, error) {
	return m.clients[id], nil
}

func newTestClient(t *testing.T, id string, method entity.ClientAuthMethod, grants ...entity.GrantType) *entity.Client {
	t.Helper()
	secret := ""
	if method != entity.ClientAuthNone {
		secret = testClientSecret
	}
	if len(grants) == 0 {
		grants = []entity.GrantType{entity.GrantAuthorizationCode, entity.GrantRefreshToken}
	}
	c, err := entity.NewClient(entity.ClientArgs{
		ID:            id,
		AuthMethod:    method,
		Secret:        secret,
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: grants,
	})
	if err != nil {
		t.Fatalf("newTestClient: %v", err)
	}
	return c
}

// ── mock UnitOfWork ───────────────────────────────────────────────────────────

type mockUoW struct{}

func (m *mockUoW) Do(ctx context.Context, fn func(context.Context) (any, error)) (any, error) {
	return fn(ctx)
}

// transactionalMockUoW snapshots the given repo's token map before running fn
// and restores it on error, simulating the rollback a real DB transaction provides.
type transactionalMockUoW struct {
	rtRepo *mockRefreshTokenRepo
}

func (m *transactionalMockUoW) Do(ctx context.Context, fn func(context.Context) (any, error)) (any, error) {
	m.rtRepo.mu.Lock()
	snapshot := make(map[string]*entity.RefreshToken, len(m.rtRepo.tokens))
	for k, v := range m.rtRepo.tokens {
		cp := *v
		snapshot[k] = &cp
	}
	m.rtRepo.mu.Unlock()

	result, err := fn(ctx)
	if err != nil {
		m.rtRepo.mu.Lock()
		m.rtRepo.tokens = snapshot
		m.rtRepo.mu.Unlock()
	}
	return result, err
}

// failingUoW returns a bare error without invoking the callback, simulating a
// session/transaction start failure (e.g. no replica set, network error).
type failingUoW struct{ err error }

func (m *failingUoW) Do(_ context.Context, _ func(context.Context) (any, error)) (any, error) {
	return nil, m.err
}

// ── helpers ───────────────────────────────────────────────────────────────────

func newTestUser() *entity.User {
	now := time.Now()
	return &entity.User{
		ID:            entity.UserID("user-1"),
		TenantID:      entity.DefaultTenantID,
		Username:      "testuser",
		Nickname:      "testnick",
		Password:      "hashed-password",
		Email:         "test@example.com",
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

var (
	testPasswordHashOnce sync.Once
	testPasswordHash     string
)

func newTestUserWithValidPassword() *entity.User {
	testPasswordHashOnce.Do(func() {
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
		testPasswordHash = u.Password
	})
	u := newTestUser()
	u.Password = testPasswordHash
	return u
}
