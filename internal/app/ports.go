// Package app declares the ports the application layer talks through: the
// repositories, sinks and collaborators every service depends on. Nothing here
// imports a database driver, an HTTP framework or an identity library — those
// live behind the interfaces, in internal/infra.
package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

var (
	ErrNotFound           = errors.New("app: not found")
	ErrForbidden          = errors.New("app: forbidden")
	ErrInvalidCredentials = errors.New("app: invalid credentials")
	ErrLockedOut          = errors.New("app: locked out")
	// ErrWeakPassword refuses a new password shorter than auth.MinPasswordLength.
	ErrWeakPassword = errors.New("app: password too short")
	// ErrConflict reports that a write lost a uniqueness race — the row it would
	// create already exists. Repositories map the driver's unique-violation onto it
	// so callers can tell "already there" from a transport failure without importing
	// a database package.
	ErrConflict = errors.New("app: conflict")
	// ErrTokenLimit refuses a new API token to an owner who already holds
	// MaxLiveTokensPerOwner live ones.
	ErrTokenLimit = errors.New("app: token limit reached")
)

//nolint:interfacebloat // One aggregate port per table: every users-table access goes through this interface.
type UserRepo interface {
	Create(ctx context.Context, u identity.User) error
	ByID(ctx context.Context, id uuid.UUID) (identity.User, error)
	ByEmail(ctx context.Context, email string) (identity.User, error)
	UpdatePolicy(ctx context.Context, id uuid.UUID, p access.Policy) error
	TouchLastSeen(ctx context.Context, id uuid.UUID, at time.Time) error
	// SaveIdentityState persists the fields an IdP login owns: policy, policy source
	// and email. It does NOT touch role, status or must_change_password —
	// those stay administrator-owned even for a federated user.
	SaveIdentityState(ctx context.Context, u identity.User) error
	// FillDisplayName sets id's display name to name only while it is empty, and
	// reports whether it did: a name already there, an administrator's included,
	// is never replaced. An unknown user is ErrNotFound.
	FillDisplayName(ctx context.Context, id uuid.UUID, name string) (bool, error)
	// SetMustChangePassword writes that one column and nothing else. It is deliberately
	// not folded into SaveIdentityState, which an IdP login calls and which must never
	// touch an administrator-owned field.
	SetMustChangePassword(ctx context.Context, id uuid.UUID, must bool) error
	// AdminExists reports whether any administrator exists, blocked ones included.
	// Bootstrap reads it to decide whether a first administrator is still owed.
	AdminExists(ctx context.Context) (bool, error)
	// List returns every account, oldest first, as View reports each.
	List(ctx context.Context) ([]UserView, error)
	// View is ByID plus the ways the account can sign in now and its pending
	// invitation, if any.
	View(ctx context.Context, id uuid.UUID) (UserView, error)
	// CreateAccount writes a new account, its first credential and the audit record
	// of its creation as one unit: all of them are stored or none is. An address
	// already taken is ErrConflict.
	CreateAccount(ctx context.Context, a NewAccount) error
	// UpdateAdminState writes the fields of ch that are set and nothing else, so two
	// edits of different fields cannot undo each other. Setting Policy also makes the
	// policy local. With RefuseIDPPolicy, a Policy change to an account whose stored
	// policy is idp-managed is ErrPolicyManagedByIDP and nothing is written — decided
	// by the same statement that writes. An unknown user is ErrNotFound.
	UpdateAdminState(ctx context.Context, id uuid.UUID, ch AdminChange) error
	// Unblock makes id active and records audit, in one transaction: the account is
	// unblocked with its record or not at all. An unknown user is ErrNotFound.
	Unblock(ctx context.Context, id uuid.UUID, audit AuditEvent) error
}

// NewAccount is what UserRepo.CreateAccount commits. At most one of Password and
// Invitation is set; a service account has neither.
type NewAccount struct {
	User       identity.User
	Password   *StoredPassword
	Invitation *Invitation
	Audit      AuditEvent
}

// StoredPassword is a password hash and, for a temporary password, its expiry.
type StoredPassword struct {
	Hash      string
	ExpiresAt *time.Time
}

// Invitation lets the first sign-in through Issuer with a verified Email claim an
// account until ExpiresAt. Issuer is stored exactly as given.
type Invitation struct {
	Issuer    string
	Email     string
	ExpiresAt time.Time
}

// AdminChange is an administrator's edit of the fields they own. A nil field is
// left as stored.
type AdminChange struct {
	DisplayName     *string
	Role            *identity.Role
	Status          *identity.Status
	Policy          *access.Policy
	RefuseIDPPolicy bool
}

// SignInMethod is one way an account can sign in to the web interface.
type SignInMethod string

const (
	// SignInPassword: the account has a usable password — permanent, or temporary
	// and unexpired. A lapsed temporary password is no way in.
	SignInPassword SignInMethod = "password"
	// SignInOIDC: the account is linked to an identity provider subject. A pending
	// invitation is not a way in until it is claimed; see UserView.InvitationExpiresAt.
	SignInOIDC SignInMethod = "oidc"
)

// UserView is an account as the administration screens see it.
type UserView struct {
	User identity.User
	// SignIn lists the ways in that work now, in the order password, oidc. Empty for
	// a service account and for a person whose only way in is an invitation.
	SignIn []SignInMethod
	// InvitationExpiresAt is set while an invitation exists and no identity is
	// linked. It may lie in the past: the invitation lapsed and wants renewing.
	InvitationExpiresAt *time.Time
}

type TokenRepo interface {
	// Create stores a new token. An owner who already holds MaxLiveTokensPerOwner
	// tokens that are not revoked gets ErrTokenLimit and nothing is written. The
	// count and the write are one step: concurrent creates for one owner cannot
	// pass the limit together.
	Create(ctx context.Context, t credentials.Token) error
	ByID(ctx context.Context, id uuid.UUID) (credentials.Token, error)
	ByHash(ctx context.Context, hash string) (credentials.Token, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]credentials.Token, error)
	Save(ctx context.Context, t credentials.Token) error
	TouchLastUsed(ctx context.Context, id uuid.UUID, at time.Time) error
}

// PasswordRepo stores the one password a user may have.
//
// Set carries an optional expiry: a temporary password an administrator issued has
// one, a password its owner chose does not. Passing nil clears whatever the previous
// row carried, so "change my password" is the same call as "issue a temporary one"
// with the expiry left out.
type PasswordRepo interface {
	Set(ctx context.Context, userID uuid.UUID, hash string, expiresAt *time.Time) error
	Get(ctx context.Context, userID uuid.UUID) (hash string, expiresAt *time.Time, err error)
}

// Session is one browser login.
//
// ID is the plaintext session id. It is set on the value SignIn returns, which exists
// so the transport can put it in a cookie, and it is empty on every session that came
// out of the store or went into it: only IDHash is persisted, and the plaintext is
// never logged, never returned in a body and never written to a row.
//
// Restricted is DERIVED, never stored. It is users.must_change_password, read at the
// moment the session is resolved. Storing it would make one fact two, and the copy on
// an already-open session would be wrong from the instant an administrator issued a
// temporary password — the restriction would apply to the next login instead of to
// the person holding the cookie now.
type Session struct {
	ID         string
	IDHash     string
	UserID     uuid.UUID
	Restricted bool
	IP         string
	UserAgent  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// SessionMeta is what the transport knows about a sign-in and the service does not.
// It is recorded on the session and on the audit trail so an operator can tell two
// concurrent logins apart.
type SessionMeta struct {
	IP        string
	UserAgent string
}

// SessionRepo stores browser sessions. The key is the SHA-256 of the session id, never
// the id itself: a stolen database dump must not yield usable cookies.
//
// A row holds identity and a window and nothing else. There is no restriction column
// and no method to clear one, because the restriction is not stored: it is read from
// the user at every request. Nothing here can therefore drift out of step with it.
//
// ByHash must not return a session whose expiry has passed, and the expiry must be
// applied by the store itself rather than by the caller — a session that outlived its
// window is gone, not merely stale, and it must not be resurrectable by a process
// whose clock runs slow.
type SessionRepo interface {
	Create(ctx context.Context, s Session) error
	ByHash(ctx context.Context, idHash string) (Session, error)
	Delete(ctx context.Context, idHash string) error
	// DeleteByUser ends every session of userID. No session is success.
	DeleteByUser(ctx context.Context, userID uuid.UUID) error
	// DeleteByUserExcept ends every session of userID but the one whose hash is
	// keepHash. No other session is success.
	DeleteByUserExcept(ctx context.Context, userID uuid.UUID, keepHash string) error
}

// UsageEvent is one row of the consumption ledger.
type UsageEvent struct {
	At               time.Time
	UserID           uuid.UUID
	TokenID          uuid.UUID
	Provider         string
	Model            string
	Alias            string
	Stream           bool
	ServiceTier      string
	TokensInput      int64
	TokensOutput     int64
	TokensReasoning  int64
	TokensCacheRead  int64
	TokensCacheWrite int64
	TokensTotal      int64
	BreakdownQuality string
	LatencyMS        int
	TTFTMS           int
	StatusCode       int
	Failed           bool
	VendorAccountID  string
	// Cost is what the tokens cost at the prices in force when the request was
	// recorded (PriceUsage). It is stored with the row and never recomputed.
	Cost UsageCost
}

// UsagePoint is one bucket of the cabinet's chart for one model, starting at At.
// Requests counts served requests: a failed upstream attempt (one a retry on
// another account followed) is not one. TokensTotal sums every attempt, because
// tokens a failed attempt consumed were spent.
type UsagePoint struct {
	At          time.Time
	Model       string
	TokensTotal int64
	Requests    int64
	// CostUSD is the priced part of the bucket's cost (UsageCost.TotalUSD).
	CostUSD float64
}

// UsageBucket is the width of the cabinet chart's buckets.
type UsageBucket string

const (
	UsageBucketHour UsageBucket = "hour"
	UsageBucketDay  UsageBucket = "day"
)

// UsageBucketFor chooses the bucket for a range: hours up to 48 hours, days beyond.
// Buckets start on UTC hour and day boundaries.
func UsageBucketFor(from, to time.Time) UsageBucket {
	if to.Sub(from) <= 48*time.Hour {
		return UsageBucketHour
	}

	return UsageBucketDay
}

// UsageTotals sums a series over its whole range, counted as UsagePoint counts.
type UsageTotals struct {
	Requests    int64
	TokensTotal int64
	Cost        UsageCost
}

// UsageSeries is one user's consumption over [from, to): what GET /api/me/usage
// answers with. Points are ordered by bucket, then model, and sparse: a bucket
// and model with neither a served request nor a token has no point.
type UsageSeries struct {
	Bucket UsageBucket
	Totals UsageTotals
	Points []UsagePoint
}

// UsageRepo is the consumption ledger.
//
// AppendBatch writes every event or none. A UserID or TokenID that names no row
// (the zero UUID, or an owner or token deleted since the request) is written as
// NULL rather than failing the batch.
type UsageRepo interface {
	AppendBatch(ctx context.Context, events []UsageEvent) error
	SeriesForUser(ctx context.Context, userID uuid.UUID, from, to time.Time) (UsageSeries, error)
}

// QuotaSignal is a vendor's latest own report of how much of one quota window an
// account has used, read from its response headers.
type QuotaSignal struct {
	// Account is the upstream account id (usage.Record.AuthID).
	Account string
	// Provider is the policy-facing provider name ("chatgpt", not "codex").
	Provider string
	// Window is the quota window, such as "5h" or "7d".
	Window string
	// UsedRatio is the share of the window used, 0..1; an overrun reads 1.
	UsedRatio float64
	// ResetAt is when the vendor says the window resets; zero if it never said.
	ResetAt time.Time
	// ObservedAt is when the response carrying the report arrived.
	ObservedAt time.Time
}

// QuotaReader serves each account's latest quota snapshot: the windows its most
// recent response carrying any quota signal reported.
type QuotaReader interface {
	QuotaSignals() []QuotaSignal
}

// Vendor login outcomes the provider wizard reports, with the contract's
// status and code each maps to on the web API.
var (
	// ErrUnsupportedProvider: no login flow exists for that provider name.
	// 422 unsupported_provider.
	ErrUnsupportedProvider = errors.New("app: unsupported provider")
	// ErrLoginExpired: the login session is unknown, timed out or already
	// used. 410 login_expired.
	ErrLoginExpired = errors.New("app: login expired")
	// ErrLoginFailed: the vendor, or the pasted callback, refused the sign-in.
	// 422 login_failed.
	ErrLoginFailed = errors.New("app: login failed")
	// ErrLoginsBusy: as many logins as the gateway allows are in progress.
	// 409 login_busy.
	ErrLoginsBusy = errors.New("app: too many pending logins")
)

// VendorAccount is one vendor account the gateway holds. Provider is the
// policy-facing name ("chatgpt", not "codex"). Nothing here is a credential.
type VendorAccount struct {
	ID       string
	Provider string
	Label    string
	Email    string
	// Status is the gateway's lifecycle status: active, error, disabled, ...
	Status          string
	Disabled        bool
	LastError       string
	LastRefreshedAt time.Time // zero when never refreshed
	// Quota is filled by providers.Service from the QuotaReader.
	Quota []QuotaSignal
}

// VendorAccounts is the gateway's account surface. Account changes go through
// it and nothing else: an id it does not hold is ErrNotFound.
type VendorAccounts interface {
	Accounts() []VendorAccount
	SetAccountDisabled(ctx context.Context, id string, disabled bool) error
	RemoveAccount(ctx context.Context, id string) error
}

// VendorLogin is a pending vendor sign-in: the administrator opens AuthURL in
// their own browser and completes it before ExpiresAt.
type VendorLogin struct {
	SessionID string
	AuthURL   string
	ExpiresAt time.Time
}

// VendorLogins runs vendor sign-ins. StartLogin takes a policy-facing provider
// name (ErrUnsupportedProvider, ErrLoginsBusy); CompleteLogin takes the URL the
// vendor sign-in ended on, adds the account and returns it (ErrLoginExpired,
// ErrLoginFailed). Neither error carries the callback URL or anything in it.
type VendorLogins interface {
	StartLogin(ctx context.Context, provider string) (VendorLogin, error)
	CompleteLogin(ctx context.Context, sessionID, callbackURL string) (VendorAccount, error)
}

// VendorQuota is the usage sink's quota store: it serves the snapshots and
// forgets a removed account's.
type VendorQuota interface {
	QuotaReader
	ForgetAccount(account string)
}

// AccountMetrics is the per-account part of the metrics. provider is the
// policy-facing name.
type AccountMetrics interface {
	SetAccountDisabled(account, provider string, disabled bool)
	ForgetAccount(account, provider string)
}

// AuditEvent records a security-relevant action. Unlike usage, it is never pruned.
type AuditEvent struct {
	At        time.Time
	ActorID   uuid.UUID
	Action    string
	Target    string
	Detail    map[string]any
	IP        string
	UserAgent string
}

type AuditSink interface {
	Record(ctx context.Context, e AuditEvent) error
}

// Claims are the assertions an identity provider makes about a person.
//
// EmailVerified is the provider's statement that the person proved control of Email.
// Without it Email is an assertion anyone can type into their IdP profile, so nothing
// that grants access by address may act on an unverified one.
type Claims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Groups        []string
	// Name is what to call the person: the provider's display name, cleaned by the
	// provider adapter. It may be empty. It is only ever a label, never an identity.
	Name string
}

// Challenge is the per-login secret material that binds a callback to the browser
// that started the login. The transport keeps it in a short-lived HttpOnly cookie
// between start and callback; nothing else stores it, and it is never logged.
type Challenge struct {
	State    string // compared with the callback's state, constant time
	Nonce    string // must equal the ID token's nonce claim
	Verifier string // PKCE code_verifier; AuthURL sends S256(Verifier)
}

// IdentityProvider is an OpenID Connect relying party.
//
// Exchange must verify the ID token's signature, issuer, audience and expiry, and
// that its nonce equals ch.Nonce, and it must send ch.Verifier as the PKCE
// code_verifier. A token that fails any of those is reported as wrapping
// ErrInvalidCredentials; an IdP that cannot be reached is any other error.
type IdentityProvider interface {
	AuthURL(ch Challenge) string
	Exchange(ctx context.Context, code string, ch Challenge) (Claims, error)
}

// Clock exists so tests control time without sleeping.
type Clock interface{ Now() time.Time }

// IdentityRepo links people to the subjects an identity provider asserts.
type IdentityRepo interface {
	BySubject(ctx context.Context, issuer, subject string) (uuid.UUID, error)
	Link(ctx context.Context, userID uuid.UUID, issuer, subject string) error
	PendingByEmail(ctx context.Context, issuer, email string) (uuid.UUID, error)
	ConsumePending(ctx context.Context, userID uuid.UUID) error
	// Invite records that the first sign-in through inv.Issuer with a verified email
	// equal to inv.Email (case-insensitively) claims userID, until inv.ExpiresAt. It
	// replaces any invitation already held for that address at that issuer, expired
	// or not, and any invitation userID already holds. An account that already has
	// an identity link is ErrAlreadyLinked and nothing is written.
	Invite(ctx context.Context, userID uuid.UUID, inv Invitation) error
}

// ActivityRepo reads the recent history of one account for the administration
// screens. Both reads return newest first and at most limit rows.
type ActivityRepo interface {
	// RecentUsage returns the proxied requests userID made.
	RecentUsage(ctx context.Context, userID uuid.UUID, limit int) ([]UsageEvent, error)
	// RecentAudit returns the audit events userID performed or that concern userID:
	// its own actions, actions whose target is the account, and actions on its tokens.
	RecentAudit(ctx context.Context, userID uuid.UUID, limit int) ([]AuditEvent, error)
}

// ModelCatalog is the gateway's live model catalogue, the one the policy gate
// routes by. Provider names are the ones written in policy rules.
type ModelCatalog interface {
	// ProvidersFor returns every provider serving model now; nil if none does.
	ProvidersFor(model string) []string
	// Models maps each provider to the models it serves now.
	Models() map[string][]string
}

// LoginAttemptRepo backs sign-in throttling. Implementations key it by the lower-cased
// address, the same folding UserRepo.ByEmail applies, so one mailbox has one counter.
type LoginAttemptRepo interface {
	// Failures reads the attempts on record and the lockout expiry, if any. An
	// address with no record is (0, nil, nil).
	Failures(ctx context.Context, email string) (count int, lockedUntil *time.Time, err error)
	// Charge counts one attempt, atomically, and returns the record as it stands
	// after this attempt. Concurrent charges against one address see distinct counts.
	// The lock window's length is lockUntil - now.
	//
	//   - A lockout in force at now is kept as it is: the count grows, the window
	//     does not move.
	//   - A lockout that has lapsed by now, or a count whose last attempt is at least
	//     one window old, is stale: the count starts over at 1 with no lock. The limit
	//     is maxFailures per window, not per lifetime.
	//   - Otherwise the count grows by one, and reaching maxFailures sets lockUntil.
	//
	// So an attempt is admitted exactly when the returned count is at most
	// maxFailures.
	Charge(ctx context.Context, email string, maxFailures int, now, lockUntil time.Time) (count int, lockedUntil *time.Time, err error)
	// Clear forgets every attempt of the address, an open lock included. A successful
	// sign-in (auth.Throttle.Reset) and the operator's recovery (recovery.Service.ResetPassword)
	// call it, and nothing else.
	Clear(ctx context.Context, email string) error
}

// Logger keeps the services from depending on a log handler or its output format.
// It takes slog.Attr values only (slog.String, slog.Int, slog.Any("err", err)):
// every attribute's key travels with its value, so a loose key/value pair is a
// compile error rather than a !BADKEY in the log.
type Logger interface {
	Warn(msg string, attrs ...slog.Attr)
}

// InfoLogger is a Logger that also reports routine outcomes, for a service whose
// successes are worth a line too.
type InfoLogger interface {
	Logger
	Info(msg string, attrs ...slog.Attr)
}

// SettingsRepo stores the editable upstream configuration document, verbatim as the
// administrator wrote it. Postgres is its source of truth: the gateway's boot
// configuration is built from it (settings.LoadBootConfig).
type SettingsRepo interface {
	// UpstreamDocument returns the stored YAML document, or ErrNotFound when none
	// was ever saved.
	UpstreamDocument(ctx context.Context) (string, error)
	SetUpstreamDocument(ctx context.Context, doc string, by uuid.UUID, at time.Time) error
}

// ConfigPusher is the embedded gateway's configuration surface. PushConfig takes
// ownership of cfg: the caller must not touch it afterwards.
type ConfigPusher interface {
	CurrentConfig() *sdkconfig.Config
	PushConfig(cfg *sdkconfig.Config) error
}

// ModelPrice is what one model costs, in US dollars per million tokens: an estimate
// of work done, not a bill. Provider and Model are the values usage events carry.
type ModelPrice struct {
	Provider   string
	Model      string
	Input      float64
	Output     float64
	CacheRead  float64
	CacheWrite float64
	UpdatedAt  time.Time
}

// PriceRepo stores the manual price list: the administrator's overrides.
type PriceRepo interface {
	// List returns every price ordered by provider, then model.
	List(ctx context.Context) ([]ModelPrice, error)
	// Replace makes prices the whole list, atomically. A row whose rates did not
	// change keeps its UpdatedAt; a new or changed row gets at.
	Replace(ctx context.Context, prices []ModelPrice, at time.Time) error
}

// PriceSink receives the whole price list whenever it changes, so the metrics cost
// estimate reads prices from memory rather than the database on every request.
type PriceSink interface {
	SetPrices(prices []ModelPrice)
}

// PriceLookup finds the price in force for a provider's model; ok is false when
// it has none. It is read for every recorded request, so it answers from memory;
// PriceTable is one.
type PriceLookup interface {
	Price(provider, model string) (ModelPrice, bool)
}

// ErrCatalogDisabled refuses a price catalog check when no catalog source is
// configured.
var ErrCatalogDisabled = errors.New("app: price catalog disabled")

// CatalogValidators are the HTTP cache validators of the last catalog a check
// accepted, sent back so an unchanged catalog costs a 304 rather than a download.
type CatalogValidators struct {
	ETag         string
	LastModified string
}

// CatalogFetch is one answer of the price catalog.
type CatalogFetch struct {
	// Unchanged is true when the catalog has not changed since the validators
	// Fetch was given; Prices and Validators are then empty.
	Unchanged bool
	// Prices are the catalog's prices under our provider names, UpdatedAt unset.
	Prices     []ModelPrice
	Validators CatalogValidators
}

// CatalogFetchTimeout bounds one PriceCatalogSource.Fetch, headers and body. The
// catalog's file host can be slow, and nothing but the check waits on it.
const CatalogFetchTimeout = 2 * time.Minute

// PriceCatalogSource fetches the upstream price catalog. An error means the
// catalog could not be read or understood; its text is short, safe to show an
// administrator and never carries the response body. Fetch returns within
// CatalogFetchTimeout.
type PriceCatalogSource interface {
	Fetch(ctx context.Context, since CatalogValidators) (CatalogFetch, error)
	// Fingerprint names what turns a catalog into prices: the URL and the
	// parser's version. Validators stored under another fingerprint describe a
	// document this source would read differently, so they are not sent.
	Fingerprint() string
}

// CatalogState is what the store keeps about the catalog's checks. A zero time
// means never.
type CatalogState struct {
	Validators CatalogValidators
	// Fingerprint is the source's Fingerprint when Validators were stored.
	Fingerprint string
	// CheckedAt is the last successful check, whether or not the catalog changed.
	CheckedAt time.Time
	// ChangedAt is when the catalog prices in force last changed.
	ChangedAt time.Time
	// LastError is why the last check failed; empty once a check succeeds.
	LastError string
}

// PriceCatalogRepo stores the catalog's prices and the state of its checks.
type PriceCatalogRepo interface {
	// List returns every catalog price ordered by provider, then model.
	List(ctx context.Context) ([]ModelPrice, error)
	// State returns the check state; the zero value before the first check.
	State(ctx context.Context) (CatalogState, error)
	// Replace makes prices the whole catalog price list and state the check
	// state, atomically. A row whose rates did not change keeps its UpdatedAt; a
	// new or changed row gets at.
	Replace(ctx context.Context, prices []ModelPrice, state CatalogState, at time.Time) error
	// SetState records the check state alone.
	SetState(ctx context.Context, state CatalogState) error
}

// PriceCatalogMetrics is the price catalog's part of the metrics.
type PriceCatalogMetrics interface {
	// SetPriceCatalog reports the catalog prices in force and the last
	// successful check (zero: never).
	SetPriceCatalog(models int, checkedAt time.Time)
	// ObservePriceCatalogFailure counts a failed check.
	ObservePriceCatalogFailure()
}
