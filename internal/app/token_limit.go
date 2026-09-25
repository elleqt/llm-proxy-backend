package app

// MaxLiveTokensPerOwner is how many tokens that are not revoked one owner may hold.
// Revoking one makes room for another. The bound keeps what one account can make the
// gateway hold — token rows, and the state kept per token — proportional to the
// number of accounts rather than to how often someone calls the issue endpoint.
const MaxLiveTokensPerOwner = 50
