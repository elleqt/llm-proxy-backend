package app

// CatalogProvider is one provider of the live catalogue and the models it serves.
type CatalogProvider struct {
	Name   string
	Models []string
	// Unpriced are models the policy admits but the account's spend limits
	// block for want of a price; disjoint from Models.
	Unpriced []string
}
