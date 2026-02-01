package domain

// Filter defines search criteria for secrets
type Filter struct {
	// Hierarchical filters
	Project     string // Required for most operations
	Environment string // Optional, empty means all environments
	Scope       string // Optional, empty means all scopes
	Key         string // Optional, specific key name

	// Type filters
	OnlyShared bool // Only return shared (KMS) secrets
	OnlyLocal  bool // Only return local (master password) secrets

	// Sync filters
	OnlyUnsynced bool // Only return secrets not synced to cloud
}

// Matches returns true if the secret matches this filter
func (f *Filter) Matches(s *Secret) bool {
	// Project must always match if specified
	if f.Project != "" && s.Project != f.Project {
		return false
	}

	// Environment filter
	if f.Environment != "" && s.Environment != f.Environment {
		return false
	}

	// Scope filter
	if f.Scope != "" && s.Scope != f.Scope {
		return false
	}

	// Key filter
	if f.Key != "" && s.Key != f.Key {
		return false
	}

	// Type filters
	if f.OnlyShared && !s.IsShared {
		return false
	}
	if f.OnlyLocal && s.IsShared {
		return false
	}

	// Sync filter
	if f.OnlyUnsynced && s.CloudSynced && !s.UpdatedAt.After(s.LastSyncAt) {
		return false
	}

	return true
}

// IsEmpty returns true if no filters are specified
func (f *Filter) IsEmpty() bool {
	return f.Project == "" &&
		f.Environment == "" &&
		f.Scope == "" &&
		f.Key == "" &&
		!f.OnlyShared &&
		!f.OnlyLocal &&
		!f.OnlyUnsynced
}

// String returns a human-readable representation of the filter
func (f *Filter) String() string {
	if f.IsEmpty() {
		return "all secrets"
	}

	s := ""
	if f.Project != "" {
		s += "project:" + f.Project
	}
	if f.Environment != "" {
		if s != "" {
			s += ", "
		}
		s += "env:" + f.Environment
	}
	if f.Scope != "" {
		if s != "" {
			s += ", "
		}
		s += "scope:" + f.Scope
	}
	if f.Key != "" {
		if s != "" {
			s += ", "
		}
		s += "key:" + f.Key
	}
	if f.OnlyShared {
		if s != "" {
			s += ", "
		}
		s += "shared-only"
	}
	if f.OnlyLocal {
		if s != "" {
			s += ", "
		}
		s += "local-only"
	}
	if f.OnlyUnsynced {
		if s != "" {
			s += ", "
		}
		s += "unsynced-only"
	}

	return s
}
