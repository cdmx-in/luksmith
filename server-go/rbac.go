package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Roles, in privilege order. Matches docs/rbac-contract.md.
const (
	roleOwner    = "owner"
	roleAdmin    = "admin"
	roleHelpdesk = "helpdesk"
	roleAuditor  = "auditor"
)

func validRole(r string) bool {
	switch r {
	case roleOwner, roleAdmin, roleHelpdesk, roleAuditor:
		return true
	}
	return false
}

func roleRank(r string) int {
	switch r {
	case roleOwner:
		return 4
	case roleAdmin:
		return 3
	case roleHelpdesk:
		return 2
	case roleAuditor:
		return 1
	}
	return 0
}

// Permission matrix. View (devices/audit) is any valid role.
func canRequest(r string) bool      { return r == roleOwner || r == roleAdmin || r == roleHelpdesk }
func canApprove(r string) bool      { return r == roleOwner || r == roleAdmin }
func canRotate(r string) bool       { return r == roleOwner || r == roleAdmin }
func canManageAdmins(r string) bool { return r == roleOwner }

// principal is the resolved identity of an admin-API caller.
type principal struct {
	username string
	role     string
	sso      bool
}

const pbkdf2Iters = 600000

// hashPassword returns pbkdf2_sha256$<iters>$<salt_hex>$<hash_hex>.
func hashPassword(pw string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	dk, _ := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iters, 32)
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s", pbkdf2Iters,
		hex.EncodeToString(salt), hex.EncodeToString(dk))
}

// verifyPassword recomputes the derived key and compares constant-time.
func verifyPassword(pw, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	iters, err := strconv.Atoi(parts[1])
	if err != nil || iters < 1 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, iters, len(want))
	if err != nil {
		return false
	}
	return hmac.Equal(dk, want)
}

// dummyHash lets login run a real pbkdf2 verify even for unknown/SSO-only
// users, so bad-credential timing does not leak whether a username exists.
var dummyHash = hashPassword("luksmith-timing-guard")

// parseGroupMap builds the SSO group→role map, seeded with the contract
// defaults, then overlaid with the operator's "group:role,..." string.
func parseGroupMap(raw string) map[string]string {
	m := map[string]string{
		"luksmith-owners":   roleOwner,
		"luksmith-admins":   roleAdmin,
		"luksmith-auditors": roleAuditor,
	}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) != 2 {
			continue
		}
		g, role := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		if g != "" && validRole(role) {
			m[g] = role
		}
	}
	return m
}

// mapGroups resolves a comma list of proxy-asserted groups to a role. Highest
// privilege among matching groups wins; any authenticated proxy user with no
// matching group defaults to helpdesk.
func mapGroups(groupMap map[string]string, groups string) string {
	matched := ""
	for _, g := range strings.Split(groups, ",") {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if role, ok := groupMap[g]; ok {
			if matched == "" || roleRank(role) > roleRank(matched) {
				matched = role
			}
		}
	}
	if matched == "" {
		return roleHelpdesk
	}
	return matched
}
