package models

// Domain represents a discovered subdomain
type Domain struct {
	Name   string
	Source string // "certstream", "brute", "recursive"
}