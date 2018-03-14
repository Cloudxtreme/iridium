package cache

// FirstAvailable Balance based on nothing, returns the first host entry
// this is used to limit the output to 1 host
func FirstAvailable(s Records) Records {
	var matches Records
	if len(s) > 0 {
		matches = append(matches, s[0])
		return matches
	}
	// if no matches, return all nodes
	return s
}
