package cache

// Preference based loadbalancing interface for statistics
type Preference struct{ Records }

// Less implements Preference based loadbalancing by sorting based on Preference counter
func (s Preference) Less(i, j int) bool {
	return s.Records[i].Preference < s.Records[j].Preference
}
