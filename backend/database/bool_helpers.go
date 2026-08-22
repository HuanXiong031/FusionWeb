package database

func BoolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func IntBool(value int) bool {
	return value != 0
}
