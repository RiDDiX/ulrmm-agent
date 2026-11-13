package taskmaster

import "strings"

// accountName strips the DOMAIN\ part of a user name. Names without a
// domain part are returned unchanged.
func accountName(username string) string {
	return username[strings.LastIndex(username, `\`)+1:]
}
