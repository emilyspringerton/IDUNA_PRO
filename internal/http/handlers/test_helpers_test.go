package handlers_test

import "encoding/json"

// jsonInt formats an int64 as its JSON representation -- shared, small helper needed by
// kanban_test.go (originally lived in the excluded chat_messages_test.go in the source repo).
func jsonInt(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}
