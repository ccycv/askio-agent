package migration

import (
	"os/user"
	"testing"
)

func TestBrokerSocketUsesTheAgentPrimaryGroupInsteadOfItsUserID(t *testing.T) {
	uid, gid, err := parseUserIDs(&user.User{Uid: "997", Gid: "988"})
	if err != nil {
		t.Fatal(err)
	}
	if uid != 997 || gid != 988 {
		t.Fatalf("user identity was collapsed: uid=%d gid=%d", uid, gid)
	}
	if uid == gid {
		t.Fatal("fixture must exercise distinct user and group IDs")
	}
	ownerID, groupID := (&Broker{allowedUID: uid, allowedGID: gid}).socketOwnership()
	if ownerID != 0 || groupID != 988 {
		t.Fatalf("unexpected broker socket ownership: owner=%d group=%d", ownerID, groupID)
	}
}

func TestBrokerUserIdentityRejectsAnInvalidPrimaryGroup(t *testing.T) {
	if _, _, err := parseUserIDs(&user.User{Uid: "997", Gid: "not-a-group"}); err == nil {
		t.Fatal("invalid primary group ID was accepted")
	}
}
