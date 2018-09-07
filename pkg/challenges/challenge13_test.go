package challenges

import "testing"

func TestProfileFor(t *testing.T) {
	if ProfileFor("dahuie@gmail.com") != "email=dahuie@gmail.com&uid=10&role=user" {
		t.Error("wrong value")
	}
	if ProfileFor("dahuie@gmail.com=") != "email=dahuie@gmail.com&uid=10&role=user" {
		t.Error("wrong value")
	}
	if ProfileFor("dahuie@gmail.com&") != "email=dahuie@gmail.com&uid=10&role=user" {
		t.Error("wrong value")
	}

}

func TestGenerateAdminProfile(t *testing.T) {
	GenerateAdminProfile()
}
