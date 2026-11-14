package cuenv

env: {
	environment: test: {
		PDS_DID:                "did:example:test"
		PDS_HANDLE:             "test"
		SESSION_JWT_SECRET:     "alteran-test-session-secret"
		PDS_OAUTH_CLIENT_HOSTS: "client.example"
		USER_PASSWORD:          "pwd"
	}
}

tasks: {
	test: {
		command: "printenv"
	}
}
