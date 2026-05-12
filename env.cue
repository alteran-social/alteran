package cuenv

env: {
	environment: test: {
		REFRESH_TOKEN: "access-secret"
		PDS_DID: "did:example:test"
		PDS_HANDLE: "test"
		REFRESH_TOKEN_SECRET: "refresh-secret"
		PDS_OAUTH_CLIENT_HOSTS: "client.example"
		USER_PASSWORD: "pwd"
	}
}

tasks: {
	test: {
		command: "printenv"
	}
}
