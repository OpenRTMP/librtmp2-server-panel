def configure_testing_app(application):
    """Configure Flask for test clients that post forms without CSRF tokens."""
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False  # NOSONAR - test client posts without CSRF tokens
    return application


def csrf_token_for_client(client):
    """Return a CSRF token for form posts when CSRF is enabled in tests."""
    with client.session_transaction() as sess:
        sess["csrf_token"] = "test-csrf-token"
    return "test-csrf-token"
