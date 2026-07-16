def configure_testing_app(application):
    """Configure Flask for test clients that post forms without CSRF tokens."""
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False  # NOSONAR - test client posts without CSRF tokens
    return application
