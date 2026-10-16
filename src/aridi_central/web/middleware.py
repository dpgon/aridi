"""Content-Security-Policy: the pages load nothing from elsewhere and run no script."""

POLICY = ("default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self'; "
          "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")


class ContentSecurityPolicyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.headers.setdefault("Content-Security-Policy", POLICY)
        return response
