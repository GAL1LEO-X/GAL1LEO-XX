"""Public errors deliberately exclude provider response bodies and credentials."""


class TeslaError(Exception):
    def __init__(self, code, message, *, http_status=None, uncertain=False, details=None):
        self.code, self.message = code, message
        self.http_status, self.uncertain = http_status, uncertain
        self.details, self.diagnostic = details or {}, None
        super().__init__(message)

    def public(self):
        result = {"status": "error", "code": self.code, "message": self.message}
        if self.http_status is not None:
            result["provider_http_status"] = self.http_status
        if self.uncertain:
            result["outcome"] = "unknown"
        result.update(self.details)
        if self.diagnostic is not None:
            result["diagnostic"] = self.diagnostic
        return result
