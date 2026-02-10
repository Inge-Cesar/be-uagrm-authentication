def get_client_ip(request):
    """Extract the client IP from request headers."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip_list = x_forwarded_for.split(",")
        # Return the real IP (considering the first IP if there are multiple IPs)
        return ip_list[0].strip()
    print(f"X-Forwarded-For header not found, using REMOTE_ADDR: {request.META.get('REMOTE_ADDR')}")
    return request.META.get("REMOTE_ADDR")