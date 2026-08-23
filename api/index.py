from app import create_app
import urllib.parse

class VercelPathMiddleware:
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        # 1. Try to get original URL from Vercel headers
        original_url = environ.get('HTTP_X_ORIGINAL_URL')
        if original_url:
            path = urllib.parse.urlparse(original_url).path
            environ['PATH_INFO'] = path
        else:
            # 2. Fallback: if PATH_INFO starts with /api/index.py or /api/index, strip it
            path_info = environ.get('PATH_INFO', '')
            for prefix in ('/api/index.py', '/api/index'):
                if path_info.startswith(prefix):
                    new_path = path_info[len(prefix):]
                    if not new_path.startswith('/'):
                        new_path = '/' + new_path
                    environ['PATH_INFO'] = new_path
                    break
        return self.wsgi_app(environ, start_response)

app = create_app()
app.wsgi_app = VercelPathMiddleware(app.wsgi_app)
