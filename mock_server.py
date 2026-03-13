import http.server
import socketserver

# Порт, на котором будет запущен сервер
PORT = 8080


class MockHandler(http.server.BaseHTTPRequestHandler):
    def handle_request(self):
        # Словарь ответов: путь -> (Content-Type, Size в байтах)
        test_responses = {
            "/.git/config": ("text/plain", 150),
            "/.env": ("text/plain", 300),
            "/docker-compose.yml": ("text/yaml", 500),
            # SQL: Правильный дамп (110KB) и слишком маленький (10KB)
            "/backup.sql": ("application/sql", 110 * 1024),
            "/db.sql": ("application/sql", 10 * 1024),
            # Архивы: Правильный (600KB) и слишком маленький (100KB)
            "/backup.zip": ("application/zip", 600 * 1024),
            # Файл для проверки подстановки домена (localhost)
            "/localhost.sql": ("application/sql", 200),
        }

        try:
            path = self.path
            if path in test_responses:
                ctype, size = test_responses[path]
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(size))
                self.end_headers()

                # Если это GET, отправляем "тело" файла (просто мусор нужного размера)
                if self.command == "GET":
                    self.wfile.write(b"a" * size)
            else:
                # Для всех остальных путей отдаем 404
                self.send_response(404)
                self.end_headers()
        except (ConnectionError, BrokenPipeError):
            pass

    do_GET = handle_request
    do_HEAD = handle_request

    def log_message(self, format, *args):
        """Отключаем стандартные логи сервера в консоль для чистоты вывода"""
        pass


if __name__ == "__main__":
    # Запуск сервера
    with socketserver.TCPServer(("", PORT), MockHandler) as httpd:
        print(f"Python Mock Server started on port {PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")
