from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import asyncio
import httpx
from bs4 import BeautifulSoup
from datetime import datetime
import os

app = FastAPI(title="Hamer Hunter")

# Налаштування статичних файлів та шаблонів з урахуванням структури папок
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# Пайлоади для тестів
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]

async def check_security_headers(url: str):
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(url)
            headers = resp.headers
            
            # Виправлено: перевірка наявності ключів у регістронезалежному словнику заголовків httpx
            checks = {
                "Strict-Transport-Security": "strict-transport-security" in headers,
                "Content-Security-Policy": "content-security-policy" in headers,
                "X-Frame-Options": "x-frame-options" in headers,
                "X-Content-Type-Options": "x-content-type-options" in headers,
            }
            return {
                "status": "ok", 
                "headers": checks, 
                "missing": [k for k, v in checks.items() if not v]
            }
    except Exception:
        return {"status": "error", "missing": []}

async def check_single_file(client: httpx.AsyncClient, base_url: str, file: str):
    """Асинхронна перевірка одного файлу для оптимізації швидкості дії сканера"""
    try:
        resp = await client.get(f"{base_url}/{file}", timeout=4.0)
        if resp.status_code == 200 and len(resp.text) > 50:
            return {"file": file, "status": resp.status_code}
    except Exception:
        pass
    return None

async def check_sensitive_files(url: str):
    base = url.rstrip("/")
    sensitive = [".env", ".git/HEAD", "config.php", "backup.sql", "wp-config.php", "administrator"]
    
    async with httpx.AsyncClient(follow_redirects=True) as client:
        tasks = [check_single_file(client, base, file) for file in sensitive]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

async def basic_xss_test(url: str):
    results = []
    for payload in XSS_PAYLOADS:
        try:
            test_url = f"{url}?q={payload}" if "?" not in url else f"{url}&q={payload}"
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.get(test_url)
                if payload in resp.text:
                    results.append({"payload": payload, "reflected": True})
        except Exception:
            pass
    return results

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/scan")
async def scan(target_url: str = Form(...), scan_type: str = Form(...)):
    # Базова нормалізація URL
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    results = {
        "target": target_url,
        "scan_type": scan_type,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "running",
        "findings": [],
        "title": "No title",
        "status_code": None
    }
    
    # Перевірка доступності хоста
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(target_url)
            results["status_code"] = resp.status_code
            if resp.text:
                soup = BeautifulSoup(resp.text, 'html.parser')
                results["title"] = soup.title.string.strip() if soup.title else "No title"
    except Exception as e:
        return {"target": target_url, "error": f"Не вдалося отримати доступ до сайту: {str(e)}"}

    # Запуск паралельних асинхронних перевірок
    tasks = [
        check_security_headers(target_url),
        check_sensitive_files(target_url),
        basic_xss_test(target_url)
    ]
    header_check, sensitive, xss = await asyncio.gather(*tasks)
    
    # Обробка результатів Security Headers
    if header_check.get("missing"):
        results["findings"].append({
            "type": "Security Headers",
            "severity": "Medium",
            "description": f"Відсутні критичні заголовки безпеки: {', '.join(header_check['missing'])}"
        })
    
    # Обробка результатів Sensitive Files
    if sensitive:
        found_files = [f["file"] for f in sensitive]
        results["findings"].append({
            "type": "Sensitive Files",
            "severity": "High",
            "description": f"Знайдено потенційно доступні конфіденційні файли/директорії: {', '.join(found_files)}"
        })
    
    # Обробка результатів XSS
    if xss:
        results["findings"].append({
            "type": "XSS (Reflected)",
            "severity": "High",
            "description": f"Виявлено відображення коду в параметрі запиту. Сайт може бути вразливим до XSS (Перевірено {len(xss)} пайлоад(ів))."
        })

    # Логіка для Розширеного сканування (на перспективу розвитку)
    if scan_type == "full":
        results["findings"].append({
            "type": "Note",
            "severity": "Info",
            "description": "Розширений режим активовано. Додаткові модулі (SQLi, CSRF) перебувають у стані розробки."
        })

    results["status"] = "completed"
    return results
