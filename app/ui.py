from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["ui"])

PAGE = """
<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>Проверка фишинговой ссылки</title>
<style>
  body{font-family:system-ui;max-width:720px;margin:40px auto;padding:0 16px}
  .form-group{margin-bottom:15px}
  label{display:block;font-weight:bold;margin-bottom:5px}
  input{width:100%;padding:10px;font-size:16px;box-sizing:border-box}
  button{margin-top:12px;padding:10px 20px;font-size:16px;cursor:pointer;background:#007bff;color:white;border:none;border-radius:4px}
  button:hover{background:#0056b3}
  pre{background:#f5f5f5;padding:16px;border-radius:8px;overflow-x:auto; font-size:14px;}
  .err{color:#b00020;font-weight:bold}
  .hint{font-size:12px;color:#666;margin-top:5px}
  .token-box{background:#eef;padding:10px;border-left:4px solid #007bff;margin-bottom:20px}
  .monitor-box{background:#e8f5e9;padding:10px;border-left:4px solid #2e7d32;margin-bottom:20px; margin-top: 30px;}
  .domain-box{background:#fff3e0;padding:10px;border-left:4px solid #f57c00;margin-bottom:20px; margin-top: 30px;}
</style></head><body>
<h2>Проверка фишинговой ссылки</h2>

<div class="token-box">
  <strong>Авторизация</strong>
  <div class="hint">Введите сюда JWT-токен.</div>
  <div class="form-group" style="margin-top:10px;">
    <input id="token" placeholder="Вставьте сюда ваш JWT-токен (eyJhbGci...)" style="font-family:monospace; font-size:12px;">
  </div>
</div>

<div class="form-group">
  <label for="url">Ссылка для проверки:</label>
  <input id="url" placeholder="https://sberbank-login.ru" value="https://sberbank-login.ru">
</div>

<button onclick="check()">Проверить ссылку</button>
<div id="status"></div><pre id="out"></pre>

<!-- БЛОК ПРОВЕРКИ ДОМЕНА -->
<div class="domain-box">
  <strong>Проверка домена (Сервис domain-intel)</strong>
  <div class="hint">Узнать возраст домена и риск.</div>
  <div class="form-group" style="margin-top:10px;">
    <input id="dom-name" placeholder="Домен (например, sberbank-login.ru)" value="sberbank-login.ru">
  </div>
  <button onclick="checkDomain()" style="background:#f57c00;">Узнать данные о домене</button>
  <div id="dom-status"></div><pre id="dom-out"></pre>
</div>

<!-- БЛОК МОНИТОРИНГА -->
<div class="monitor-box">
  <strong>Мониторинг домена</strong>
  <div class="hint">Создать правило фонового отслеживания домена.</div>
  <div class="form-group" style="margin-top:10px;">
    <input id="mon-domain" placeholder="Домен (например, sberbank.ru)" value="sberbank.ru">
  </div>
  <div class="form-group">
    <input id="mon-period" type="number" placeholder="Период проверки (часы)" value="24">
  </div>
  <button onclick="createRule()" style="background:#2e7d32;">Создать правило мониторинга</button>
  <div id="mon-status"></div><pre id="mon-out"></pre>
</div>

<script>
async function check(){
 const url=document.getElementById('url').value.trim();
 const token=document.getElementById('token').value.trim();
 const out=document.getElementById('out'),status=document.getElementById('status');
 
 if(!token){ status.innerHTML='<span class="err">Ошибка: введите токен!</span>'; return; }
 out.textContent='';status.textContent='Отправка...';
 try{
  const r=await fetch('/api/v1/scans',{method:'POST',
   headers:{'Content-Type':'application/json','Authorization':'Bearer '+token,'Idempotency-Key':crypto.randomUUID()},
   body:JSON.stringify({url,htmlContent:'<form/>',screenshotId:'s1'})});
  if(!r.ok)throw new Error('HTTP '+r.status);
  const created=await r.json();
  status.textContent='Ожидание вердикта...';
  for(let i=0;i<10;i++){
   await new Promise(res=>setTimeout(res,300));
   const s=await fetch('/api/v1/scans/'+created.scanId,{headers:{'Authorization':'Bearer '+token}});
   const scan=await s.json();
   if(scan.status==='COMPLETED'){status.textContent='Готово';out.textContent=JSON.stringify(scan,null,2);return;}
  }
  status.textContent='Таймаут';out.textContent=JSON.stringify(created,null,2);
 }catch(e){status.innerHTML='<span class="err">Ошибка: '+e.message+'</span>';}
}

async function checkDomain(){
 const domain=document.getElementById('dom-name').value.trim();
 const token=document.getElementById('token').value.trim();
 const out=document.getElementById('dom-out'),status=document.getElementById('dom-status');
 
 if(!token){ status.innerHTML='<span class="err">Ошибка: введите токен!</span>'; return; }
 
 out.textContent='';status.textContent='Запрос к domain-intel...';
 try{
  // ИСПРАВЛЕННЫЙ ПУТЬ: /internal/v1/domains/
  const r=await fetch('/internal/v1/domains/'+domain,{headers:{'Authorization':'Bearer '+token}});
  if(!r.ok)throw new Error('HTTP '+r.status);
  const res=await r.json();
  
  status.textContent='Готово!';
  out.textContent = "Домен: " + res.domain + "\\n" +
                    "Риск (0-1): " + res.riskScore + "\\n" +
                    "Возраст домена: " + (res.registered || "Неизвестно");
 }catch(e){status.innerHTML='<span class="err">Ошибка: '+e.message+'</span>';}
}

async function createRule(){
 const domain=document.getElementById('mon-domain').value.trim();
 const period=parseInt(document.getElementById('mon-period').value);
 const token=document.getElementById('token').value.trim();
 const out=document.getElementById('mon-out'),status=document.getElementById('mon-status');
 
 if(!token){ status.innerHTML='<span class="err">Ошибка: введите токен!</span>'; return; }
 
 out.textContent='';status.textContent='Создание правила...';
 try{
  const r=await fetch('/api/v1/monitoring/rules',{method:'POST',
   headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
   body:JSON.stringify({domain:domain, periodHours:period})});
  if(!r.ok)throw new Error('HTTP '+r.status);
  const res=await r.json();
  status.textContent='Правило успешно создано!';
  out.textContent=JSON.stringify(res,null,2);
 }catch(e){status.innerHTML='<span class="err">Ошибка: '+e.message+'</span>';}
}
</script></body></html>
"""

@router.get("/", response_class=HTMLResponse)
async def index():
    return PAGE
