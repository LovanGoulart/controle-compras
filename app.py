from flask import Flask, render_template, request, redirect, session, flash, g
from datetime import datetime, date
from functools import wraps
import sqlite3
import os
import secrets
import re
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)

# SECRET KEY via variavel de ambiente (fallback para desenvolvimento)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Headers de seguranca
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # CSP que permite CDN para fontes, scripts e styles
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:;"
    )
    return response
# Rate limiting simples
login_attempts = {}

# ---------------- BANCO ----------------
DATABASE = "database.db"

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        senha TEXT NOT NULL,
        ativo INTEGER DEFAULT 1,
        data_cadastro TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS compras (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id INTEGER NOT NULL,
        local TEXT,
        produto TEXT,
        valor REAL NOT NULL CHECK(valor >= 0),
        data TEXT NOT NULL,
        parcelas INTEGER DEFAULT 1,
        parcela_atual INTEGER DEFAULT 1,
        data_cadastro TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_compras_usuario_data ON compras(usuario_id, data)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_compras_produto ON compras(produto)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios(email)")

    db.commit()

with app.app_context():
    init_db()

# ---------------- UTILITARIOS ----------------
def formatar_mes(mes):
    meses = {
        "01": "Janeiro", "02": "Fevereiro", "03": "Março", "04": "Abril",
        "05": "Maio", "06": "Junho", "07": "Julho", "08": "Agosto",
        "09": "Setembro", "10": "Outubro", "11": "Novembro", "12": "Dezembro"
    }
    if mes:
        ano, mes_num = mes.split('-')
        return f"{meses.get(mes_num)} de {ano}"
    return ""

def formatar_data(data_str):
    try:
        data = datetime.strptime(data_str, '%Y-%m-%d')
        return data.strftime('%d/%m/%y')
    except (ValueError, TypeError):
        return data_str

def validar_email_seguro(email):
    try:
        valid = validate_email(email)
        return valid.email
    except EmailNotValidError:
        return None

def validar_senha_forte(senha):
    if len(senha) < 8:
        return False, "Senha deve ter no minimo 8 caracteres"
    if not re.search(r"[A-Z]", senha):
        return False, "Senha deve conter pelo menos uma letra maiúscula"
    if not re.search(r"[a-z]", senha):
        return False, "Senha deve conter pelo menos uma letra minúscula"
    if not re.search(r"[0-9]", senha):
        return False, "Senha deve conter pelo menos um número"
    return True, None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    mensagem = None
    tipo = None

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        senha = request.form.get('senha', '')

        ip = request.remote_addr
        if ip in login_attempts:
            if login_attempts[ip]['count'] >= 5:
                if (datetime.now() - login_attempts[ip]['last']).seconds < 300:
                    mensagem = "Muitas tentativas. Aguarde 5 minutos."
                    tipo = "erro"
                    return render_template('login.html', mensagem=mensagem, tipo=tipo)
                else:
                    login_attempts[ip] = {'count': 0, 'last': datetime.now()}

        if not email or not senha:
            mensagem = "Preencha todos os campos"
            tipo = "erro"
        else:
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "SELECT id, nome, senha, ativo FROM usuarios WHERE email = ?",
                (email,)
            )
            user = cursor.fetchone()

            if user and check_password_hash(user['senha'], senha):
                if not user['ativo']:
                    mensagem = "Conta desativada"
                    tipo = "erro"
                else:
                    session['usuario_id'] = user['id']
                    session['usuario_nome'] = user['nome']
                    login_attempts.pop(ip, None)
                    return redirect('/')
            else:
                mensagem = "Email ou senha incorretos"
                tipo = "erro"

                if ip not in login_attempts:
                    login_attempts[ip] = {'count': 0, 'last': datetime.now()}
                login_attempts[ip]['count'] += 1
                login_attempts[ip]['last'] = datetime.now()

    return render_template('login.html', mensagem=mensagem, tipo=tipo)

@app.route('/logout')
def logout():
    session.clear()
    flash("Voce entrou no sistema", "sucesso")
    return redirect('/login')

# ---------------- CADASTRO ----------------
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    mensagem = None
    tipo = None

    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        email = request.form.get('email', '').strip().lower()
        senha = request.form.get('senha', '')

        if not nome or len(nome) < 3:
            mensagem = "Nome deve ter no minimo 3 caracteres"
            tipo = "erro"
        elif not validar_email_seguro(email):
            mensagem = "Email inválido"
            tipo = "erro"
        else:
            senha_valida, erro_senha = validar_senha_forte(senha)
            if not senha_valida:
                mensagem = erro_senha
                tipo = "erro"
            else:
                db = get_db()
                cursor = db.cursor()

                try:
                    senha_hash = generate_password_hash(senha, method='pbkdf2:sha256', salt_length=16)

                    cursor.execute("""
                        INSERT INTO usuarios (nome, email, senha)
                        VALUES (?, ?, ?)
                    """, (nome, email, senha_hash))

                    db.commit()
                    mensagem = "Usuario cadastrado com sucesso! Redirecionando..."
                    tipo = "sucesso"

                except sqlite3.IntegrityError:
                    mensagem = "Este e-mail já está cadastrado!"
                    tipo = "erro"

    return render_template('cadastro.html', mensagem=mensagem, tipo=tipo)

# ---------------- HOME ----------------
@app.route('/')
@login_required
def index():
    usuario_id = session['usuario_id']
    usuario_nome = session['usuario_nome']

    mes = request.args.get('mes') or datetime.now().strftime("%Y-%m")

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT COALESCE(SUM(valor), 0) as total
        FROM compras
        WHERE usuario_id=? AND strftime('%Y-%m', data)=?
    """, (usuario_id, mes))
    total_mes = cursor.fetchone()['total']

    cursor.execute("""
        SELECT produto, SUM(valor) as total
        FROM compras
        WHERE usuario_id=? AND strftime('%Y-%m', data)=?
        GROUP BY produto
        ORDER BY total DESC
        LIMIT 8
    """, (usuario_id, mes))
    dados = cursor.fetchall()

    nomes = [d['produto'] or "Sem nome" for d in dados]
    valores = [float(d['total'] or 0) for d in dados]

    meses = []
    data_base = datetime.strptime(mes, "%Y-%m")

    for i in range(12):
        ano = data_base.year
        mes_num = data_base.month - i

        while mes_num <= 0:
            mes_num += 12
            ano -= 1

        valor = f"{ano}-{mes_num:02d}"
        nome = formatar_mes(valor)
        meses.append({"valor": valor, "nome": nome})

    return render_template(
        'index.html',
        total_mes=float(total_mes),
        nomes=nomes,
        valores=valores,
        mes=mes,
        mes_formatado=formatar_mes(mes),
        meses=meses
    )

# ---------------- CADASTRAR COMPRA ----------------
from dateutil.relativedelta import relativedelta

@app.route('/cadastrar', methods=['GET', 'POST'])
@login_required
def cadastrar():
    usuario_id = session['usuario_id']

    if request.method == 'POST':
        db = get_db()
        cursor = db.cursor()

        produto = request.form.get('produto', '').strip()

        if produto == 'outros':
            produto = request.form.get('outro_categoria', 'Outros').strip()

        local = request.form.get('local', '').strip()

        try:
            valor_total = float(request.form.get('valor', 0))
            if valor_total <= 0:
                flash("Valor deve ser maior que zero", "erro")
                return redirect('/cadastrar')
        except (ValueError, TypeError):
            flash("Valor inválido", "erro")
            return redirect('/cadastrar')

        try:
            parcelas = int(request.form.get('parcelas', 1))
            if parcelas < 1 or parcelas > 48:
                flash("Número de parcelas inválido (max: 48)", "erro")
                return redirect('/cadastrar')
        except (ValueError, TypeError):
            parcelas = 1

        try:
            data_inicial = datetime.strptime(request.form.get('data'), '%Y-%m-%d')
        except (ValueError, TypeError):
            flash("Data inválida", "erro")
            return redirect('/cadastrar')

        valor_parcela = round(valor_total / parcelas, 2)
        ajuste = valor_total - (valor_parcela * parcelas)

        for i in range(parcelas):
            data_parcela = data_inicial + relativedelta(months=i)

            descricao_produto = produto
            if parcelas > 1:
                descricao_produto = f"{produto} ({i+1}/{parcelas})"

            valor_final = valor_parcela
            if i == parcelas - 1:
                valor_final = round(valor_parcela + ajuste, 2)

            cursor.execute("""
                INSERT INTO compras (
                    usuario_id, local, produto, valor, data,
                    parcelas, parcela_atual
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                usuario_id, local, descricao_produto, valor_final,
                data_parcela.strftime('%Y-%m-%d'), parcelas, i+1
            ))

        db.commit()
        flash("Compra cadastrada com sucesso!", "sucesso")
        return redirect('/')

    return render_template('cadastrar.html', hoje=date.today())

# ---------------- RELATORIO ----------------
@app.route('/relatorio')
@login_required
def relatorio():
    usuario_id = session['usuario_id']
    mes = request.args.get('mes') or date.today().strftime('%Y-%m')

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT produto, SUM(valor) as total
        FROM compras
        WHERE usuario_id=? AND strftime('%Y-%m', data)=?
        GROUP BY produto
        ORDER BY total DESC
    """, (usuario_id, mes))
    gastos = cursor.fetchall()

    cursor.execute("""
        SELECT COALESCE(SUM(valor), 0) as total
        FROM compras
        WHERE usuario_id=? AND strftime('%Y-%m', data)=?
    """, (usuario_id, mes))
    total = float(cursor.fetchone()['total'])

    cursor.execute("""
        SELECT COALESCE(SUM(valor), 0) as total
        FROM compras
        WHERE usuario_id=?
    """, (usuario_id,))
    total_anual = float(cursor.fetchone()['total'])

    cursor.execute("""
        SELECT COUNT(DISTINCT strftime('%Y-%m', data)) as meses
        FROM compras
        WHERE usuario_id=?
    """, (usuario_id,))
    meses_count = cursor.fetchone()['meses'] or 1
    media_mensal = total_anual / meses_count

    return render_template(
        'relatorio.html',
        gastos=gastos,
        total=total,
        total_anual=total_anual,
        media_mensal=media_mensal,
        mes=mes,
        mes_formatado=formatar_mes(mes)
    )

# ---------------- COMPRAS ----------------
@app.route('/compras')
@login_required
def compras():
    usuario_id = session['usuario_id']
    mes = request.args.get('mes') or date.today().strftime('%Y-%m')
    busca = request.args.get('busca', '').strip()
    pagina = request.args.get('pagina', 1, type=int)
    por_pagina = 20

    db = get_db()
    cursor = db.cursor()

    query = "SELECT COUNT(*) as total FROM compras WHERE usuario_id=?"
    params = [usuario_id]

    query += " AND strftime('%Y-%m', data)=?"
    params.append(mes)

    if busca:
        query += " AND (produto LIKE ? OR local LIKE ?)"
        busca_like = f"%{busca}%"
        params.extend([busca_like, busca_like])

    cursor.execute(query, params)
    total_registros = cursor.fetchone()['total']

    query = """
        SELECT id, local, produto, valor, data, parcelas, parcela_atual
        FROM compras WHERE usuario_id=?
    """
    params = [usuario_id]

    query += " AND strftime('%Y-%m', data)=?"
    params.append(mes)

    if busca:
        query += " AND (produto LIKE ? OR local LIKE ?)"
        busca_like = f"%{busca}%"
        params.extend([busca_like, busca_like])

    query += " ORDER BY data DESC LIMIT ? OFFSET ?"
    params.extend([por_pagina, (pagina - 1) * por_pagina])

    cursor.execute(query, params)
    dados = cursor.fetchall()

    compras_formatadas = []
    for c in dados:
        compras_formatadas.append({
            'id': c['id'],
            'local': c['local'],
            'produto': c['produto'],
            'valor': float(c['valor'] or 0),
            'data': formatar_data(c['data']),
            'parcelas': c['parcelas'],
            'parcela_atual': c['parcela_atual']
        })

    total_paginas = (total_registros + por_pagina - 1) // por_pagina

    return render_template(
        'compras.html',
        compras=compras_formatadas,
        mes=mes,
        busca=busca,
        mes_formatado=formatar_mes(mes),
        pagina=pagina,
        total_paginas=total_paginas,
        total_registros=total_registros
    )

# ---------------- EXCLUIR COMPRA ----------------
@app.route('/compra/<int:id>/excluir', methods=['POST'])
@login_required
def excluir_compra(id):

    usuario_id = session['usuario_id']

    # PEGA O MÊS ATUAL DA TELA
    mes = request.form.get('mes', '')

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        "SELECT id FROM compras WHERE id=? AND usuario_id=?",
        (id, usuario_id)
    )

    if not cursor.fetchone():
        flash("Compra não encontrada", "erro")

        if mes:
            return redirect(f'/compras?mes={mes}')

        return redirect('/compras')

    cursor.execute(
        "DELETE FROM compras WHERE id=?",
        (id,)
    )

    db.commit()

    flash("Compra excluída com sucesso!", "sucesso")

    # VOLTA PARA O MESMO MÊS
    if mes:
        return redirect(f'/compras?mes={mes}')

    return redirect('/compras')

# ---------------- ERRO HANDLERS ----------------
@app.errorhandler(404)
def not_found(error):
    return render_template('erro.html', codigo=404, mensagem="Página não encontrada"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('erro.html', codigo=500, mensagem="Erro interno do servidor"), 500

# ---------------- RUN ----------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
