require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');
const PDFDocument = require('pdfkit');
const bcrypt = require('bcrypt'); // Adicionado
const jwt = require('jsonwebtoken'); // Adicionado

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// A chave secreta agora vem do .env (com um fallback de segurança)
const JWT_SECRET = process.env.JWT_SECRET || 'chave_temporaria_mudar_em_producao';

// Testa a conexão ao iniciar
pool.connect((err, client, release) => {
    if (err) {
        return console.error('Erro ao conectar com o banco de dados:', err.stack);
    }
    console.log('Conexão com o banco de dados PostgreSQL (Local) estabelecida com sucesso!');
    release();
});

// Middleware Geral: Verifica se o utilizador está com sessão iniciada
function verificarAcesso(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ erro: 'Acesso negado. Token não fornecido.' });

    jwt.verify(token, JWT_SECRET, (err, decodificado) => {
        if (err) return res.status(403).json({ erro: 'Sessão inválida ou expirada.' });
        req.usuario = decodificado; 
        next();
    });
}

// Middleware Restrito: Permite passagem apenas ao Administrador
function verificarAdmin(req, res, next) {
    // Note que validamos "req.usuario.nivel" correspondendo à forma como o token é gerado
    if (req.usuario && req.usuario.nivel === 'Admin') {
        next();
    } else {
        res.status(403).json({ erro: 'Acesso negado. Funcionalidade exclusiva para a gestão.' });
    }
}

// Rota de teste para garantir que o servidor está respondendo
app.get('/api/status', (req, res) => {
    res.json({ mensagem: "Servidor OS Pro rodando 100%!" });
});

// ----------------------------------------------------------------------
// 1. ROTA DE CADASTRO DE EQUIPE (Técnicos e Administradores)
// ----------------------------------------------------------------------
app.post('/api/usuarios', async (req, res) => {
    try {
        const { nome, email, senha, perfil } = req.body;

        // Verifica se o e-mail já existe no banco
        const usuarioExiste = await pool.query("SELECT id FROM usuarios WHERE email = $1", [email]);
        if (usuarioExiste.rows.length > 0) {
            return res.status(400).json({ erro: "Este e-mail já está cadastrado." });
        }

        // Criptografa a senha com 10 camadas de embaralhamento
        const senhaCriptografada = await bcrypt.hash(senha, 10);

        // O perfil padrão será TECNICO caso não seja enviado
        const perfilUsuario = perfil || 'TECNICO';

        const novoUsuario = await pool.query(
            "INSERT INTO usuarios (nome, email, senha_hash, perfil) VALUES ($1, $2, $3, $4) RETURNING id, nome, email, perfil",
            [nome, email, senhaCriptografada, perfilUsuario]
        );

        res.status(201).json({ 
            mensagem: "Usuário da equipe criado com sucesso!", 
            usuario: novoUsuario.rows[0] 
        });
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao cadastrar usuário." });
    }
});

// ----------------------------------------------------------------------
// 2. ROTA DE LOGIN
// ----------------------------------------------------------------------
app.post('/api/login', async (req, res) => {
    const { login, senha } = req.body;
    try {
        const result = await pool.query('SELECT * FROM funcionarios WHERE login = $1 AND ativo = true', [login]);
        if (result.rows.length === 0) return res.status(401).json({ erro: 'Utilizador não encontrado ou desativado.' });

        const usuario = result.rows[0];
        
        // Compara a palavra-passe digitada com a hash guardada no banco de dados
        const senhaValida = await bcrypt.compare(senha, usuario.senha);
        if (!senhaValida) return res.status(401).json({ erro: 'Senha incorreta.' }); 

        const token = jwt.sign(
            { id: usuario.id, nome: usuario.nome, cargo: usuario.cargo, nivel: usuario.nivel_acesso }, 
            JWT_SECRET, 
            { expiresIn: '12h' }
        );

        res.json({ token, nome: usuario.nome, nivel: usuario.nivel_acesso });
    } catch (erro) {
        res.status(500).json({ erro: 'Erro interno no servidor' });
    }
});


// ----------------------------------------------------------------------
// 4. ROTAS DE CLIENTES
// ----------------------------------------------------------------------
app.post('/api/clientes', verificarAcesso, async (req, res) => {
    try {
        const { nome, documento, telefone, email, endereco } = req.body;

        // Evita cadastro duplicado de CPF/CNPJ
        const clienteExiste = await pool.query("SELECT id FROM clientes WHERE documento = $1", [documento]);
        if (clienteExiste.rows.length > 0) {
            return res.status(400).json({ erro: "Este documento já está vinculado a um cliente." });
        }

        const novoCliente = await pool.query(
            "INSERT INTO clientes (nome, documento, telefone, email, endereco) VALUES ($1, $2, $3, $4, $5) RETURNING *",
            [nome, documento, telefone, email, endereco]
        );

        res.status(201).json({ 
            mensagem: "Cliente cadastrado com sucesso!", 
            cliente: novoCliente.rows[0] 
        });
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao cadastrar cliente." });
    }
});

app.get('/api/clientes', verificarAcesso, async (req, res) => {
    try {
        const clientes = await pool.query("SELECT * FROM clientes ORDER BY nome ASC");
        res.json(clientes.rows);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao buscar a lista de clientes." });
    }
});

// --- ROTAS DE CLIENTES ---


// Atualizar cliente existente
app.patch('/api/clientes/:id', verificarAcesso, async (req, res) => {
    const { id } = req.params;
    const { nome, documento, telefone, email, endereco } = req.body;
    try {
        await pool.query(
            "UPDATE clientes SET nome=$1, documento=$2, telefone=$3, email=$4, endereco=$5 WHERE id=$6",
            [nome, documento, telefone, email, endereco, id]
        );
        res.json({ mensagem: "Cliente atualizado com sucesso!" });
    } catch (erro) {
        res.status(500).json({ erro: "Erro ao atualizar o cliente." });
    }
});

// --- APAGAR CLIENTE ---
app.delete('/api/clientes/:id', verificarAcesso, async (req, res) => {
    try {
        await pool.query("DELETE FROM clientes WHERE id=$1", [req.params.id]);
        res.json({ mensagem: "Cliente removido com sucesso!" });
    } catch (erro) {
        // Se o cliente tiver aparelhos ou OS, o banco bloqueia por segurança
        res.status(500).json({ erro: "Não é possível apagar. Este cliente já possui aparelhos ou Ordens de Serviço." });
    }
});

// --- EDITAR EQUIPAMENTO ---
app.patch('/api/equipamentos/:id', verificarAcesso, async (req, res) => {
    const { tipo, marca, modelo, numero_serie } = req.body;
    try {
        await pool.query(
            "UPDATE equipamentos SET tipo=$1, marca=$2, modelo=$3, numero_serie=$4 WHERE id=$5",
            [tipo, marca, modelo, numero_serie, req.params.id]
        );
        res.json({ mensagem: "Aparelho atualizado!" });
    } catch (erro) {
        res.status(500).json({ erro: "Erro ao atualizar o aparelho." });
    }
});

// --- APAGAR EQUIPAMENTO ---
app.delete('/api/equipamentos/:id', verificarAcesso, async (req, res) => {
    try {
        await pool.query("DELETE FROM equipamentos WHERE id=$1", [req.params.id]);
        res.json({ mensagem: "Aparelho removido!" });
    } catch (erro) {
        res.status(500).json({ erro: "Não é possível apagar. Este aparelho já tem uma OS associada." });
    }
});

// ----------------------------------------------------------------------
// 5. ROTAS DE EQUIPAMENTOS
// ----------------------------------------------------------------------
app.post('/api/equipamentos', verificarAcesso, async (req, res) => {
    try {
        const { id_cliente, tipo, marca, modelo, numero_serie, senha_desbloqueio } = req.body;

        // Valida se o cliente de fato existe no banco
        const clienteResult = await pool.query("SELECT id FROM clientes WHERE id = $1", [id_cliente]);
        if (clienteResult.rows.length === 0) {
            return res.status(404).json({ erro: "Cliente não encontrado no sistema." });
        }

        const novoEquipamento = await pool.query(
            "INSERT INTO equipamentos (id_cliente, tipo, marca, modelo, numero_serie, senha_desbloqueio) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
            [id_cliente, tipo, marca, modelo, numero_serie, senha_desbloqueio]
        );

        res.status(201).json({ 
            mensagem: "Equipamento registrado com sucesso!", 
            equipamento: novoEquipamento.rows[0] 
        });
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao registrar o equipamento." });
    }
});

// --- ROTA DO MÓDULO FINANCEIRO (Com Blindagem Matemática) ---
app.get('/api/financeiro/resumo', verificarAcesso, async (req, res) => {
    try {
        const query = `
            SELECT id, valor_mao_de_obra, valor_total 
            FROM ordens_servico 
            WHERE status = 'Concluído'
            ORDER BY id DESC
        `;
        const resultado = await pool.query(query);
        
        let totalFaturado = 0;
        let totalMaoObra = 0;
        let totalPecas = 0; // Variável independente para as peças
        
        const historico = resultado.rows.map(os => {
            const maoObra = parseFloat(os.valor_mao_de_obra) || 0;
            let totalBruto = parseFloat(os.valor_total) || 0;
            
            // BLINDAGEM: O Valor Total nunca pode ser menor que a Mão de Obra!
            // Se houver um erro no banco (ex: Total 180, Mão de Obra 200), ele corrige automaticamente para 200.
            const total = Math.max(totalBruto, maoObra);
            
            const pecas = total - maoObra; // Como o total é no mínimo igual à mão de obra, isto nunca será negativo
            
            totalFaturado += total;
            totalMaoObra += maoObra;
            totalPecas += pecas;
            
            return {
                os_numero: os.id,
                maoObra,
                pecas,
                total
            };
        });

        res.json({
            resumo: {
                totalFaturado,
                totalMaoObra,
                totalPecas
            },
            historico
        });
    } catch (erro) {
        console.error("Erro no financeiro:", erro);
        res.status(500).json({ erro: "Erro ao gerar relatório financeiro." });
    }
});

// Busca todos os aparelhos vinculados a um cliente específico
app.get('/api/equipamentos/cliente/:idCliente', verificarAcesso, async (req, res) => {
    try {
        const { idCliente } = req.params;
        const equipamentos = await pool.query(
            "SELECT * FROM equipamentos WHERE id_cliente = $1 ORDER BY data_registro DESC",
            [idCliente]
        );
        res.json(equipamentos.rows);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao buscar histórico de equipamentos." });
    }
});

// ----------------------------------------------------------------------
// 6. ROTAS DE ORDENS DE SERVIÇO (OS)
// ----------------------------------------------------------------------

// Abrir uma nova Ordem de Serviço
app.post('/api/os', verificarAcesso, async (req, res) => {
    try {
        // 1. Recebe todos os campos do front-end (incluindo acessorios_deixados)
        const { id_cliente, id_equipamento, defeito_relatado, checklist_entrada, acessorios_deixados } = req.body;
        
        // 2. Pega o nome do técnico direto do token de quem está logado!
        const tecnico_responsavel = req.usuario.nome; 

        // 3. Monta a query com todos os 6 campos obrigatórios
        const query = `
            INSERT INTO ordens_servico 
            (id_cliente, id_equipamento, defeito_relatado, checklist_entrada, acessorios_deixados, tecnico_responsavel, status) 
            VALUES ($1, $2, $3, $4, $5, $6, 'Aberto') 
            RETURNING id
        `;
        
        await pool.query(query, [
            id_cliente, 
            id_equipamento, 
            defeito_relatado, 
            checklist_entrada, 
            acessorios_deixados || 'Nenhum', 
            tecnico_responsavel
        ]);
        
        res.json({ mensagem: 'Ordem de Serviço aberta com sucesso!' });
    } catch (erro) {
        // 👉 A MÁGICA DO DIAGNÓSTICO: Agora o terminal vai te dizer exatamente o que quebrou!
        console.error("ERRO DETALHADO AO ABRIR OS:", erro);
        res.status(500).json({ erro: 'Erro interno ao abrir OS. Verifique o terminal do Node.' });
    }
});

// Listar todas as OS (Painel Kanban)
app.get('/api/os', verificarAcesso, async (req, res) => {
    try {
        const query = `
            SELECT 
                os.id, 
                os.id as os_numero,
                os.status, 
                os.data_abertura, 
                os.tecnico_responsavel,
                os.defeito_relatado,
                os.checklist_entrada,
                os.laudo_tecnico,
                os.valor_mao_de_obra,
                os.valor_total,
                c.nome AS cliente_nome,
                c.nome AS cliente, -- Adicionado como redundância para o Front-end
                e.tipo, 
                e.marca, 
                e.modelo
            FROM ordens_servico os
            LEFT JOIN clientes c ON os.id_cliente = c.id
            LEFT JOIN equipamentos e ON os.id_equipamento = e.id
            ORDER BY os.id DESC
        `;
        
        const result = await pool.query(query);
        res.json(result.rows);
        
    } catch (erro) {
        console.error("ERRO AO LISTAR AS OS:", erro);
        res.status(500).json({ erro: 'Erro interno ao buscar as Ordens de Serviço.' });
    }
});

// ----------------------------------------------------------------------
// 7. ROTAS DE ESTOQUE E RASTREABILIDADE
// ----------------------------------------------------------------------

// 1. Criar uma nova peça no armazém (Atualizado)
app.post('/api/estoque', verificarAcesso, async (req, res) => {
    const { nome, categoria, descricao, modelo, quantidade_atual, preco_custo, preco_venda } = req.body;
    try {
        await pool.query(
            "INSERT INTO estoque (nome, categoria, descricao, modelo, quantidade_atual, preco_custo, preco_venda) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            [nome, categoria, descricao, modelo, quantidade_atual, preco_custo, preco_venda]
        );
        res.json({ mensagem: "Peça cadastrada com sucesso!" });
    } catch (erro) {
        console.error("Erro ao cadastrar peça:", erro);
        res.status(500).json({ erro: "Erro ao cadastrar peça no banco de dados." });
    }
});

// 2. Atualizar uma peça existente (Atualizado)
app.patch('/api/estoque/:id', verificarAcesso, async (req, res) => {
    const { id } = req.params;
    const { nome, categoria, descricao, modelo, quantidade_atual, preco_custo, preco_venda } = req.body;
    try {
        await pool.query(
            "UPDATE estoque SET nome=$1, categoria=$2, descricao=$3, modelo=$4, quantidade_atual=$5, preco_custo=$6, preco_venda=$7 WHERE id=$8",
            [nome, categoria, descricao, modelo, quantidade_atual, preco_custo, preco_venda, id]
        );
        res.json({ mensagem: "Peça atualizada com sucesso!" });
    } catch (erro) {
        console.error("Erro ao atualizar peça:", erro);
        res.status(500).json({ erro: "Erro ao atualizar a peça." });
    }
});

// 3. Apagar uma peça do armazém
app.delete('/api/estoque/:id', verificarAcesso, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query("DELETE FROM estoque WHERE id=$1", [id]);
        res.json({ mensagem: "Peça removida com sucesso!" });
    } catch (erro) {
        console.error("Erro ao apagar peça:", erro);
        // Se a peça já estiver a ser usada numa OS, o PostgreSQL bloqueia a exclusão por segurança
        res.status(500).json({ erro: "Não é possível apagar esta peça pois já foi utilizada em alguma Ordem de Serviço." });
    }
});

// Listar tudo o que há no estoque
app.get('/api/estoque', verificarAcesso, async (req, res) => {
    try {
        const estoque = await pool.query("SELECT * FROM estoque ORDER BY nome ASC");
        res.json(estoque.rows);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao consultar o estoque." });
    }
});

// 8. APROVAÇÃO REMOTA DE ORÇAMENTO (WHATSAPP)
// ----------------------------------------------------------------------

// 1. Técnico gera o link de aprovação (Requer Token do Técnico)
app.post('/api/os/:id/gerar-link', verificarAcesso, async (req, res) => {
    try {
        const id_os = req.params.id;
        
        // Gera um código único e difícil de adivinhar de 32 caracteres
        const tokenAprovacao = crypto.randomBytes(16).toString('hex');

        // Atualiza a OS com o token e muda o status
        const resultado = await pool.query(
            "UPDATE ordens_servico SET token_aprovacao = $1, status = 'Aguardando Aprovação' WHERE id = $2 RETURNING id",
            [tokenAprovacao, id_os]
        );

        if (resultado.rows.length === 0) {
            return res.status(404).json({ erro: "OS não encontrada." });
        }

        // Simula como o link ficará no seu Front-end (depois trocamos localhost pelo seu domínio real)
        const linkFrontEnd = `http://localhost:5500/aprovar-os.html?token=${tokenAprovacao}`;

        res.json({ 
            mensagem: "Link gerado com sucesso! Envie para o WhatsApp do cliente.", 
            link_whatsapp: linkFrontEnd,
            token: tokenAprovacao
        });

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao gerar link de aprovação." });
    }
});

// 2. Cliente consulta os dados da OS pelo link (Rota Pública)
app.get('/api/os/aprovacao/:token', async (req, res) => {
    try {
        const { token } = req.params;

        const query = `
            SELECT 
                os.id, 
                os.defeito_relatado, 
                os.laudo_tecnico, 
                os.valor_mao_de_obra, 
                os.valor_total, 
                os.status,
                e.marca, 
                e.modelo
            FROM ordens_servico os
            JOIN equipamentos e ON os.id_equipamento = e.id
            WHERE os.token_aprovacao = $1 AND os.status = 'Aguardando Aprovação'
        `;

        const resultado = await pool.query(query, [token]);

        if (resultado.rows.length === 0) {
            return res.status(404).json({ erro: "Link inválido ou orçamento já respondido." });
        }

        res.json(resultado.rows[0]);
    } catch (erro) {
        console.error("Erro ao buscar orçamento:", erro);
        res.status(500).json({ erro: "Erro interno no servidor." });
    }
});

// 3. Cliente aprova ou rejeita o orçamento (Rota PÚBLICA, sem verificarAcesso)
app.patch('/api/os/aprovacao/:token/responder', async (req, res) => {
    try {
        const { token } = req.params;
        const { aprovado, assinatura } = req.body;

        if (aprovado && !assinatura) {
            return res.status(400).json({ erro: "É necessário assinar digitalmente para aprovar." });
        }

        const novoStatus = aprovado ? 'Aprovado - Em Andamento' : 'Orçamento Rejeitado';

        const resultado = await pool.query(
            `UPDATE ordens_servico 
             SET orcamento_aprovado = $1, assinatura_cliente = $2, status = $3, token_aprovacao = NULL
             WHERE token_aprovacao = $4 RETURNING id, status, orcamento_aprovado`,
            [aprovado, assinatura, novoStatus, token]
        );

        if (resultado.rows.length === 0) {
            return res.status(404).json({ erro: "Ordem de serviço não encontrada ou já processada." });
        }

        res.json({ 
            mensagem: aprovado ? "Obrigado! Orçamento aprovado com sucesso." : "Orçamento rejeitado.",
            os: resultado.rows[0]
        });

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao processar a resposta do cliente." });
    }
});

// ----------------------------------------------------------------------
// 9. ENCERRAMENTO DA OS E GESTÃO FINANCEIRA
// ----------------------------------------------------------------------

// Substitua ou adicione a sua rota PATCH /api/os/:id no index.js
app.patch('/api/os/:id', verificarAcesso, async (req, res) => {
    try {
        const id_os = req.params.id;
        const { laudo_tecnico, valor_mao_de_obra, status } = req.body;

        // 1. Descobre se já existem peças adicionadas a esta OS para não perder o valor delas
        const queryPecas = await pool.query("SELECT COALESCE(SUM(valor_total), 0) AS total_pecas FROM os_pecas WHERE id_os = $1", [id_os]);
        const totalPecas = parseFloat(queryPecas.rows[0].total_pecas);
        
        // 2. Faz a matemática: Mão de Obra + Peças = Valor Total
        const maoDeObra = parseFloat(valor_mao_de_obra || 0);
        const valorTotal = totalPecas + maoDeObra;

        // 3. Atualiza tudo de uma vez no banco
        await pool.query(
            `UPDATE ordens_servico 
             SET laudo_tecnico = $1, valor_mao_de_obra = $2, valor_total = $3, status = $4
             WHERE id = $5`,
            [laudo_tecnico, maoDeObra, valorTotal, status, id_os]
        );

        res.json({ mensagem: "Laudo e valores atualizados com sucesso!" });
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao atualizar a OS." });
    }
});

// 1. Rota de Conclusão da OS (Checkout do Aparelho)
app.patch('/api/os/:id/concluir', verificarAcesso, async (req, res) => {
    try {
        const id_os = req.params.id;

        // Verifica o status atual da OS antes de fechar
        const checkResult = await pool.query(
            "SELECT status, orcamento_aprovado FROM ordens_servico WHERE id = $1", 
            [id_os]
        );
        
        if (checkResult.rows.length === 0) {
            return res.status(404).json({ erro: "OS não encontrada no sistema." });
        }

        const osAtual = checkResult.rows[0];

        if (osAtual.status === 'Concluído') {
            return res.status(400).json({ erro: "Esta Ordem de Serviço já foi encerrada." });
        }
        
        if (!osAtual.orcamento_aprovado) {
            return res.status(400).json({ erro: "Não é possível concluir uma OS sem a aprovação do cliente." });
        }

        // Altera o status e regista o Timestamp da conclusão
        const resultado = await pool.query(
            `UPDATE ordens_servico 
             SET status = 'Concluído', data_conclusao = CURRENT_TIMESTAMP 
             WHERE id = $1 RETURNING id, status, data_conclusao, valor_total`,
            [id_os]
        );

        res.json({ 
            mensagem: "Serviço finalizado! Aparelho pronto para entrega ao cliente.", 
            os: resultado.rows[0]
        });

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao concluir a Ordem de Serviço." });
    }
});

// 2. Rota do Dashboard Financeiro (Apenas para o Administrador)
app.get('/api/financeiro/relatorios', verificarAcesso, verificarAdmin, async (req, res) => {
    try {
        
        // O JOIN cruza as OS concluídas com as peças usadas e o estoque para saber o custo real
        const queryRelatorio = `
            SELECT 
                COUNT(DISTINCT os.id) AS total_os_concluidas,
                COALESCE(SUM(os.valor_mao_de_obra), 0) AS total_mao_de_obra,
                COALESCE(SUM(os.valor_total), 0) AS faturamento_bruto,
                COALESCE(SUM(p.quantidade * e.preco_custo), 0) AS custo_pecas
            FROM ordens_servico os
            LEFT JOIN os_pecas p ON os.id = p.id_os
            LEFT JOIN estoque e ON p.id_peca = e.id
            WHERE os.status = 'Concluído'
        `;

        const resultado = await pool.query(queryRelatorio);
        const dados = resultado.rows[0];

        // Processa os cálculos de lucro líquido
        const faturamentoBruto = parseFloat(dados.faturamento_bruto);
        const custoPecas = parseFloat(dados.custo_pecas);
        const lucroLiquido = faturamentoBruto - custoPecas;

        res.json({
            mensagem: "Dashboard Financeiro atualizado",
            resumo: {
                os_finalizadas: parseInt(dados.total_os_concluidas),
                faturamento_bruto: faturamentoBruto.toFixed(2),
                custo_materiais: custoPecas.toFixed(2),
                lucro_liquido: lucroLiquido.toFixed(2)
            }
        });

    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao extrair o relatório financeiro." });
    }
});

// ----------------------------------------------------------------------
// 10. GERAÇÃO DE LAUDO TÉCNICO E TERMO EM PDF
// ----------------------------------------------------------------------
app.get('/api/os/:id/pdf', verificarAcesso, async (req, res) => {
    try {
        const id_os = req.params.id;

        const queryOS = `
            SELECT 
                os.id, os.data_abertura, os.status, os.defeito_relatado, os.checklist_entrada,
                c.nome AS cliente, c.documento, c.telefone,
                e.tipo, e.marca, e.modelo, e.numero_serie
            FROM ordens_servico os
            JOIN clientes c ON os.id_cliente = c.id
            JOIN equipamentos e ON os.id_equipamento = e.id
            WHERE os.id = $1
        `;
        const resultOS = await pool.query(queryOS, [id_os]);

        if (resultOS.rows.length === 0) {
            return res.status(404).json({ erro: "Ordem de Serviço não encontrada." });
        }

        const os = resultOS.rows[0];
        const doc = new PDFDocument({ margin: 40, size: 'A4' });

        res.setHeader('Content-disposition', `inline; filename=OS_${os.id}_Entrada.pdf`);
        res.setHeader('Content-type', 'application/pdf');
        doc.pipe(res);

        // --- INSERÇÃO DA LOGO (VIA DA LOJA) ---
        try {
            // Insere a imagem nas coordenadas X: 40, Y: 30
            doc.image('logo-doc.png', 40, 30, { width: 120 });
            doc.moveDown(4); // Empurra o texto principal para baixo da imagem
        } catch (err) {
            console.log("Logo não encontrada para o PDF.");
        }

        // ==========================================
        // PARTE 1: VIA DA LOJA (TERMO DE RESPONSABILIDADE)
        // ==========================================
        doc.fontSize(16).font('Helvetica-Bold').text('Ordem de Serviço', { align: 'center' });
        doc.fontSize(10).font('Helvetica').text(`OS Nº: ${os.id} | Data: ${new Date(os.data_abertura).toLocaleDateString('pt-BR')}`, { align: 'center' });
        doc.moveDown(1.5);

        // Box de Dados
        doc.font('Helvetica-Bold').text('DADOS DO CLIENTE E EQUIPAMENTO:');
        doc.font('Helvetica').text(`Cliente: ${os.cliente} (Doc: ${os.documento} | Tel: ${os.telefone})`);
        doc.text(`Equipamento: ${os.tipo} ${os.marca} ${os.modelo} - S/N: ${os.numero_serie || 'Não informado'}`);
        doc.moveDown();

        doc.font('Helvetica-Bold').text('CONDIÇÕES DE ENTRADA:');
        doc.font('Helvetica').text(`Defeito Relatado: ${os.defeito_relatado}`);
        doc.text(`Checklist / Estado Físico: ${os.checklist_entrada}`);
        doc.moveDown(1.5);

        // Cláusulas Jurídicas de Proteção
        doc.font('Helvetica-Bold').fontSize(9).text('TERMOS E CONDIÇÕES DA PRESTAÇÃO DE SERVIÇO:');
        const termosJuridicos = 
            "1. BACKUP: A salvaguarda de dados (backup) é de inteira responsabilidade do cliente. A Dr. Info não se responsabiliza por perda de dados durante testes ou formatações, salvo se o serviço de backup for expressamente contratado.\n" +
            "2. GARANTIA: Garantia de 90 dias sobre a mão de obra do defeito descrito, conforme Art. 26, II, do CDC. A garantia não cobre mau uso, quedas, líquidos ou rompimento de lacres.\n" +
            "3. ABANDONO: Aparelhos não retirados num prazo de 90 dias após a comunicação de conclusão ou reprovação do orçamento serão considerados abandonados, podendo ser doados ou vendidos para custear despesas de armazenamento (Art. 1.275, III, do Código Civil).\n" +
            "4. ESTADO FÍSICO: O cliente atesta que o aparelho foi entregue nas condições exatas descritas no 'Checklist / Estado Físico' acima.";
        doc.font('Helvetica').fontSize(8).text(termosJuridicos, { align: 'justify' });
        doc.moveDown(3);

        // Assinatura
        doc.text('____________________________________________________', { align: 'center' });
        doc.text(`Assinatura do Cliente: ${os.cliente}`, { align: 'center' });
        doc.moveDown(2);

        // ==========================================
        // LINHA PONTILHADA DE CORTE
        // ==========================================
        const yLine = doc.y;
        doc.lineWidth(1).dash(5, { space: 5 }).moveTo(40, yLine).lineTo(550, yLine).stroke();
        doc.moveDown(2);

        // ==========================================
        // PARTE 2: CANHOTO DO CLIENTE
        // ==========================================
        doc.undash(); // Tira o pontilhado da linha de corte
        doc.moveDown(2);

        const startY = doc.y; // Guarda a altura (linha vertical) atual da página

        // 1. Desenha a logo na margem esquerda original (X = 40)
        try {
            doc.image('logo-doc.png', 40, startY, { width: 85 });
        } catch (err) {}

        // 2. Move a margem do texto mais para a direita (X = 140) para não colidir com a logo
        doc.x = 140;
        doc.y = startY;

        doc.fontSize(14).font('Helvetica-Bold').text('Comprovante de Retirada (Via do Cliente)');
        doc.moveDown(0.5);
        
        doc.fontSize(10).font('Helvetica').text(`OS Nº: ${os.id}`);
        doc.text(`Cliente: ${os.cliente}`);
        doc.text(`Aparelho: ${os.tipo} ${os.marca} ${os.modelo}`);
        
        // 3. Garante que o cursor desceu o suficiente para ultrapassar a altura da imagem
        doc.y = Math.max(doc.y, startY + 70);
        doc.moveDown();

        // 4. Devolve a margem para a posição normal (X = 40) e centraliza o aviso
        doc.x = 40;
        doc.font('Helvetica-Bold').text('ATENÇÃO: A apresentação deste canhoto é obrigatória para a retirada do equipamento.', { align: 'center' });

        doc.end();
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao gerar o PDF da OS." });
    }
});

// Adicione junto das outras rotas de OS no index.js
app.get('/api/os/:id/pecas', verificarAcesso, async (req, res) => {
    try {
        const id_os = req.params.id;
        const query = `
            SELECT op.id, op.quantidade, op.valor_unitario, op.valor_total, e.nome
            FROM os_pecas op
            JOIN estoque e ON op.id_peca = e.id
            WHERE op.id_os = $1
        `;
        const resultado = await pool.query(query, [id_os]);
        res.json(resultado.rows);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao procurar peças da OS." });
    }
});

// Adicione junto das outras rotas de OS no index.js
app.post('/api/os/:id/pecas', verificarAcesso, async (req, res) => {
    const id_os = req.params.id;
    const { id_peca, quantidade } = req.body;
    
    try {
        // 1. Busca o preço atual da peça e verifica se há quantidade suficiente
        const pecaQuery = await pool.query("SELECT preco_venda, quantidade_atual FROM estoque WHERE id = $1", [id_peca]);
        if (pecaQuery.rows.length === 0) return res.status(404).json({ erro: "Peça não encontrada." });
        
        const peca = pecaQuery.rows[0];
        if (peca.quantidade_atual < quantidade) return res.status(400).json({ erro: "Estoque insuficiente para esta quantidade." });

        const valor_unitario = peca.preco_venda;
        const valor_total_pecas = valor_unitario * quantidade;

        // 2. Regista a peça na Ordem de Serviço
        await pool.query(
            "INSERT INTO os_pecas (id_os, id_peca, quantidade, valor_unitario, valor_total) VALUES ($1, $2, $3, $4, $5)",
            [id_os, id_peca, quantidade, valor_unitario, valor_total_pecas]
        );

        // 3. Desconta do Estoque físico
        await pool.query(
            "UPDATE estoque SET quantidade_atual = quantidade_atual - $1 WHERE id = $2",
            [quantidade, id_peca]
        );

        // 4. Soma o valor da peça ao Valor Total da OS
        await pool.query(
            "UPDATE ordens_servico SET valor_total = valor_total + $1 WHERE id = $2",
            [valor_total_pecas, id_os]
        );

        res.json({ mensagem: "Peça adicionada com sucesso!" });
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro interno ao adicionar peça." });
    }
});

// Rota para REMOVER peça da OS e devolver ao estoque
app.delete('/api/os/:id_os/pecas/:id_os_peca', verificarAcesso, async (req, res) => {
    const { id_os, id_os_peca } = req.params;
    try {
        // 1. Pega os dados da peça na OS antes de a apagar
        const pecaOSQuery = await pool.query("SELECT id_peca, quantidade, valor_total FROM os_pecas WHERE id = $1 AND id_os = $2", [id_os_peca, id_os]);
        if (pecaOSQuery.rows.length === 0) return res.status(404).json({ erro: "Peça não encontrada na OS." });
        
        const pecaOS = pecaOSQuery.rows[0];

        // 2. Devolve a quantidade para o Estoque físico
        await pool.query("UPDATE estoque SET quantidade_atual = quantidade_atual + $1 WHERE id = $2", [pecaOS.quantidade, pecaOS.id_peca]);

        // 3. Subtrai o valor da peça do Valor Total da OS (evitando ficar negativo)
        await pool.query("UPDATE ordens_servico SET valor_total = GREATEST(valor_total - $1, 0) WHERE id = $2", [pecaOS.valor_total, id_os]);

        // 4. Apaga o registo da peça na OS
        // Recalcula o total mantendo a mão de obra salva
        await pool.query(`
            UPDATE ordens_servico 
            SET valor_total = COALESCE(valor_mao_de_obra, 0) + COALESCE((SELECT SUM(valor_total) FROM os_pecas WHERE id_os = $1), 0)
            WHERE id = $1
        `, [req.params.id]);

        res.json({ mensagem: "Peça removida e devolvida ao estoque!" });
    } catch (erro) {
        console.error("Erro ao remover peça:", erro);
        res.status(500).json({ erro: "Erro interno ao remover a peça." });
    }
});

// Rota pública para o cliente visualizar o orçamento (Corrigida com JOIN)
app.get('/api/public/os/:token', async (req, res) => {
    try {
        const { token } = req.params;
        
        // Usamos os.* para trazer todas as colunas reais da OS (incluindo valor_mao_de_obra e valor_total)
        // E fazemos o JOIN para pegar o nome do cliente e os dados do aparelho sem erro de coluna!
        const query = `
            SELECT 
                os.*, 
                c.nome AS cliente_nome,
                CONCAT(e.tipo, ' ', e.marca, ' ', e.modelo) AS equipamento,
                e.marca,
                e.modelo
            FROM ordens_servico os
            LEFT JOIN clientes c ON os.id_cliente = c.id
            LEFT JOIN equipamentos e ON os.id_equipamento = e.id
            WHERE os.token_aprovacao = $1
        `;
        
        const resultado = await pool.query(query, [token]);
        
        if (resultado.rows.length === 0) {
            return res.status(404).json({ erro: "Orçamento não encontrado ou link inválido." });
        }
        
        res.json(resultado.rows[0]);
    } catch (erro) {
        console.error("Erro na rota pública da OS:", erro);
        res.status(500).json({ erro: "Erro interno do servidor." });
    }
});

// Listar funcionários ativos (Apenas Admins)
app.get('/api/funcionarios', verificarAcesso, verificarAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, nome, cargo, login, nivel_acesso, ativo FROM funcionarios ORDER BY nome');
        res.json(result.rows);
    } catch (erro) {
        res.status(500).json({ erro: 'Erro ao buscar funcionários' });
    }
});

app.get('/api/os/:id/recibo', async (req, res) => {
            try {
                const id_os = req.params.id;
                
                const queryOS = `
                    SELECT os.*, c.nome as cliente_nome, c.documento, e.marca, e.modelo 
                    FROM ordens_servico os
                    JOIN clientes c ON os.id_cliente = c.id
                    JOIN equipamentos e ON os.id_equipamento = e.id
                    WHERE os.id = $1
                `;
                const resOS = await pool.query(queryOS, [id_os]);
                
                if (resOS.rows.length === 0) return res.status(404).send("OS não encontrada.");
                
                const os = resOS.rows[0];
                const dataHoje = new Date().toLocaleDateString('pt-BR');
                const valorFormatado = parseFloat(os.valor_total).toFixed(2).replace('.', ',');

                // Layout HTML do Recibo
                const html = `
                    <!DOCTYPE html>
                    <html lang="pt-BR">
                    <head>
                        <meta charset="UTF-8">
                        <title>Recibo OS #${os.id}</title>
                        <style>
                            body { font-family: Arial, sans-serif; padding: 40px; max-width: 800px; margin: 0 auto; color: #333; }
                            .header { text-align: center; border-bottom: 2px solid #ddd; padding-bottom: 20px; margin-bottom: 30px; }
                            .valor { font-size: 24px; font-weight: bold; background: #f9f9f9; padding: 15px; border: 1px solid #ccc; text-align: center; margin: 20px 0; }
                            .assinatura { margin-top: 80px; text-align: center; border-top: 1px solid #000; width: 60%; margin-left: auto; margin-right: auto; padding-top: 10px; }
                        </style>
                    </head>
                    <body onload="window.print()">
                        <div class="header">
                            <!-- Como o seu frontend roda localmente na porta 5500, usamos este caminho. Em produção, você colocaria a URL do seu site (ex: https://seusite.com/logo.png) -->
                            <img src="http://localhost:5500/logo-doc.png" alt="Dr. Info" style="max-width: 180px; margin-bottom: 10px;">
                            
                            <h1>Dr. Info - Oficina Técnica</h1>
                            <h2>RECIBO DE PAGAMENTO</h2>
                        </div>
                        
                        <p>Recebemos de <strong>${os.cliente_nome}</strong> (Doc: ${os.documento}), a quantia de:</p>
                        <div class="valor">R$ ${valorFormatado}</div>
                        
                        <p>Referente aos serviços de manutenção prestados no equipamento <strong>${os.marca} ${os.modelo}</strong> (OS #${os.id}).</p>
                        <p><strong>Descrição do Serviço:</strong> ${os.laudo_tecnico}</p>
                        
                        <p style="margin-top: 40px;">Por ser verdade, firmamos o presente recibo.</p>
                        <p>Ibirité, MG - ${dataHoje}</p>
                        
                        <div class="assinatura">
                            Assinatura / Carimbo Dr. Info
                        </div>
                    </body>
                    </html>
                `;
                
                res.send(html);
            } catch (erro) {
                res.status(500).send("Erro ao gerar recibo.");
            }
        });

        // Cadastrar funcionário
        app.post('/api/funcionarios', verificarAcesso, verificarAdmin, async (req, res) => {
            const { nome, cargo, login, senha, nivel_acesso } = req.body;
            try {
                const senhaHash = await bcrypt.hash(senha, 10);
                await pool.query(
                    'INSERT INTO funcionarios (nome, cargo, login, senha, nivel_acesso) VALUES ($1, $2, $3, $4, $5)',
                    [nome, cargo, login, senhaHash, nivel_acesso]
                );
                res.json({ mensagem: 'Funcionário cadastrado com sucesso!' });
            } catch (erro) {
                res.status(500).json({ erro: 'Erro ao cadastrar funcionário. O login já pode estar em uso.' });
            }
        });

        // Atualizar dados do funcionário (Editar)
        app.put('/api/funcionarios/:id', verificarAcesso, verificarAdmin, async (req, res) => {
            const { nome, cargo, login, senha, nivel_acesso } = req.body;
            try {
                if (senha) {
                    const senhaHash = await bcrypt.hash(senha, 10);
                    await pool.query(
                        'UPDATE funcionarios SET nome=$1, cargo=$2, login=$3, senha=$4, nivel_acesso=$5 WHERE id=$6',
                        [nome, cargo, login, senhaHash, nivel_acesso, req.params.id]
                    );
                } else {
                    await pool.query(
                        'UPDATE funcionarios SET nome=$1, cargo=$2, login=$3, nivel_acesso=$4 WHERE id=$5',
                        [nome, cargo, login, nivel_acesso, req.params.id]
                    );
                }
                res.json({ mensagem: 'Funcionário atualizado com sucesso!' });
            } catch (erro) {
                res.status(500).json({ erro: 'Erro ao atualizar funcionário.' });
            }
        });

        // Desativar ou Reativar funcionário (Soft Delete)
       app.patch('/api/funcionarios/:id/status', verificarAcesso, verificarAdmin, async (req, res) => {
            const { ativo } = req.body;
            try {
                await pool.query('UPDATE funcionarios SET ativo = $1 WHERE id = $2', [ativo, req.params.id]);
                res.json({ mensagem: 'Status atualizado com sucesso!' });
            } catch (erro) {
                res.status(500).json({ erro: 'Erro ao mudar status do funcionário.' });
            }
        });


const PORTA = process.env.PORT || 3000;
app.listen(PORTA, () => {
    console.log(`Servidor rodando na porta ${PORTA}`);
});

module.exports = pool;