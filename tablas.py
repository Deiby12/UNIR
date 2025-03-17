import tkinter as tk
from tkinter import ttk, messagebox
import re
import itertools

# ==========================================================
# = 1) PARSER (analizador sintáctico) y evaluación de AST  =
# ==========================================================

def tokenize(expr):
    expr = expr.replace("<->", "↔")
    expr = expr.replace("->", "→")
    expr = expr.replace("↔", " ↔ ")
    expr = expr.replace("→", " → ")
    expr = expr.replace("&", " ∧ ")
    expr = expr.replace("|", " ∨ ")
    expr = expr.replace("^", " ⊕ ")
    expr = expr.replace("(", " ( ")
    expr = expr.replace(")", " ) ")
    expr = expr.replace("~", " ~ ")
    expr = expr.replace("!", " ! ")
    tokens = expr.split()
    return tokens

class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0
    
    def peek(self):
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None
    
    def get(self):
        token = self.peek()
        if token is not None:
            self.pos += 1
        return token
    
    def parse_expression(self):
        return self.parse_bicond()
    
    def parse_bicond(self):
        left = self.parse_cond()
        while True:
            token = self.peek()
            if token == '↔':
                self.get()
                right = self.parse_cond()
                left = ('bicond', left, right)
            else:
                break
        return left
    
    def parse_cond(self):
        left = self.parse_xor()
        while True:
            token = self.peek()
            if token == '→':
                self.get()
                right = self.parse_xor()
                left = ('cond', left, right)
            else:
                break
        return left
    
    def parse_xor(self):
        left = self.parse_or()
        while True:
            token = self.peek()
            if token == '⊕':
                self.get()
                right = self.parse_or()
                left = ('xor', left, right)
            else:
                break
        return left
    
    def parse_or(self):
        left = self.parse_and()
        while True:
            token = self.peek()
            if token == '∨':
                self.get()
                right = self.parse_and()
                left = ('or', left, right)
            else:
                break
        return left
    
    def parse_and(self):
        left = self.parse_unary()
        while True:
            token = self.peek()
            if token == '∧':
                self.get()
                right = self.parse_unary()
                left = ('and', left, right)
            else:
                break
        return left
    
    def parse_unary(self):
        token = self.peek()
        if token in ('~', '!'):
            self.get()
            expr = self.parse_unary()
            return ('not', expr)
        if token == '(':
            self.get()
            expr = self.parse_expression()
            if self.peek() == ')':
                self.get()
            else:
                raise ValueError("Falta un ')' en la expresión")
            return expr
        if token and re.match(r'^[a-z]$', token):
            self.get()
            return ('var', token)
        raise ValueError(f"Token inesperado: {token}")

def parse(expr):
    tokens = tokenize(expr)
    parser = Parser(tokens)
    tree = parser.parse_expression()
    if parser.peek() is not None:
        raise ValueError("Sobraron tokens tras parsear la expresión.")
    return tree

def eval_ast(ast, env):
    op = ast[0]
    if op == 'var':
        return env[ast[1]]
    elif op == 'not':
        return not eval_ast(ast[1], env)
    elif op == 'and':
        return eval_ast(ast[1], env) and eval_ast(ast[2], env)
    elif op == 'or':
        return eval_ast(ast[1], env) or eval_ast(ast[2], env)
    elif op == 'xor':
        return eval_ast(ast[1], env) != eval_ast(ast[2], env)
    elif op == 'cond':
        left_val = eval_ast(ast[1], env)
        right_val = eval_ast(ast[2], env)
        return (not left_val) or right_val
    elif op == 'bicond':
        left_val = eval_ast(ast[1], env)
        right_val = eval_ast(ast[2], env)
        return left_val == right_val
    else:
        raise ValueError(f"Operador desconocido en AST: {op}")

# ==========================================================
# = 2) FUNCIONES PARA RECOGER TODAS LAS SUBEXPRESIONES     =
# ==========================================================

def walk_ast(ast):
    """
    Recorre el AST recursivamente y produce todos los sub-nodos (sub-AST).
    """
    yield ast
    op = ast[0]
    if op == 'var':
        return
    elif op == 'not':
        yield from walk_ast(ast[1])
    else:
        yield from walk_ast(ast[1])
        yield from walk_ast(ast[2])

def ast_to_string(ast):
    op = ast[0]
    if op == 'var':
        return ast[1]  # p, q, r, s
    elif op == 'not':
        return "~" + ast_to_string(ast[1])
    elif op == 'and':
        return "(" + ast_to_string(ast[1]) + " ∧ " + ast_to_string(ast[2]) + ")"
    elif op == 'or':
        return "(" + ast_to_string(ast[1]) + " ∨ " + ast_to_string(ast[2]) + ")"
    elif op == 'xor':
        return "(" + ast_to_string(ast[1]) + " ⊕ " + ast_to_string(ast[2]) + ")"
    elif op == 'cond':
        return "(" + ast_to_string(ast[1]) + " -> " + ast_to_string(ast[2]) + ")"
    elif op == 'bicond':
        return "(" + ast_to_string(ast[1]) + " <-> " + ast_to_string(ast[2]) + ")"
    else:
        raise ValueError("Operador desconocido en AST: " + str(op))

# ==========================================================
# = 3) APLICACIÓN tkinter/ttk CON TECLADO LÓGICO           =
# ==========================================================

class TruthTableGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Generador de Tablas de Verdad - Colorear V y F")
        self.root.geometry("1100x600")
        
        # Colores para el tema oscuro
        self.bg_color = "#2d2d2d"
        self.header_color = "#004d40"
        self.text_color = "#ffffff"
        self.true_color = "#4CAF50"   # verde
        self.false_color = "#F44336"  # rojo
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", background=self.bg_color, foreground=self.text_color, fieldbackground=self.bg_color)
        style.configure("Treeview.Heading", background=self.header_color, foreground=self.text_color, relief="flat")
        style.map("Treeview", background=[('selected', self.header_color)])
        
        self.root.configure(bg=self.bg_color)
        self.expression_var = tk.StringVar()
        
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        input_frame = ttk.Frame(main_frame, padding="5")
        input_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(input_frame, text="Expresión lógica:", foreground=self.text_color, background=self.bg_color).pack(side=tk.LEFT, padx=5)
        self.entry_expr = ttk.Entry(input_frame, textvariable=self.expression_var, width=50)
        self.entry_expr.pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="Generar Tabla", command=self.generate_table).pack(side=tk.LEFT, padx=5)
        
        # Botón de ejemplos
        ttk.Button(input_frame, text="Ejemplos", command=self.show_examples).pack(side=tk.LEFT, padx=5)
        
        help_frame = ttk.Frame(main_frame, padding="5")
        help_frame.pack(fill=tk.X, pady=5)
        help_text = (
            "Operadores permitidos:\n"
            "  ~ (Negación), ∧ (Conjunción), ∨ (Disyunción), ⊕ (XOR), -> (Condicional), <-> (Bicondicional)\n"
            "Variables permitidas: p, q, r, s.\n\n"
            "En la tabla, las celdas con 'V' se verán en verde,\n"
            "y las celdas con 'F' se verán en rojo."
        )
        ttk.Label(help_frame, text=help_text, justify=tk.LEFT, foreground=self.text_color, background=self.bg_color).pack(anchor=tk.W)
        
        keypad_frame = ttk.Frame(main_frame, padding="5")
        keypad_frame.pack(pady=5)
        
        button_layout = [
            [("AC", "AC"), ("DEL", "DEL"), ("(", "("), (")", ")")],
            [("~", " ~ "), ("^", " ∧ "), ("v", " ∨ "), ("->", " -> ")],
            [("p", "p"), ("q", "q"), ("↔", " <-> "), ("⊕", " ⊕ ")],
            [("r", "r"), ("s", "s"), ("=", "="), ("", "")]
        ]
        
        for row_idx, row in enumerate(button_layout):
            for col_idx, (label, value) in enumerate(row):
                if not label:
                    continue
                btn = ttk.Button(keypad_frame, text=label, command=lambda l=label, v=value: self.on_keypad_click(l, v), width=4)
                btn.grid(row=row_idx, column=col_idx, padx=3, pady=3)
        
        self.result_frame = ttk.Frame(main_frame, padding="5")
        self.result_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.tree = ttk.Treeview(self.result_frame)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.status_frame = ttk.Frame(main_frame, padding="5")
        self.status_frame.pack(fill=tk.X, pady=5)
        self.status_label = ttk.Label(self.status_frame, text="", font=("Arial", 12, "bold"), foreground=self.text_color, background=self.bg_color)
        self.status_label.pack(anchor=tk.W)
        
        self.var_stats_frame = ttk.Frame(main_frame, padding="5")
        self.var_stats_frame.pack(fill=tk.X, pady=5)
        self.var_stats_label = ttk.Label(self.var_stats_frame, text="", foreground=self.text_color, background=self.bg_color)
        self.var_stats_label.pack(anchor=tk.W)
        
        # Para no reconfigurar el mismo tag varias veces, guardamos aquí los que ya definimos
        self.defined_tags = set()

    def on_keypad_click(self, label, value):
        if label == "AC":
            self.expression_var.set("")
        elif label == "DEL":
            current = self.expression_var.get()
            if current:
                self.expression_var.set(current[:-1])
        elif label == "=":
            self.generate_table()
        else:
            current = self.expression_var.get()
            new_expr = current + value
            self.expression_var.set(new_expr)
        self.entry_expr.focus_set()

    def extract_variables(self, expr):
        var_pattern = re.compile(r'[a-z]')
        vars_found = set(var_pattern.findall(expr))
        return sorted(list(vars_found))
    
    def display_bool(self, value):
        return "V" if value else "F"
    
    def show_examples(self):
        examples = [
            "(p->q) ∧ (r ∨ ~s)",
            "p -> (q -> r)",
            "(p -> q) ↔ (~q -> ~p)",
            "(p ∨ q) ∧ ~(p ∧ q)",
            "p ∨ q ∨ r ∨ s",
            "(p ↔ q) ∧ (r -> s)"
        ]
        examples_window = tk.Toplevel(self.root)
        examples_window.title("Ejemplos de Expresiones")
        examples_window.geometry("400x300")
        examples_window.configure(bg=self.bg_color)
        
        ttk.Label(
            examples_window, 
            text="Haga clic en un ejemplo para usarlo:", 
            font=("Arial", 12), 
            foreground=self.text_color, 
            background=self.bg_color
        ).pack(pady=10)
        
        for example in examples:
            btn = ttk.Button(
                examples_window, 
                text=example, 
                command=lambda ex=example: self.use_example(ex, examples_window)
            )
            btn.pack(fill=tk.X, padx=20, pady=5)
    
    def use_example(self, example, window):
        self.expression_var.set(example)
        window.destroy()

    def generate_table(self):
        expression = self.expression_var.get().strip()
        if not expression:
            messagebox.showwarning("Advertencia", "Por favor, ingrese una expresión lógica.")
            return
        
        # 1) Extraer variables y verificar que sean solo p, q, r, s.
        variables = self.extract_variables(expression)
        allowed = {'p', 'q', 'r', 's'}
        if not set(variables).issubset(allowed):
            bad_vars = sorted(set(variables) - allowed)
            msg = f"Solo se permiten p, q, r, s.\nSe encontraron variables no permitidas: {', '.join(bad_vars)}"
            messagebox.showerror("Error de variables", msg)
            return
        
        self.var_stats_label.config(text=f"Variables detectadas: {', '.join(variables)} (subconjunto de p, q, r, s)")
        
        # 2) Parsear la expresión principal
        try:
            main_ast = parse(expression)
        except ValueError as e:
            messagebox.showerror("Error de parseo", str(e))
            return
        
        # 3) Recolectar TODAS las subexpresiones (walk_ast)
        all_subasts = set(walk_ast(main_ast))
        subexpr_strings = set(ast_to_string(node) for node in all_subasts)
        
        # Quitamos las expresiones que son solo variables sueltas
        subexpr_strings = {s for s in subexpr_strings if len(s) > 1}
        
        # Agregamos la expresión completa
        expr_str = ast_to_string(main_ast)
        subexpr_strings.add(expr_str)
        
        # Ordenamos las subexpresiones por longitud
        ordered_subexprs = sorted(list(subexpr_strings), key=len)
        
        # Limpiar la tabla anterior
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Definir columnas: variables + subexpresiones
        columns = variables + ordered_subexprs
        self.tree["columns"] = columns
        self.tree["show"] = "headings"
        
        for col in columns:
            self.tree.heading(col, text=col)
            width = max(120, len(col) * 10)
            self.tree.column(col, width=width, anchor=tk.CENTER)
        
        # Parsear cada subexpresión a AST para evaluarla
        subexpr_asts = {}
        for se in ordered_subexprs:
            try:
                subexpr_asts[se] = parse(se)
            except ValueError:
                subexpr_asts[se] = None
        
        # Generar todas las combinaciones de valores
        truth_combinations = list(itertools.product([False, True], repeat=len(variables)))
        
        final_results = []
        
        for combination in truth_combinations:
            var_values = dict(zip(variables, combination))
            
            # Primero, valores de las variables
            row_values = [self.display_bool(val) for val in combination]
            
            # Luego, evaluar cada subexpresión
            subexpr_result_for_main = None
            for se in ordered_subexprs:
                ast_node = subexpr_asts.get(se)
                if ast_node is not None:
                    val = eval_ast(ast_node, var_values)
                    val_str = self.display_bool(val)
                    row_values.append(val_str)
                    if se == expr_str:
                        subexpr_result_for_main = val
                else:
                    row_values.append("?")
            
            # Insertamos la fila en la tabla
            item_id = self.tree.insert("", tk.END, values=row_values)
            
            # Asignamos colores a cada celda (V=verde, F=rojo)
            # Definimos un tag por (columna, valor) => "true_col_i" o "false_col_i"
            for i, val_str in enumerate(row_values):
                if val_str == "V":
                    tag_true = f"true_col_{i}"
                    # Si aún no definimos el tag, lo creamos
                    if tag_true not in self.defined_tags:
                        self.tree.tag_configure(tag_true, foreground=self.true_color)
                        self.defined_tags.add(tag_true)
                    # Asignamos el tag a este ítem
                    self.tree.item(item_id, tags=(tag_true,))
                
                elif val_str == "F":
                    tag_false = f"false_col_{i}"
                    if tag_false not in self.defined_tags:
                        self.tree.tag_configure(tag_false, foreground=self.false_color)
                        self.defined_tags.add(tag_false)
                    self.tree.item(item_id, tags=(tag_false,))
                # Si es "?", no le ponemos color
            
            # Guardamos el resultado de la expresión principal
            if subexpr_result_for_main is not None:
                final_results.append(subexpr_result_for_main)
        
        # Clasificar la expresión principal
        if final_results:
            if all(final_results):
                self.status_label.config(text=f"La expresión '{expr_str}' es una TAUTOLOGÍA (siempre verdadera).")
            elif not any(final_results):
                self.status_label.config(text=f"La expresión '{expr_str}' es una CONTRADICCIÓN (siempre falsa).")
            else:
                self.status_label.config(text=f"La expresión '{expr_str}' es una CONTINGENCIA (a veces verdadera, a veces falsa).")
        else:
            self.status_label.config(text="No se pudo determinar el resultado final (revisa la expresión).")

# ==========================================================
# = EJECUCIÓN DE LA APLICACIÓN                            =
# ==========================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = TruthTableGenerator(root)
    root.mainloop()
