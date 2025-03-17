import tkinter as tk
from tkinter import ttk, messagebox
import re
import itertools

# ==========================================================
# = 1) PARSER (analizador sintáctico) y evaluación de AST  =
# ==========================================================

def tokenize(expr):
    """
    Convierte la cadena 'expr' en una lista de tokens:
      - Reemplaza primero las variantes de los operadores por uno estándar.
      - p->q  se convierte en p → q
      - p<->q se convierte en p ↔ q
      - &     se convierte en ∧
      - |     se convierte en ∨
      - ^     se convierte en ⊕
      - etc.
    Luego separa por espacios y devuelve la lista de tokens.
    """
    # Unificamos flechas
    expr = expr.replace("<->", "↔")
    expr = expr.replace("->", "→")
    
    # También la variante con símbolos Unicode
    expr = expr.replace("↔", " ↔ ")
    expr = expr.replace("→", " → ")
    
    # Unificamos conjunción y disyunción
    expr = expr.replace("&", " ∧ ")
    expr = expr.replace("|", " ∨ ")
    
    # Unificamos XOR
    expr = expr.replace("^", " ⊕ ")
    
    # Insertamos espacios alrededor de paréntesis
    expr = expr.replace("(", " ( ")
    expr = expr.replace(")", " ) ")
    
    # Negaciones ~ y ! se quedan tal cual, solo separamos con espacios
    expr = expr.replace("~", " ~ ")
    expr = expr.replace("!", " ! ")
    
    # Ahora dividimos por espacios
    tokens = expr.split()
    return tokens

class Parser:
    """
    Parser recursivo que construye un árbol sintáctico (AST) para la expresión.
    Gramática simplificada con precedencia (de mayor a menor):
      1) Negación (~, !)
      2) Paréntesis (...)
      3) Conjunción (∧)
      4) Disyunción (∨)
      5) XOR (⊕)
      6) Implicación (→)
      7) Bicondicional (↔)
    """
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0  # posición actual en la lista de tokens
    
    def peek(self):
        """Mira el token actual sin consumirlo."""
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None
    
    def get(self):
        """Devuelve el token actual y avanza."""
        token = self.peek()
        if token is not None:
            self.pos += 1
        return token
    
    def parse_expression(self):
        """
        parse_expression := parse_bicond
        """
        return self.parse_bicond()
    
    def parse_bicond(self):
        """
        parse_bicond := parse_imp (('↔') parse_imp)*
        """
        left = self.parse_imp()
        while True:
            token = self.peek()
            if token == '↔':
                self.get()  # consume '↔'
                right = self.parse_imp()
                left = ('bicond', left, right)
            else:
                break
        return left
    
    def parse_imp(self):
        """
        parse_imp := parse_xor (('→') parse_xor)*
        (implicación es menor precedencia que XOR, AND, OR)
        """
        left = self.parse_xor()
        while True:
            token = self.peek()
            if token == '→':
                self.get()
                right = self.parse_xor()
                left = ('imp', left, right)  # p->q
            else:
                break
        return left
    
    def parse_xor(self):
        """
        parse_xor := parse_or (('⊕') parse_or)*
        """
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
        """
        parse_or := parse_and (('∨') parse_and)*
        """
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
        """
        parse_and := parse_unary (('∧') parse_unary)*
        """
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
        """
        parse_unary := ('~' | '!') parse_unary
                     | '(' parse_expression ')'
                     | variable (una letra a-z)
        """
        token = self.peek()
        if token in ('~', '!'):
            self.get()
            expr = self.parse_unary()
            return ('not', expr)
        
        if token == '(':
            self.get()  # consume '('
            expr = self.parse_expression()
            # esperar ')'
            if self.peek() == ')':
                self.get()
            else:
                raise ValueError("Falta un ')' en la expresión")
            return expr
        
        # variable: una sola letra a-z
        if token and re.match(r'^[a-z]$', token):
            self.get()
            return ('var', token)
        
        raise ValueError(f"Token inesperado: {token}")
    
def parse(expr):
    """
    Función de conveniencia para tokenizar la expresión y construir el AST.
    """
    tokens = tokenize(expr)
    parser = Parser(tokens)
    tree = parser.parse_expression()
    # Si sobran tokens, error
    if parser.peek() is not None:
        raise ValueError("Sobraron tokens tras parsear la expresión.")
    return tree

def eval_ast(ast, env):
    """
    Evalúa el AST con los valores de 'env' (dict var->bool).
    Devuelve True/False.
    
    ast: (op, izq, der) o (op, expr) o ('var', nombre)
    """
    op = ast[0]
    
    if op == 'var':
        # ('var', 'p')
        varname = ast[1]
        return env[varname]
    elif op == 'not':
        return not eval_ast(ast[1], env)
    elif op == 'and':
        return eval_ast(ast[1], env) and eval_ast(ast[2], env)
    elif op == 'or':
        return eval_ast(ast[1], env) or eval_ast(ast[2], env)
    elif op == 'xor':
        return eval_ast(ast[1], env) != eval_ast(ast[2], env)
    elif op == 'imp':
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
# = 2) APLICACIÓN tkinter/ttk PARA GENERAR TABLAS DE VERDAD =
# ==========================================================

class TruthTableGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Generador de Tablas de Verdad (con Parser)")
        self.root.geometry("900x600")
        
        # Colores para el tema oscuro
        self.bg_color = "#2d2d2d"
        self.header_color = "#004d40"
        self.text_color = "#ffffff"
        self.true_color = "#4CAF50"   # Verde
        self.false_color = "#F44336"  # Rojo
        
        # Configuración del estilo de ttk
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", 
                        background=self.bg_color, 
                        foreground=self.text_color, 
                        fieldbackground=self.bg_color)
        style.configure("Treeview.Heading", 
                        background=self.header_color, 
                        foreground=self.text_color,
                        relief="flat")
        style.map("Treeview", background=[('selected', self.header_color)])
        
        # Configuración de la ventana raíz
        self.root.configure(bg=self.bg_color)
        
        # Variable para la expresión
        self.expression_var = tk.StringVar()
        
        # Frame principal
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Frame de entrada (expresión y botones)
        input_frame = ttk.Frame(main_frame, padding="5")
        input_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(
            input_frame, 
            text="Expresión lógica:", 
            foreground=self.text_color, 
            background=self.bg_color
        ).pack(side=tk.LEFT, padx=5)
        
        self.entry_expr = ttk.Entry(
            input_frame, 
            textvariable=self.expression_var, 
            width=50
        )
        self.entry_expr.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            input_frame, 
            text="Generar Tabla", 
            command=self.generate_table
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            input_frame, 
            text="Ejemplos", 
            command=self.show_examples
        ).pack(side=tk.LEFT, padx=5)

        # Frame de ayuda con los operadores
        help_frame = ttk.Frame(main_frame, padding="5")
        help_frame.pack(fill=tk.X, pady=5)
        
        help_text = (
            "Operadores disponibles (parser):\n"
            " - Negación: ~ o !\n"
            " - Conjunción: & o ∧  (internamente se convertirá en ∧)\n"
            " - Disyunción: | o ∨  (internamente se convertirá en ∨)\n"
            " - Implicación: -> o →\n"
            " - Bicondicional: <-> o ↔\n"
            " - XOR: ^ o ⊕\n\n"
            "Ejemplos:\n"
            " (p->q) ∧ r\n"
            " p ↔ q\n"
            " ~p ∨ (q ⊕ r)\n"
            " etc.\n"
            "Variables: letras a-z.\n"
        )
        ttk.Label(
            help_frame, 
            text=help_text, 
            justify=tk.LEFT, 
            foreground=self.text_color, 
            background=self.bg_color
        ).pack(anchor=tk.W)
        
        # === MARCO PARA EL "TECLADO LÓGICO" ===
        keypad_frame = ttk.Frame(main_frame, padding="5")
        keypad_frame.pack(pady=5)
        
        # Definimos la cuadrícula de botones
        # Cada tupla: (texto_boton, valor_a_insertar)
        # 'AC' (All Clear) y 'DEL' (borrar último carácter) se tratarán de forma especial
        # '=' llamará a generate_table()
        button_layout = [
            [("AC", "AC"),  ("DEL", "DEL"), ("(", "("),    (")", ")")],
            [("~", " ~ "),  ("^", " ∧ "),   ("v", " ∨ "),   ("->", " -> ")],
            [("p", "p"),    ("q", "q"),     ("↔", " <-> "), ("⊕", " ⊕ ")],
            [("r", "r"),    ("s", "s"),     ("=", "="),     ("", "")],
        ]
        
        for row_idx, row in enumerate(button_layout):
            for col_idx, (label, value) in enumerate(row):
                # Si label está vacío, dejamos un hueco
                if not label:
                    continue
                btn = ttk.Button(
                    keypad_frame, 
                    text=label, 
                    command=lambda l=label, v=value: self.on_keypad_click(l, v),
                    width=4
                )
                btn.grid(row=row_idx, column=col_idx, padx=3, pady=3)
        
        # Frame para la tabla de resultados
        self.result_frame = ttk.Frame(main_frame, padding="5")
        self.result_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Treeview para la tabla de verdad
        self.tree = ttk.Treeview(self.result_frame)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Frame para el estado final (tautología, contradicción, etc.)
        self.status_frame = ttk.Frame(main_frame, padding="5")
        self.status_frame.pack(fill=tk.X, pady=5)
        
        self.status_label = ttk.Label(
            self.status_frame, 
            text="", 
            font=("Arial", 12, "bold"), 
            foreground=self.text_color, 
            background=self.bg_color
        )
        self.status_label.pack(anchor=tk.W)
        
        # Frame para mostrar información de las variables detectadas
        self.var_stats_frame = ttk.Frame(main_frame, padding="5")
        self.var_stats_frame.pack(fill=tk.X, pady=5)
        
        self.var_stats_label = ttk.Label(
            self.var_stats_frame, 
            text="", 
            foreground=self.text_color, 
            background=self.bg_color
        )
        self.var_stats_label.pack(anchor=tk.W)

    # -----------------------------------------------
    #  Funciones de la aplicación
    # -----------------------------------------------
    def on_keypad_click(self, label, value):
        """
        Maneja la pulsación de un botón del “teclado lógico”.
        - AC: borra todo
        - DEL: borra último carácter
        - '=': genera la tabla
        - caso general: inserta 'value' en la expresión
        """
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
        
        # Retornar el foco al Entry para seguir escribiendo
        self.entry_expr.focus_set()

    def extract_variables(self, expr):
        """
        Extrae las variables de la expresión (letras minúsculas a-z).
        """
        var_pattern = re.compile(r'[a-z]')
        vars_found = set(var_pattern.findall(expr))
        return sorted(list(vars_found))

    def generate_subexpressions(self, expr):
        """
        Extrae subexpresiones *entre paréntesis* (para mostrarlas como columnas intermedias).
        No incluye la expresión completa.
        """
        subexpressions = set()
        open_pos = []
        
        for i, char in enumerate(expr):
            if char == '(':
                open_pos.append(i)
            elif char == ')' and open_pos:
                start = open_pos.pop()
                subexpr = expr[start:i+1]
                if len(subexpr) > 2:  # Evitamos paréntesis vacíos
                    subexpressions.add(subexpr)
        
        # Ordenamos por longitud
        subexpr_list = list(subexpressions)
        subexpr_list.sort(key=len)
        return subexpr_list

    def display_bool(self, value):
        """Devuelve 'V' si value es True, 'F' si es False."""
        return "V" if value else "F"
    
    def show_examples(self):
        """
        Muestra una ventana con ejemplos de expresiones lógicas.
        Al hacer clic en un ejemplo, se carga en el Entry principal.
        """
        examples = [
            "p -> q",
            "p ∧ q",
            "p ∨ q",
            "p <-> q",
            "p ^ q",
            "~p",
            "(p->q) ∧ r",
            "(p ∨ q) -> r",
            "p -> (q -> r)",
            "(p -> q) ↔ (~q -> ~p)",
            "(p ∨ q) ∧ ~(p ∧ q)",
            "a ∨ b ∨ c",
            "(w ∧ x) -> (y ∨ z)",
            "(a ↔ b) ∧ (c -> d)"
        ]
        
        examples_window = tk.Toplevel(self.root)
        examples_window.title("Ejemplos de Expresiones")
        examples_window.geometry("400x400")
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
        """Carga el ejemplo seleccionado en el Entry y cierra la ventana de ejemplos."""
        self.expression_var.set(example)
        window.destroy()

    def generate_table(self):
        """
        Genera la tabla de verdad al pulsar el botón:
          1) Extrae variables
          2) Construye AST para la expresión principal
          3) Extrae subexpresiones (entre paréntesis) y también las parsea
          4) Evalúa cada combinación y la muestra en la tabla
          5) Determina si es tautología, contradicción o contingencia
        """
        expression = self.expression_var.get().strip()
        if not expression:
            messagebox.showwarning("Advertencia", "Por favor, ingrese una expresión lógica.")
            return
        
        # 1) Detectar variables
        variables = self.extract_variables(expression)
        if not variables:
            messagebox.showwarning("Advertencia", "No se detectaron variables en la expresión.")
            return
        
        self.var_stats_label.config(
            text=f"Variables detectadas: {', '.join(variables)} ({len(variables)} variables)"
        )
        
        # 2) Parsear la expresión principal para obtener su AST
        try:
            main_ast = parse(expression)
        except ValueError as e:
            messagebox.showerror("Error de parseo", str(e))
            return
        
        # 3) Extraer subexpresiones entre paréntesis y parsearlas también
        subexpr_list = self.generate_subexpressions(expression)
        
        # Creamos un diccionario subexpr->AST
        subexpr_asts = {}
        for subexpr in subexpr_list:
            try:
                subexpr_asts[subexpr] = parse(subexpr)
            except ValueError:
                # Si no se puede parsear algún paréntesis raro, lo ignoramos o marcamos
                subexpr_asts[subexpr] = None
        
        # Añadimos la expresión completa como última "subexpresión"
        subexpr_list.append(expression)
        subexpr_asts[expression] = main_ast
        
        # Limpiamos la tabla anterior
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Configuramos columnas: primero las variables, luego cada subexpresión
        columns = variables + subexpr_list
        self.tree["columns"] = columns
        self.tree["show"] = "headings"
        
        # Encabezados y anchos
        for col in columns:
            self.tree.heading(col, text=col)
            width = max(100, len(col) * 8)
            self.tree.column(col, width=width, anchor=tk.CENTER)
        
        # Todas las combinaciones de valores de verdad
        truth_combinations = list(itertools.product([False, True], repeat=len(variables)))
        
        # Lista para almacenar el resultado final de la expresión principal
        final_results = []
        
        # 4) Evaluar cada combinación
        for combination in truth_combinations:
            # Asignamos valores a las variables en un diccionario
            var_values = dict(zip(variables, combination))
            
            # Primero añadimos las V/F de cada variable
            row_values = [self.display_bool(val) for val in combination]
            
            # Luego evaluamos cada subexpresión
            subexpr_results = []
            for subexpr in subexpr_list:
                ast_node = subexpr_asts[subexpr]
                if ast_node is not None:
                    val = eval_ast(ast_node, var_values)
                    row_values.append(self.display_bool(val))
                    subexpr_results.append(val)
                else:
                    # Si hubo error al parsear esa subexpresión, marcamos con "?"
                    row_values.append("?")
                    subexpr_results.append(None)
            
            # Insertamos la fila en el Treeview
            item_id = self.tree.insert("", tk.END, values=row_values)
            
            # Colorear V/F
            for i, val_str in enumerate(row_values):
                if val_str == "V":
                    tag_true = f"true_{i}"
                    self.tree.tag_configure(tag_true, foreground=self.true_color)
                    self.tree.item(item_id, tags=(tag_true,))
                elif val_str == "F":
                    tag_false = f"false_{i}"
                    self.tree.tag_configure(tag_false, foreground=self.false_color)
                    self.tree.item(item_id, tags=(tag_false,))
            
            # El resultado de la expresión principal es la última subexpresión
            if subexpr_results and subexpr_results[-1] is not None:
                final_results.append(subexpr_results[-1])
        
        # 5) Clasificar la expresión completa (última columna)
        if final_results:
            if all(final_results):
                self.status_label.config(
                    text=f"La expresión '{expression}' es una TAUTOLOGÍA (siempre verdadera)."
                )
            elif not any(final_results):
                self.status_label.config(
                    text=f"La expresión '{expression}' es una CONTRADICCIÓN (siempre falsa)."
                )
            else:
                self.status_label.config(
                    text=f"La expresión '{expression}' es una CONTINGENCIA (a veces verdadera, a veces falsa)."
                )
        else:
            self.status_label.config(
                text="No se pudo determinar el resultado final (revisa la expresión)."
            )

# ==========================================================
# = 3) EJECUCIÓN DE LA APLICACIÓN                         =
# ==========================================================

if __name__ == "__main__":
    root = tk.Tk()
    app = TruthTableGenerator(root)
    root.mainloop()
