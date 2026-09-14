import tkinter as tk
from tkinter import ttk, messagebox, font
import base64
import secrets
import string
import re

# ── Colours (warm paper palette matching HTML version) ──────────────────────
BG       = "#f5f0e8"
SURFACE  = "#faf7f2"
CARD     = "#fffefa"
BORDER   = "#e2d9cc"
ROSE     = "#c2637a"
ROSE_BG  = "#f9eaee"
SAGE     = "#4a7c6a"
SAGE_BG  = "#e6f2ed"
RED      = "#b83c3c"
AMBER    = "#b5762a"
CYAN     = "#2a8098"
TEXT     = "#2e2318"
MUTED    = "#8a7a68"
FAINT    = "#b8a898"
WHITE    = "#ffffff"

BAR_COLORS   = [RED, AMBER, AMBER, SAGE, SAGE]
STR_LABELS   = ["Very Weak 🔴", "Weak 🟠", "Fair 🟡", "Good 🟢", "Strong 💪"]
COMMON_PWDS  = {"password","123456","qwerty","admin","letmein",
                "welcome","monkey","abc123","iloveyou","dragon"}

# ── Cipher helpers ───────────────────────────────────────────────────────────
def _derive_key(password: str, length: int) -> bytes:
    key, counter = b"", 0
    while len(key) < length:
        chunk = password.encode() + str(counter).encode()
        h = _simple_hash(chunk)
        key += h
        counter += 1
    return key[:length]

def _simple_hash(data: bytes) -> bytes:
    h = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
         0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
    for i, b in enumerate(data):
        h[i % 8] = ((h[i % 8] * 31 + b) & 0xFFFFFFFF)
    out = bytearray()
    for v in h:
        out += v.to_bytes(4, "big")
    return bytes(out)

def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def _pkcs7_pad(data: bytes, block=16) -> bytes:
    n = block - (len(data) % block)
    return data + bytes([n] * n)

def _pkcs7_unpad(data: bytes) -> bytes:
    return data[:-data[-1]]

def _cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    out, prev = b"", iv
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i+16], prev))
        enc = _xor(block, key)
        out += enc; prev = enc
    return out

def _cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    out, prev = b"", iv
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        dec = bytes(a ^ b for a, b in zip(_xor(block, key), prev))
        out += dec; prev = block
    return out

def xor_encrypt(text, key):
    d = text.encode(); k = _derive_key(key, len(d))
    return base64.b64encode(_xor(d, k)).decode()

def xor_decrypt(text, key):
    raw = base64.b64decode(text); k = _derive_key(key, len(raw))
    return _xor(raw, k).decode()

def aes_encrypt(text, key):
    k = _derive_key(key, 16)
    iv = secrets.token_bytes(16)
    cipher = _cbc_encrypt(_pkcs7_pad(text.encode()), k, iv)
    return base64.b64encode(iv + cipher).decode()

def aes_decrypt(text, key):
    raw = base64.b64decode(text)
    iv, cipher = raw[:16], raw[16:]
    k = _derive_key(key, 16)
    return _pkcs7_unpad(_cbc_decrypt(cipher, k, iv)).decode()

def caesar(text, shift):
    res = []
    for ch in text:
        if ch.isalpha():
            base = ord('a') if ch.islower() else ord('A')
            res.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            res.append(ch)
    return "".join(res)

def vigenere(text, key, encrypt):
    key = key.upper(); ki = 0; res = []
    for ch in text:
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            if not encrypt: shift = -shift
            base = ord('a') if ch.islower() else ord('A')
            res.append(chr((ord(ch) - base + shift + 26) % 26 + base))
            ki += 1
        else:
            res.append(ch)
    return "".join(res)

def atbash(text):
    res = []
    for ch in text:
        if ch.isalpha():
            base = ord('a') if ch.islower() else ord('A')
            res.append(chr(base + 25 - (ord(ch) - base)))
        else:
            res.append(ch)
    return "".join(res)

def rail_fence_encrypt(text, rails):
    rows = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for ch in text:
        rows[rail].append(ch)
        if rail == 0: direction = 1
        elif rail == rails - 1: direction = -1
        rail += direction
    return "".join("".join(r) for r in rows)

def rail_fence_decrypt(text, rails):
    n = len(text)
    pattern = []; rail, direction = 0, 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0: direction = 1
        elif rail == rails - 1: direction = -1
        rail += direction
    indices = sorted(range(n), key=lambda i: (pattern[i], i))
    result = [''] * n
    for pos, char in zip(indices, text):
        result[pos] = char
    return "".join(result)

MORSE_ENC = {
    'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---',
    'K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-',
    'U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..','0':'-----','1':'.----','2':'..---',
    '3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.', ' ':'/'
}
MORSE_DEC = {v: k for k, v in MORSE_ENC.items()}

def morse_encode(text): return " ".join(MORSE_ENC.get(c.upper(), '?') for c in text)
def morse_decode(text): return "".join(MORSE_DEC.get(c, '?') for c in text.split())

# ── Password helpers ─────────────────────────────────────────────────────────
def score_password(pw):
    s = 0
    if len(pw) >= 8:  s += 1
    if len(pw) >= 12: s += 1
    if re.search(r'[A-Z]', pw): s += 1
    if re.search(r'[0-9]', pw): s += 1
    if re.search(r'[^A-Za-z0-9]', pw): s += 1
    return s

def analyze_password(pw):
    lines = [
        f"  Length              : {len(pw)} characters",
        f"  Uppercase letters   : {'✓ Present' if re.search(r'[A-Z]', pw) else '✗ Missing'}",
        f"  Lowercase letters   : {'✓ Present' if re.search(r'[a-z]', pw) else '✗ Missing'}",
        f"  Numbers             : {'✓ Present' if re.search(r'[0-9]', pw) else '✗ Missing'}",
        f"  Special symbols     : {'✓ Present' if re.search(r'[^A-Za-z0-9]', pw) else '✗ Missing'}",
        f"  Common password     : {'⚠  YES — very dangerous!' if pw.lower() in COMMON_PWDS else '✓ Not common'}",
        f"  Repeating chars     : {'⚠  Found' if re.search(r'(.)\1{2,}', pw) else '✓ None detected'}",
        f"  Sequential pattern  : {'⚠  Found' if re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde|def)', pw, re.I) else '✓ None detected'}",
        f"  Unique characters   : {len(set(pw))} of {len(pw)}",
        f"  Estimated entropy   : {len(set(pw)) * len(pw)} bits (approx)",
        "",
    ]
    tips = []
    if len(pw) < 8:   tips.append("→ Use at least 8 characters (12+ recommended)")
    elif len(pw) < 12: tips.append("→ Increase to 12+ characters for better security")
    if not re.search(r'[A-Z]', pw): tips.append("→ Add uppercase letters (A–Z)")
    if not re.search(r'[0-9]', pw): tips.append("→ Add numbers (0–9)")
    if not re.search(r'[^A-Za-z0-9]', pw): tips.append("→ Add special characters (!@#$%^&*)")
    if pw.lower() in COMMON_PWDS:    tips.append("→ Never use common passwords!")
    if tips:
        lines.append("  ── TIPS TO IMPROVE ──────────────────")
        lines += ["  " + t for t in tips]
    else:
        lines.append("  ✓  Excellent password! Keep it safe and never share it.")
    return "\n".join(lines)

# ── Main App ─────────────────────────────────────────────────────────────────
class ShieldForge(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ShieldForge")
        self.geometry("860x680")
        self.minsize(700, 560)
        self.configure(bg=BG)
        self._build_nav()
        self._build_home()
        self._build_enc()
        self._build_pwd()
        self._show("home")

    # ── Navigation ──────────────────────────────────────────────────────────
    def _build_nav(self):
        nav = tk.Frame(self, bg=SURFACE, height=48)
        nav.pack(fill="x")
        nav.pack_propagate(False)
        # Logo — clicking always goes home
        tk.Button(nav, text="🛡 ShieldForge", bg=SURFACE, fg=ROSE,
                  font=("Georgia", 13, "bold"), relief="flat", bd=0,
                  activebackground=SURFACE, cursor="hand2",
                  command=lambda: self._show("home")).pack(side="left", padx=18)
        # Back button — only visible when inside a tool page
        self._back_btn = tk.Button(nav, text="← Home", bg=SURFACE, fg=MUTED,
                                   font=("Georgia", 11), relief="flat", bd=0,
                                   activebackground=CARD, cursor="hand2",
                                   command=lambda: self._show("home"))
        self._tabs = {}
        tk.Frame(nav, bg=BORDER, height=1).pack(fill="x", side="bottom")

    def _show(self, name):
        for n, f in self._frames.items():
            f.pack_forget()
        self._frames[name].pack(fill="both", expand=True)
        # Show back button only when not on home
        if name == "home":
            self._back_btn.pack_forget()
        else:
            self._back_btn.pack(side="left", padx=2, pady=8, ipady=2, ipadx=8)

    # ── Reusable widget helpers ──────────────────────────────────────────────
    def _card(self, parent, label=None, pady=(0,8)):
        outer = tk.Frame(parent, bg=BG)
        outer.pack(fill="x", pady=pady)
        box = tk.Frame(outer, bg=CARD, highlightbackground=BORDER,
                       highlightthickness=1)
        box.pack(fill="x", padx=0)
        if label:
            tk.Label(box, text=label.upper(), bg=CARD, fg=FAINT,
                     font=("Georgia", 8, "bold")).pack(anchor="w", padx=14, pady=(10,4))
        return box

    def _entry(self, parent, show=None, font_=("Courier New",11)):
        e = tk.Entry(parent, bg=SURFACE, fg=TEXT, insertbackground=TEXT,
                     relief="flat", highlightbackground=BORDER,
                     highlightthickness=1, font=font_, show=show or "")
        return e

    def _btn(self, parent, text, cmd, color=TEXT, bg=SURFACE):
        return tk.Button(parent, text=text, command=cmd, bg=bg, fg=color,
                         font=("Georgia", 10, "bold"), relief="flat",
                         activebackground=BORDER, cursor="hand2",
                         padx=12, pady=4)

    def _textarea(self, parent, height=5, readonly=False):
        t = tk.Text(parent, bg=SURFACE, fg=TEXT, insertbackground=TEXT,
                    relief="flat", highlightbackground=BORDER,
                    highlightthickness=1, font=("Courier New",11),
                    height=height, wrap="word")
        if readonly:
            t.config(state="disabled", bg=CARD)
        return t

    # ── Home page ───────────────────────────────────────────────────────────
    def _build_home(self):
        self._frames = {}
        f = tk.Frame(self, bg=BG)
        self._frames["home"] = f

        inner = tk.Frame(f, bg=BG)
        inner.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(inner, text="🛡", font=("", 52), bg=BG).pack(pady=(0, 6))
        tk.Label(inner, text="ShieldForge", font=("Georgia", 34, "bold"),
                 bg=BG, fg=ROSE).pack(pady=(0, 40))

        row = tk.Frame(inner, bg=BG)
        row.pack()
        for icon, label, desc, name, color in [
            ("🔐", "Text Encryption",   "9 cipher algorithms", "enc", ROSE),
            ("🔑", "Password Analyzer", "Strength and generator", "pwd", SAGE),
        ]:
            card = tk.Frame(row, bg=CARD, highlightbackground=BORDER,
                            highlightthickness=1)
            card.pack(side="left", padx=16, pady=8, ipadx=24, ipady=16)
            tk.Label(card, text=icon, font=("", 30), bg=CARD).pack(pady=(14, 4))
            tk.Label(card, text=label, font=("Georgia", 13, "bold"),
                     bg=CARD, fg=color).pack()
            tk.Label(card, text=desc, font=("Georgia", 10, "italic"),
                     bg=CARD, fg=MUTED).pack(pady=(2, 14))
            tk.Button(card, text="Open →", bg=color, fg=WHITE,
                      font=("Georgia", 10, "bold"), relief="flat",
                      cursor="hand2", padx=18, pady=6,
                      activebackground=color, activeforeground=WHITE,
                      command=lambda n=name: self._show(n)).pack(pady=(0, 14))

    # ── Encryption page ──────────────────────────────────────────────────────
    ALGOS = [
        ("XOR + Base64", "Bitwise XOR with Base64 output. Fast and key-based."),
        ("AES-CBC",      "AES-style CBC block cipher. Industry-standard approach."),
        ("Caesar",       "Shifts each letter by N positions. Classic substitution cipher."),
        ("Vigenère",     "Polyalphabetic cipher using a repeating keyword."),
        ("Atbash",       "Reverses the alphabet. A↔Z, B↔Y — no key needed."),
        ("ROT13",        "Rotates letters by 13. Symmetric — encrypt equals decrypt."),
        ("Rail Fence",   "Zigzag transposition cipher using multiple rails."),
        ("Base64",       "Encodes text to Base64 format. Encoding, not encryption."),
        ("Morse Code",   "Converts text to dots and dashes. Classic telegraph cipher."),
    ]
    KEYLESS = {"Atbash","ROT13","Base64","Morse Code"}

    def _build_enc(self):
        outer = tk.Frame(self, bg=BG)
        self._frames["enc"] = outer

        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        f = tk.Frame(canvas, bg=BG)
        win = canvas.create_window((0,0), window=f, anchor="nw")

        def _resize(e):
            canvas.itemconfig(win, width=e.width)
        def _scroll(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        canvas.bind("<Configure>", _resize)
        f.bind("<Configure>", _scroll)
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(-1*(e.delta//120),"units"))

        inner = tk.Frame(f, bg=BG, padx=40)
        inner.pack(fill="x", pady=20)

        tk.Label(inner, text="🔐 Text Encryption", font=("Georgia",18,"bold"),
                 bg=BG, fg=ROSE).pack(anchor="w", pady=(0,2))
        tk.Label(inner, text="9 cipher algorithms to encrypt and decrypt any text securely.",
                 font=("Georgia",10,"italic"), bg=BG, fg=MUTED).pack(anchor="w", pady=(0,16))

        # Algorithm picker
        algo_card = self._card(inner, "Algorithm")
        self._algo_var = tk.StringVar(value="XOR + Base64")
        self._algo_desc_var = tk.StringVar()
        grid = tk.Frame(algo_card, bg=CARD)
        grid.pack(fill="x", padx=14, pady=(0,6))
        self._algo_btns = {}
        for i, (name, _) in enumerate(self.ALGOS):
            b = tk.Button(grid, text=name, bg=SURFACE, fg=MUTED,
                          font=("Georgia",9), relief="flat",
                          highlightbackground=BORDER, highlightthickness=1,
                          cursor="hand2", padx=10, pady=4,
                          command=lambda n=name: self._select_algo(n))
            b.grid(row=i//5, column=i%5, padx=3, pady=3, sticky="w")
            self._algo_btns[name] = b
        tk.Label(algo_card, textvariable=self._algo_desc_var,
                 bg=CARD, fg=MUTED, font=("Georgia",9,"italic"),
                 anchor="w").pack(anchor="w", padx=14, pady=(0,10))

        # Container for all optional param cards (same parent = safe show/hide)
        self._param_container = tk.Frame(inner, bg=BG)
        self._param_container.pack(fill="x")

        def _pcard(label):
            outer = tk.Frame(self._param_container, bg=BG)
            box = tk.Frame(outer, bg=CARD, highlightbackground=BORDER,
                           highlightthickness=1)
            box.pack(fill="x")
            tk.Label(box, text=label.upper(), bg=CARD, fg=FAINT,
                     font=("Georgia", 8, "bold")).pack(anchor="w", padx=14, pady=(10,4))
            return outer, box

        # Key card
        self._key_frame, key_box = _pcard("Key / Password")
        key_row = tk.Frame(key_box, bg=CARD)
        key_row.pack(fill="x", padx=14, pady=(0,10))
        self._enc_key = self._entry(key_row, show="●")
        self._enc_key.pack(side="left", fill="x", expand=True, ipady=5)
        self._show_key = False
        self._btn(key_row, "👁 Show", self._toggle_key).pack(side="left", padx=(6,0))
        self._btn(key_row, "⚡ Gen", self._gen_key, color=ROSE).pack(side="left", padx=(4,0))

        # Caesar shift
        self._caesar_frame, caesar_box = _pcard("Caesar Shift")
        cr = tk.Frame(caesar_box, bg=CARD)
        cr.pack(fill="x", padx=14, pady=(0,10))
        tk.Label(cr, text="Shift value (1–25)", bg=CARD, fg=MUTED,
                 font=("Georgia",10)).pack(side="left")
        self._shift_var = tk.IntVar(value=3)
        tk.Spinbox(cr, from_=1, to=25, textvariable=self._shift_var,
                   width=5, bg=SURFACE, relief="flat",
                   font=("Courier New",11)).pack(side="left", padx=8)

        # Rail fence
        self._rail_frame, rail_box = _pcard("Rail Fence Rails")
        rr = tk.Frame(rail_box, bg=CARD)
        rr.pack(fill="x", padx=14, pady=(0,10))
        tk.Label(rr, text="Number of rails (2–10)", bg=CARD, fg=MUTED,
                 font=("Georgia",10)).pack(side="left")
        self._rail_var = tk.IntVar(value=3)
        tk.Spinbox(rr, from_=2, to=10, textvariable=self._rail_var,
                   width=5, bg=SURFACE, relief="flat",
                   font=("Courier New",11)).pack(side="left", padx=8)

        # Input
        inp_card = self._card(inner, "Input Text")
        self._enc_input = self._textarea(inp_card)
        self._enc_input.pack(fill="x", padx=14, pady=(0,10), ipady=2)

        # Buttons
        btn_row = tk.Frame(inner, bg=BG)
        btn_row.pack(fill="x", pady=4)
        self._btn(btn_row,"🔒 Encrypt", lambda: self._run_enc("encrypt"), WHITE, ROSE).pack(side="left",padx=(0,6))
        self._btn(btn_row,"🔓 Decrypt", lambda: self._run_enc("decrypt")).pack(side="left",padx=(0,6))
        self._btn(btn_row,"🔄 Swap",    self._swap_io, CYAN).pack(side="left",padx=(0,6))
        self._btn(btn_row,"📋 Copy",    self._copy_output, SAGE).pack(side="left",padx=(0,6))
        self._btn(btn_row,"🗑 Clear",   self._clear_enc, RED).pack(side="left")

        # Output
        out_card = self._card(inner, "Output")
        self._enc_output = self._textarea(out_card, readonly=True)
        self._enc_output.pack(fill="x", padx=14, pady=(0,10), ipady=2)

        # Status
        self._enc_status_var = tk.StringVar(value="Ready — select an algorithm and enter text")
        tk.Label(inner, textvariable=self._enc_status_var, bg=BG, fg=MUTED,
                 font=("Georgia",9,"italic"), anchor="w").pack(anchor="w", pady=(4,0))

        self._select_algo("XOR + Base64")

    def _select_algo(self, name):
        self._algo_var.set(name)
        desc = next((d for n, d in self.ALGOS if n == name), "")
        self._algo_desc_var.set(f"  ℹ  {desc}")
        for n, b in self._algo_btns.items():
            if n == name:
                b.config(bg=ROSE_BG, fg=ROSE, font=("Georgia",9,"bold"))
            else:
                b.config(bg=SURFACE, fg=MUTED, font=("Georgia",9))
        keyless = name in self.KEYLESS
        is_caesar = name == "Caesar"
        is_rail = name == "Rail Fence"
        # Hide all first, then show what's needed (all share same parent)
        self._key_frame.pack_forget()
        self._caesar_frame.pack_forget()
        self._rail_frame.pack_forget()
        if not keyless and not is_caesar and not is_rail:
            self._key_frame.pack(fill="x", pady=(0,8))
        if is_caesar:
            self._caesar_frame.pack(fill="x", pady=(0,8))
        if is_rail:
            self._rail_frame.pack(fill="x", pady=(0,8))

    def _toggle_key(self):
        self._show_key = not self._show_key
        self._enc_key.config(show="" if self._show_key else "●")

    def _gen_key(self):
        chars = string.ascii_letters + string.digits + "!@#$%"
        key = "".join(secrets.choice(chars) for _ in range(18))
        self._enc_key.delete(0, "end")
        self._enc_key.insert(0, key)
        self._enc_key.config(show="")
        self._show_key = True

    def _set_status(self, msg, color=MUTED):
        self._enc_status_var.set(msg)

    def _set_output(self, text):
        self._enc_output.config(state="normal")
        self._enc_output.delete("1.0", "end")
        self._enc_output.insert("1.0", text)
        self._enc_output.config(state="disabled")

    def _run_enc(self, mode):
        text = self._enc_input.get("1.0", "end").strip()
        key  = self._enc_key.get()
        algo = self._algo_var.get()
        shift = self._shift_var.get()
        rails = self._rail_var.get()
        if not text:
            self._set_status("⚠  Enter some text first."); return
        try:
            if algo == "XOR + Base64":
                if not key: self._set_status("⚠  Enter a key."); return
                result = xor_encrypt(text, key) if mode=="encrypt" else xor_decrypt(text, key)
            elif algo == "AES-CBC":
                if not key: self._set_status("⚠  Enter a key."); return
                result = aes_encrypt(text, key) if mode=="encrypt" else aes_decrypt(text, key)
            elif algo == "Caesar":
                result = caesar(text, shift if mode=="encrypt" else -shift)
            elif algo == "Vigenère":
                if not key: self._set_status("⚠  Enter a keyword."); return
                if not re.match(r'^[a-zA-Z]+$', key):
                    self._set_status("⚠  Vigenère key must be letters only."); return
                result = vigenere(text, key, mode=="encrypt")
            elif algo == "Atbash":
                result = atbash(text)
            elif algo == "ROT13":
                result = caesar(text, 13)
            elif algo == "Rail Fence":
                result = rail_fence_encrypt(text, rails) if mode=="encrypt" else rail_fence_decrypt(text, rails)
            elif algo == "Base64":
                result = base64.b64encode(text.encode()).decode() if mode=="encrypt" else base64.b64decode(text).decode()
            elif algo == "Morse Code":
                result = morse_encode(text) if mode=="encrypt" else morse_decode(text)
            else:
                result = ""
            self._set_output(result)
            action = "Encrypted" if mode == "encrypt" else "Decrypted"
            self._set_status(f"✓  {action} with {algo}")
        except Exception as e:
            self._set_status(f"Error: {e}")

    def _swap_io(self):
        inp = self._enc_input.get("1.0","end").strip()
        out = self._enc_output.get("1.0","end").strip()
        self._enc_input.delete("1.0","end"); self._enc_input.insert("1.0", out)
        self._set_output(inp)

    def _copy_output(self):
        out = self._enc_output.get("1.0","end").strip()
        if out:
            self.clipboard_clear(); self.clipboard_append(out)
            self._set_status("✓ Copied to clipboard!")

    def _clear_enc(self):
        self._enc_input.delete("1.0","end")
        self._set_output("")
        self._set_status("Cleared.")

    # ── Password page ────────────────────────────────────────────────────────
    def _build_pwd(self):
        outer = tk.Frame(self, bg=BG)
        self._frames["pwd"] = outer

        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        f = tk.Frame(canvas, bg=BG)
        win = canvas.create_window((0,0), window=f, anchor="nw")

        def _resize(e): canvas.itemconfig(win, width=e.width)
        def _scroll(e): canvas.configure(scrollregion=canvas.bbox("all"))
        canvas.bind("<Configure>", _resize)
        f.bind("<Configure>", _scroll)
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(-1*(e.delta//120),"units"))

        inner = tk.Frame(f, bg=BG, padx=40)
        inner.pack(fill="x", pady=20)

        tk.Label(inner, text="🔑 Password Analyzer", font=("Georgia",18,"bold"),
                 bg=BG, fg=SAGE).pack(anchor="w", pady=(0,2))
        tk.Label(inner, text="Evaluate strength, detect weaknesses, and generate secure passwords.",
                 font=("Georgia",10,"italic"), bg=BG, fg=MUTED).pack(anchor="w", pady=(0,16))

        # Input
        pwd_card = self._card(inner, "Enter Password")
        pwd_row = tk.Frame(pwd_card, bg=CARD)
        pwd_row.pack(fill="x", padx=14, pady=(0,10))
        self._pwd_input = self._entry(pwd_row, show="●")
        self._pwd_input.pack(side="left", fill="x", expand=True, ipady=5)
        self._pwd_input.bind("<KeyRelease>", lambda e: self._analyze_pwd())
        self._show_pwd = False
        self._btn(pwd_row,"👁 Show", self._toggle_pwd).pack(side="left", padx=(6,0))

        # Strength bars
        str_card = self._card(inner, "Strength Meter")
        bar_row = tk.Frame(str_card, bg=CARD)
        bar_row.pack(fill="x", padx=14, pady=(0,6))
        self._bars = []
        for _ in range(5):
            b = tk.Frame(bar_row, bg=BORDER, height=8, width=80)
            b.pack(side="left", padx=3, pady=2)
            b.pack_propagate(False)
            self._bars.append(b)
        self._str_label_var = tk.StringVar(value="Enter a password")
        tk.Label(str_card, textvariable=self._str_label_var, bg=CARD, fg=MUTED,
                 font=("Georgia",11,"bold")).pack(anchor="w", padx=14, pady=(0,10))

        # Analysis
        ana_card = self._card(inner, "Detailed Analysis")
        self._analysis_box = tk.Text(ana_card, bg=SURFACE, fg=TEXT, relief="flat",
                                      highlightbackground=BORDER, highlightthickness=1,
                                      font=("Courier New",10), height=12, wrap="word",
                                      state="disabled", padx=8, pady=6)
        self._analysis_box.pack(fill="x", padx=14, pady=(0,10))

        # Generator
        gen_card = self._card(inner, "Generate Strong Password")
        gen_opts = tk.Frame(gen_card, bg=CARD)
        gen_opts.pack(fill="x", padx=14, pady=(0,8))

        tk.Label(gen_opts, text="Length:", bg=CARD, fg=MUTED,
                 font=("Georgia",10)).pack(side="left")
        self._gen_len = tk.IntVar(value=16)
        tk.Spinbox(gen_opts, from_=8, to=64, textvariable=self._gen_len,
                   width=4, bg=SURFACE, relief="flat",
                   font=("Courier New",11)).pack(side="left", padx=(4,16))

        self._use_upper = tk.BooleanVar(value=True)
        self._use_num   = tk.BooleanVar(value=True)
        self._use_sym   = tk.BooleanVar(value=True)
        for text, var in [("Uppercase", self._use_upper),
                          ("Numbers",   self._use_num),
                          ("Symbols",   self._use_sym)]:
            tk.Checkbutton(gen_opts, text=text, variable=var, bg=CARD, fg=MUTED,
                           font=("Georgia",10), activebackground=CARD,
                           selectcolor=SAGE_BG).pack(side="left", padx=6)

        gen_row = tk.Frame(gen_card, bg=CARD)
        gen_row.pack(fill="x", padx=14, pady=(0,10))
        self._gen_out = self._entry(gen_row)
        self._gen_out.pack(side="left", fill="x", expand=True, ipady=5)
        self._gen_out.config(state="readonly", bg=CARD)
        self._btn(gen_row,"⚡ Generate", self._generate_pwd, WHITE, SAGE).pack(side="left", padx=(6,0))
        self._btn(gen_row,"📋 Copy",     self._copy_gen_pwd, SAGE).pack(side="left", padx=(4,0))

    def _toggle_pwd(self):
        self._show_pwd = not self._show_pwd
        self._pwd_input.config(show="" if self._show_pwd else "●")

    def _analyze_pwd(self):
        pw = self._pwd_input.get()
        s  = score_password(pw) if pw else 0
        for i, bar in enumerate(self._bars):
            bar.config(bg=BAR_COLORS[i] if i < s else BORDER)
        if pw and s > 0:
            self._str_label_var.set(STR_LABELS[s-1])
        else:
            self._str_label_var.set("Enter a password")
        self._analysis_box.config(state="normal")
        self._analysis_box.delete("1.0","end")
        if pw:
            self._analysis_box.insert("1.0", analyze_password(pw))
        else:
            self._analysis_box.insert("1.0","Enter a password above to see analysis.")
        self._analysis_box.config(state="disabled")

    def _generate_pwd(self):
        length = max(8, min(64, self._gen_len.get()))
        chars  = string.ascii_lowercase
        if self._use_upper.get(): chars += string.ascii_uppercase
        if self._use_num.get():   chars += string.digits
        if self._use_sym.get():   chars += "!@#$%^&*()-_=+"
        pw = "".join(secrets.choice(chars) for _ in range(length))
        self._gen_out.config(state="normal")
        self._gen_out.delete(0,"end")
        self._gen_out.insert(0, pw)
        self._gen_out.config(state="readonly")
    def _copy_gen_pwd(self):
        pw = self._gen_out.get()
        if pw:
            self.clipboard_clear(); self.clipboard_append(pw)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

if __name__ == "__main__":
    app = ShieldForge()
    app.mainloop()