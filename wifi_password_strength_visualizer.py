
# WiFi Password Tester - GUI Tool
# Created for Cybersecurity coursework
# Analyzes password strength using entropy, feedback, and crack-time

import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
import string, math, re, secrets

# Calculates how random (unpredictable) a password is
def entropy_calc(pwd):
    charset = 0
    if any(ch.islower() for ch in pwd): charset += 26
    if any(ch.isupper() for ch in pwd): charset += 26
    if any(ch.isdigit() for ch in pwd): charset += 10
    if any(ch in string.punctuation for ch in pwd): charset += len(string.punctuation)
    if charset == 0: return 0
    return round(len(pwd) * math.log2(charset))

# Figures out how long it might take to crack the password
def cracktime(bits):
    guesses_per_sec = 10**9
    total_secs = 2 ** bits / guesses_per_sec

    if total_secs < 60:
        return f"{int(total_secs)} seconds"
    elif total_secs < 3600:
        return f"{int(total_secs//60)} mins"
    elif total_secs < 86400:
        return f"{int(total_secs//3600)} hrs"
    elif total_secs < 31536000:
        return f"{int(total_secs//86400)} days"
    else:
        return f"{int(total_secs//31536000)} yrs"

# Checks how strong the given password is
def rate_password(pwd):
    points = 0
    tips = []

    # basic length check
    if len(pwd) >= 12:
        points += 2
    elif len(pwd) >= 8:
        points += 1
    else:
        tips.append("Try using at least 8 characters.")

    # letter variety checks
    if any(c.islower() for c in pwd): points += 1
    else: tips.append("No lowercase letters.")

    if any(c.isupper() for c in pwd): points += 1
    else: tips.append("No uppercase letters.")

    if any(c.isdigit() for c in pwd): points += 1
    else: tips.append("No numbers.")

    if any(c in string.punctuation for c in pwd): points += 1
    else: tips.append("No symbols.")

    # repeated characters check (not ideal)
    if re.search(r'(.)\1{2,}', pwd):
        tips.append("Too many repeated characters.")

    # decide label and color
    level = "Weak"
    clr = "red"
    if points >= 7:
        level = "Strong"; clr = "green"
    elif points >= 5:
        level = "Okay"; clr = "orange"

    entropy_val = entropy_calc(pwd)
    crack_time = cracktime(entropy_val)
    return level, clr, entropy_val, crack_time, tips

# This shows a meter chart to visualize entropy score
def show_gauge(entropy_val, colr):
    fig, ax = plt.subplots()
    slice_angle = min(entropy_val, 100) * 180 / 100
    ax.pie([slice_angle, 180 - slice_angle], startangle=180, colors=[colr, "#dddddd"], radius=1.3)
    ax.add_artist(plt.Circle((0, 0), 0.75, color='white'))
    ax.text(0, -0.1, f"Entropy\n{entropy_val} bits", ha='center', va='center', fontsize=14)
    plt.title("Password Strength Gauge")
    ax.set_aspect('equal')
    plt.show()

# This runs when user clicks Check or hits Enter
def analyze_pwd():
    val = input_box.get()
    if val.strip() == "":
        messagebox.showwarning("Oops!", "Please type something first.")
        return

    label, clr, bits, time, adv = rate_password(val)
    out_strength.config(text=f"Strength: {label}", foreground=clr)
    out_entropy.config(text=f"Entropy: {bits} bits")
    out_crack.config(text=f"Crack Time: {time}")

    feedback_area.config(state='normal')
    feedback_area.delete(1.0, tk.END)
    if adv:
        feedback_area.insert(tk.END, "\n".join(f"- {a}" for a in adv))
    else:
        feedback_area.insert(tk.END, "Nice! This looks strong.")
    feedback_area.config(state='disabled')

    show_gauge(bits, clr)

# Generates a secure password
def make_strong_pwd():
    chars = string.ascii_letters + string.digits + string.punctuation
    new_pwd = ''.join(secrets.choice(chars) for _ in range(16))
    input_box.delete(0, tk.END)
    input_box.insert(0, new_pwd)

# Show/hide typed password
def toggle_see():
    if show_var.get():
        input_box.config(show='')
    else:
        input_box.config(show='*')

# ================= GUI SETUP ===================

win = tk.Tk()
win.title("Wi-Fi Password Tester")
win.geometry("500x400")
win.resizable(False, False)

ttk.Label(win, text="Enter Password:", font=("Segoe UI", 12)).pack(pady=10)
input_box = ttk.Entry(win, width=40, show='*', font=("Segoe UI", 12))
input_box.pack(pady=5)

show_var = tk.BooleanVar()
show_cb = ttk.Checkbutton(win, text="Show Password", variable=show_var, command=toggle_see)
show_cb.pack()

ttk.Button(win, text="Check Strength", command=analyze_pwd).pack(pady=5)
ttk.Button(win, text="Generate Strong Password", command=make_strong_pwd).pack(pady=5)

out_strength = ttk.Label(win, text="Strength: ", font=("Segoe UI", 12))
out_strength.pack(pady=5)
out_entropy = ttk.Label(win, text="Entropy: ", font=("Segoe UI", 10))
out_entropy.pack()
out_crack = ttk.Label(win, text="Crack Time: ", font=("Segoe UI", 10))
out_crack.pack()

ttk.Label(win, text="Tips / Feedback:", font=("Segoe UI", 10, "bold")).pack(pady=(10, 2))
feedback_area = tk.Text(win, height=4, width=50, wrap='word', state='disabled', font=("Segoe UI", 10))
feedback_area.pack()

# Bind enter key to trigger analysis
win.bind('<Return>', lambda evt: analyze_pwd())

win.mainloop()
