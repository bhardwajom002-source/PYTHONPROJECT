import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

# ============================
# Main Class (Controller)
# ============================
class MultiPageApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("School Management System")
        self.geometry("900x550")

        # Container for all pages
        container = tk.Frame(self)
        container.pack(fill="both", expand=True)

        self.frames = {}

        for F in (HomePage, TeacherPage, StudentPage):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show(HomePage)

    def show(self, page):
        frame = self.frames[page]
        frame.tkraise()

# ============================
# PAGE 1 — Home Page
# ============================
class HomePage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)

        tk.Label(self, text="School Management System", font=("Arial", 26, "bold")).pack(pady=40)

        ttk.Button(self, text="Teacher Data Page", width=30,
                   command=lambda: controller.show(TeacherPage)).pack(pady=10)

        ttk.Button(self, text="Student Data Page", width=30,
                   command=lambda: controller.show(StudentPage)).pack(pady=10)

# ============================
# PAGE 2 — Teacher Data Page
# ============================
class TeacherPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)

        tk.Label(self, text="Teacher Data", font=("Arial", 22, "bold")).pack(pady=10)

        form = tk.Frame(self)
        form.pack()

        labels = ["Teacher ID", "Name", "Subject", "Salary (₹)", "Phone"]
        self.entries = {}

        for i, label in enumerate(labels):
            tk.Label(form, text=label, font=("Arial", 12)).grid(row=i, column=0, sticky="w", pady=5)
            ent = tk.Entry(form, width=40)
            ent.grid(row=i, column=1, pady=5)
            self.entries[label] = ent

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Add", command=self.add_record).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Delete Selected", command=self.delete_record).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="Clear", command=self.clear_entries).grid(row=0, column=2, padx=5)

        ttk.Button(self, text="Back to Home", command=lambda: controller.show(HomePage)).pack(pady=5)

        # Treeview Table
        self.tree = ttk.Treeview(self, columns=("ID", "Name", "Subject", "Salary", "Phone"), show="headings")
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        self.tree.pack(fill="both", expand=True, pady=10)

    def add_record(self):
        data = [self.entries[k].get().strip() for k in self.entries]

        if any(x == "" for x in data):
            messagebox.showwarning("Missing Data", "Please fill all fields.")
            return
        
        self.tree.insert("", tk.END, values=data)
        self.clear_entries()

    def delete_record(self):
        selected = self.tree.selection()
        for item in selected:
            self.tree.delete(item)

    def clear_entries(self):
        for ent in self.entries.values():
            ent.delete(0, tk.END)

# ============================
# PAGE 3 — Student Data Page
# ============================
class StudentPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)

        tk.Label(self, text="Student Data", font=("Arial", 22, "bold")).pack(pady=10)

        form = tk.Frame(self)
        form.pack()

        labels = ["Roll No", "Name", "Class", "Fees (₹)", "Phone"]
        self.entries = {}

        for i, label in enumerate(labels):
            tk.Label(form, text=label, font=("Arial", 12)).grid(row=i, column=0, sticky="w", pady=5)
            ent = tk.Entry(form, width=40)
            ent.grid(row=i, column=1, pady=5)
            self.entries[label] = ent

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Add", command=self.add_record).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Delete Selected", command=self.delete_record).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="Clear", command=self.clear_entries).grid(row=0, column=2, padx=5)

        ttk.Button(self, text="Back to Home", command=lambda: controller.show(HomePage)).pack(pady=5)

        # Table
        self.tree = ttk.Treeview(self, columns=("Roll", "Name", "Class", "Fees", "Phone"), show="headings")
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        self.tree.pack(fill="both", expand=True, pady=10)

    def add_record(self):
        data = [self.entries[k].get().strip() for k in self.entries]

        if any(x == "" for x in data):
            messagebox.showwarning("Missing Data", "All fields required!")
            return
        
        self.tree.insert("", tk.END, values=data)
        self.clear_entries()

    def delete_record(self):
        selected = self.tree.selection()
        for item in selected:
            self.tree.delete(item)

    def clear_entries(self):
        for ent in self.entries.values():
            ent.delete(0, tk.END)

# ============================
# RUN THE APP
# ============================
if __name__ == "__main__":
    app = MultiPageApp()
    app.mainloop()
