# main.py
"""
Entry point for the Serpent tkinter application.

Python: 3.9.12
Run:
    python main.py
"""

from __future__ import annotations

import tkinter as tk

from app import create_app


def main() -> None:
    root = tk.Tk()
    create_app(root)
    root.mainloop()


if __name__ == "__main__":
    main()
