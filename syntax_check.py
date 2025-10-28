import ast
import sys

def check_syntax(file_path):
    try:
        with open(file_path, 'r') as file:
            source = file.read()
        ast.parse(source)
        print("Syntax check passed")
        return True
    except SyntaxError as e:
        print(f"Syntax error in {file_path}:")
        print(f"Line {e.lineno}: {e.text}")
        print(f"Error: {e.msg}")
        return False
    except Exception as e:
        print(f"Error checking syntax: {e}")
        return False

if __name__ == "__main__":
    check_syntax("app.py")