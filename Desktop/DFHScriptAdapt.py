import sys
from typing import Dict, Optional

try:
    from sympy.ntheory.residue_ntheory import discrete_log
except ImportError:
    print("Error: sympy library is required. Install with 'pip install sympy'.")
    sys.exit(1)

class DiffieHellmanSolver:
    """
    A class to handle Diffie-Hellman key exchange variable computations.
    It allows input of known variables and infers the missing ones.
    """

    def __init__(self) -> None:
        self.variables: Dict[str, Optional[int]] = {
            'p': None,  # Prime modulus
            'g': None,  # Generator (base)
            'a': None,  # Alice's private key
            'b': None,  # Bob's private key
            'A': None,  # Alice's public key (g^a mod p)
            'B': None,  # Bob's public key (g^b mod p)
            's': None   # Shared secret (A^b mod p or B^a mod p)
        }

    def infer_variables(self) -> None:
        """
        Infers missing variables using modular arithmetic and discrete logarithm where necessary.
        Uses a loop to repeatedly compute until no more changes.
        """
        changed = True
        while changed:
            changed = False

            # Compute public keys from private keys
            if self.variables['A'] is None and all(self.variables[v] is not None for v in ['g', 'a', 'p']):
                self.variables['A'] = pow(self.variables['g'], self.variables['a'], self.variables['p'])
                changed = True

            if self.variables['B'] is None and all(self.variables[v] is not None for v in ['g', 'b', 'p']):
                self.variables['B'] = pow(self.variables['g'], self.variables['b'], self.variables['p'])
                changed = True

            # Compute shared secret from one side
            if self.variables['s'] is None and all(self.variables[v] is not None for v in ['A', 'b', 'p']):
                self.variables['s'] = pow(self.variables['A'], self.variables['b'], self.variables['p'])
                changed = True

            if self.variables['s'] is None and all(self.variables[v] is not None for v in ['B', 'a', 'p']):
                self.variables['s'] = pow(self.variables['B'], self.variables['a'], self.variables['p'])
                changed = True

            # Compute private keys using discrete logarithm (computationally intensive for large p)
            if self.variables['a'] is None and all(self.variables[v] is not None for v in ['A', 'g', 'p']):
                try:
                    self.variables['a'] = discrete_log(self.variables['p'], self.variables['A'], self.variables['g'])
                    changed = True
                except ValueError as e:
                    print(f"Cannot compute Alice's private key 'a': {e}")

            if self.variables['b'] is None and all(self.variables[v] is not None for v in ['B', 'g', 'p']):
                try:
                    self.variables['b'] = discrete_log(self.variables['p'], self.variables['B'], self.variables['g'])
                    changed = True
                except ValueError as e:
                    print(f"Cannot compute Bob's private key 'b': {e}")

            if self.variables['a'] is None and all(self.variables[v] is not None for v in ['s', 'B', 'p']):
                try:
                    self.variables['a'] = discrete_log(self.variables['p'], self.variables['s'], self.variables['B'])
                    changed = True
                except ValueError as e:
                    print(f"Cannot compute Alice's private key 'a' from s and B: {e}")

            if self.variables['b'] is None and all(self.variables[v] is not None for v in ['s', 'A', 'p']):
                try:
                    self.variables['b'] = discrete_log(self.variables['p'], self.variables['s'], self.variables['A'])
                    changed = True
                except ValueError as e:
                    print(f"Cannot compute Bob's private key 'b' from s and A: {e}")

    def check_consistency(self) -> None:
        """
        Checks for consistency in the computed or provided shared secret.
        """
        if all(self.variables[v] is not None for v in ['A', 'b', 'p', 's']):
            computed_s = pow(self.variables['A'], self.variables['b'], self.variables['p'])
            if computed_s != self.variables['s']:
                print("Warning: Inconsistency in shared secret 's' (computed from A^b mod p does not match provided s).")

        if all(self.variables[v] is not None for v in ['B', 'a', 'p', 's']):
            computed_s = pow(self.variables['B'], self.variables['a'], self.variables['p'])
            if computed_s != self.variables['s']:
                print("Warning: Inconsistency in shared secret 's' (computed from B^a mod p does not match provided s).")

    def print_variables(self) -> None:
        """Prints the current state of all variables."""
        print("\nComputed variables:")
        for name, value in self.variables.items():
            print(f"{name}: {value if value is not None else 'Unknown'}")

def main() -> None:
    solver = DiffieHellmanSolver()

    print("Diffie-Hellman Variable Solver")
    print("------------------------------")
    print("This program computes missing Diffie-Hellman variables based on provided values.")
    print("Note: Computing private keys requires solving the discrete logarithm problem,")
    print("which is only feasible for small primes using sympy. Large values may fail or take too long.")
    print("\nValid variable names: p, g, a, b, A, B, s")
    print("Enter one per line in the format 'name value' (e.g., 'p 23').")
    print("Enter a blank line to finish input and start computation.")
    print("Example:")
    print("(public) p 23")
    print("(public) g 5")
    print("(private) a 6")
    print("(private) b 15")
    print("")

    while True:
        try:
            inp = input("> ").strip()
            if not inp:
                break
            name, value_str = inp.split(maxsplit=1)
            if name in solver.variables:
                solver.variables[name] = int(value_str)
            else:
                print(f"Invalid variable name: '{name}'. Valid names: p, g, a, b, A, B, s")
        except ValueError:
            print("Invalid input format. Use 'name value' where value is an integer.")
        except Exception as e:
            print(f"Unexpected error: {e}")

    solver.infer_variables()
    solver.check_consistency()
    solver.print_variables()

if __name__ == "__main__":
    main()