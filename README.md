# PA&T-Symbolic-Execution
Project: 2021SP-COSC6386-Program Analysis & Testing \
Task: Write a symbolic fuzzer that can generate input values symbolically for a python function.

- - -

# Library:
- Python 3.7.3
- z3-solver==4.8.10.0

- - -

# Final Project Guidelines:

•	Write a symbolic fuzzer that can generate input values symbolically for a python function. We assume that the function is not recursive and at most calls two self-contained methods. We can assume that all variables are annotated with the type information, and only container used in the programs are lists with the maximum size 10.

•	The key idea is as follows: We traverse through the control flow graph from the entry point, and generate all possible paths to a given depth. Then we collect constraints that we encountered along the path, and generate inputs that will traverse the program up to that point.

•	The tool should

    1-Generate and print the path constraints in the program.
    2-Each constraint should be traceable to the part of code that created the constraint.
    3-If a path is unsatisfiable, the fuzzer should generate the corresponding unsat core and the statements that it belongs to.

•	You can use the symbolic fuzzer is available at https://www.fuzzingbook.org/html/SymbolicFuzzer.html as the basis for your tool.

- - -

# How to use the Fuzzer:

There is a *main.sh* file that can be used to run the fuzzer from the command line.

    $ source main.sh

Sample files are kept into *‘examples/’* folder, and results are saved into *‘outputs/’* folder.

To individually run, use:

    $ python3 run_simple_symfz.py
    $ python3 run_advance_symfz.py

We tested our tool with Python 3.7.3. Dependency (i.e. Z3-solver version) are listed into requirements.txt file:

	  $ python3 -m pip install -r requirements.txt


- - -

# Sample Output:

     check_triangle.py
     ------------------

    def check_triangle(a: int, b: int, c: int) -> int:
        if a == b:
            if a == c:
                if b == c:
                    return "Equilateral"
                else:
                    return "Isosceles"
            else:
                return "Isosceles"
        else:
            if b != c:
                if a == c:
                    return "Isosceles"
                else:
                    return "Scalene"
            else:
                return "Isosceles"


     Number of paths: 6 
     ------------------ 
    
        Path-1: [1, 2, 3, 4, 5]
        Path-2: [1, 2, 3, 4, 7]
        Path-3: [1, 2, 3, 9]
        Path-4: [1, 2, 11, 12, 13]
        Path-5: [1, 2, 11, 12, 15]
        Path-6: [1, 2, 11, 17]
    
    
     Constraints with Traces in File: 
     -------------------------------- 
    
        Path-1:
            Constraint: ['(a == b)', '(a == c)', '(b == c)']
            Trace in File: [{'line': '2', 'col': '7'}, {'line': '3', 'col': '11'}, {'line': '4', 'col': '15'}]
    
        Path-2:
            Constraint: ['(a == b)', '(a == c)', 'z3.Not(b == c)']
            Trace in File: [{'line': '2', 'col': '7'}, {'line': '3', 'col': '11'}, {'line': '4', 'col': '15'}]
    
        Path-3:
            Constraint: ['(a == b)', 'z3.Not(a == c)']
            Trace in File: [{'line': '2', 'col': '7'}, {'line': '3', 'col': '11'}]
    
        Path-4:
            Constraint: ['z3.Not(a == b)', '(b != c)', '(a == c)']
            Trace in File: [{'line': '2', 'col': '7'}, {'line': '11', 'col': '11'}, {'line': '12', 'col': '15'}]
    
        Path-5:
            Constraint: ['z3.Not(a == b)', '(b != c)', 'z3.Not(a == c)']
            Trace in File: [{'line': '2', 'col': '7'}, {'line': '11', 'col': '11'}, {'line': '12', 'col': '15'}]
    
        Path-6:
            Constraint: ['z3.Not(a == b)', 'z3.Not(b != c)']
            Trace in File: [{'line': '2', 'col': '7'}, {'line': '11', 'col': '11'}]
    
    
     Unsat Core: 
     ----------- 
     
         <bound method Solver.unsat_core of [Not(And(a == 2, b == 2, c == 2)), a == b, a == c, Not(b == c)]>
    
    
     Solve Path Constraint: 
     ---------------------- 
    
        Path-1:
            Constraint: ['(a == b)', '(a == c)', '(b == c)']
            Solve: {'a': 2, 'b': 2, 'c': 2}
    
        Path-2:
            Constraint: ['(a == b)', '(a == c)', 'z3.Not(b == c)']
            Solve: Unsatisfiable, No Solution!
    
        Path-3:
            Constraint: ['(a == b)', 'z3.Not(a == c)']
            Solve: {'a': 3, 'b': 3, 'c': 4}
    
        Path-4:
            Constraint: ['z3.Not(a == b)', '(b != c)', '(a == c)']
            Solve: {'a': 6, 'b': 5, 'c': 6}
    
        Path-5:
            Constraint: ['z3.Not(a == b)', '(b != c)', 'z3.Not(a == c)']
            Solve: {'a': 7, 'b': 8, 'c': 9}
    
        Path-6:
            Constraint: ['z3.Not(a == b)', 'z3.Not(b != c)']
            Solve: {'a': 10, 'b': 11, 'c': 11}
    



# References:

•	SymbolicFuzzer: https://www.fuzzingbook.org/html/SymbolicFuzzer.html \
•	Z3py: https://ericpony.github.io/z3py-tutorial/guide-examples.htm \
•	UnsatCore: https://ericpony.github.io/z3py-tutorial/advanced-examples.htm 
