# SA&T-Symbolic-Execution
Project: 2021SP-COSC6386-Software Analysis & Testing \
Task: Write a symbolic fuzzer that can generate input values symbolically for a python function.

- - -

# Library:
- Python 3.7.7
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
  
# References:

•	SymbolicFuzzer: https://www.fuzzingbook.org/html/SymbolicFuzzer.html \
•	z3py: https://ericpony.github.io/z3py-tutorial/guide-examples.html
