from SymbolicFuzzer import *
from examples.gcd import *  # TODO - at least five examples


def pretty_print_paths(paths_):
    msg = "Number of {} paths:".format(len(paths_))
    print("\n", msg, "\n", "-" * len(msg), "\n")
    for idx_p, path_ in enumerate(paths_):
        path_ = path_.get_path_to_root()
        seq_lineno = []
        for elt in path_:
            seq_lineno.append(elt.cfgnode.ast_node.lineno)
        if len(seq_lineno) > 1 and seq_lineno[0] == seq_lineno[-1]:
            seq_lineno = seq_lineno[:-1]  # entry and exit nodes are same
        print("\tPath-{}: {}".format(idx_p + 1, seq_lineno))
    print()


def pretty_print_constraints_with_traces(n, predicates_, traces_):
    msg = "Constraints with Traces in File:"
    print("\n", msg, "\n", "-" * len(msg), "\n")
    for i in range(n):
        print("\tPath-{}:".format(i + 1))
        print("\t\tConstraint: {}".format(predicates_[i]))
        print("\t\tTrace in File: {}".format(traces_[i]))
        print()
    print()


def pretty_print_results(n, predicates_, results_):
    msg = "Solve Path Constraint:"
    print("\n", msg, "\n", "-" * len(msg), "\n")
    for i in range(n):
        print("\tPath-{}:".format(i + 1))
        print("\t\tConstraint: {}".format(predicates_[i]))
        print("\t\tSolve: {}".format(results_[i]))
        print()
    print()


if __name__ == "__main__":
    fn_list = [gcd]  # TODO - at least five examples
    for i, fn_example in enumerate(fn_list):
        msg = "Example #{}:".format(i + 1)
        print("\n", msg, "\n", "-" * len(msg), "\n")
        print("\tfilename: {}".format(fn_example.__code__.co_filename))
        print("\tfunction: {}".format(fn_example.__name__))
        print()

        # save_digraph
        gdot = show_cfg(fn_example)
        gdot.render('outputs/{}'.format(fn_example.__name__), view=False)

        # SimpleSymbolicFuzzer
        advfz_ex = AdvancedSymbolicFuzzer(fn_example, max_iter=10, max_tries=10, max_depth=10)

        # get_all_paths
        paths = advfz_ex.get_all_paths_unrolled(advfz_ex.fnenter)
        pretty_print_paths(paths)

        # extract_constraints_with_traces
        predicates_all, traces_all = advfz_ex.extract_constraints_with_traces(paths)
        pretty_print_constraints_with_traces(len(paths), predicates_all, traces_all)

        # solve_path_constraint
        res_all = advfz_ex.fuzz_path(paths)
        pretty_print_results(len(paths), predicates_all, res_all)

        # TODO - unsat core

        print("\n", "-" * 100, "\n")
