clear

echo; echo "Installing requirements:"; echo
python3 -m pip install -r requirements.txt

rm -rf outputs
mkdir outputs

echo; echo "Checking with SimpleSymbolicFuzzer..."; echo
python3 run_simple_symfz.py &> outputs/output_simple_fz.txt
cat outputs/output_simple_fz.txt
echo

echo; echo "Checking with AdvancedSymbolicFuzzer..."; echo
python3 run_advance_symfz.py &> outputs/output_advanced_fz.txt
cat outputs/output_advanced_fz.txt
echo

echo "Done."; echo
